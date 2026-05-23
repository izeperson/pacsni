#include <pcap.h>
#include "packet_types.h"
#include "protocol_dissectors.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#else
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <cstring>
#include <iostream>
#include <chrono>
#include <memory>
#include <optional> // For std::optional
#include <tuple>    // For std::tuple, though custom structs are used
#include <vector>
#include <atomic>
#include <signal.h>
#include <cmath>
#include <thread>

// Windows compatibility fixes
#ifdef _WIN32
#define sleep(x) Sleep((x)*1000)
typedef int ssize_t;

struct ether_header {
    uint8_t  ether_dhost[6];
    uint8_t  ether_shost[6];
    uint16_t ether_type;
};
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

void* memmem(const void* haystack, size_t haystacklen, const void* needle, size_t needlelen) {
    if (needlelen == 0) return (void*)haystack;
    if (haystacklen < needlelen) return NULL;
    const char* h = (const char*)haystack;
    const char* n = (const char*)needle;
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(h + i, n, needlelen) == 0) return (void*)(h + i);
    }
    return NULL;
}
#define ICMP_DEST_UNREACH 3
#endif

static const char* shared_secret = nullptr;

#ifdef _WIN32
struct ip {
    uint8_t  ip_hl:4, ip_v:4;
    uint8_t  ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t  ip_ttl;
    uint8_t  ip_p;
    uint16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
#endif

struct SslCtxDeleter { void operator()(SSL_CTX* ctx) { if (ctx) SSL_CTX_free(ctx); } };
struct SslDeleter { void operator()(SSL* ssl) { if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); } } };
struct PcapDeleter { void operator()(pcap_t* p) { if (p) pcap_close(p); } };
struct PcapIfDeleter { void operator()(pcap_if_t* i) { if (i) pcap_freealldevs(i); } };

std::atomic<bool> keep_running(true);
pcap_t* global_pcap_handle = nullptr;

void check_icmp_unreachable(uint8_t t, uint8_t c, char* o, int m) {
#ifndef _WIN32
    if (t == ICMP_DEST_UNREACH) {
        const char* reasons[] = {"Net", "Host", "Proto", "Port", "Frag", "SrcRoute", "DestNet", "DestHost"};
        if (c < 8) snprintf(o, m, "ICMP Unreachable: %s", reasons[c]);
    }
#endif
}

void dissect_app_common(const u_char* p, int l, char* o, int m) {
    if (l < 4) return;
    if (l > 7 && memcmp(p, "SSH-", 4) == 0) {
        int c = 0;
        while (c < l && c < m - 1 && p[c] != '\r' && p[c] != '\n') {
            o[c] = p[c];
            c++;
        }
        o[c] = '\0';
    } else if (l > 4 && (memcmp(p, "220 ", 4) == 0 || memcmp(p, "HELO", 4) == 0 || memcmp(p, "EHLO", 4) == 0)) {
        snprintf(o, m, "SMTP Control");
    } else if (l > 4 && (memcmp(p, "USER", 4) == 0 || memcmp(p, "PASS", 4) == 0 || memcmp(p, "220 ", 4) == 0)) {
        snprintf(o, m, "FTP Control");
    } else if (p[0] == 0xff && p[1] == 0xfb) {
        snprintf(o, m, "Telnet Negotiation");
    } else if ((p[0] & 0xc0) == 0x80 && l > 12) {
        snprintf(o, m, "QUIC Long Header");
    }
}

void dissect_icmp_details(uint8_t t, uint8_t c, char* o, int m) {
    const char* s = "ICMP Info";
    if (t == ICMP_ECHOREPLY) s = "Echo Reply";
    else if (t == ICMP_DEST_UNREACH) {
        switch(c) {
            case ICMP_NET_UNREACH: s = "Net Unreachable"; break;
            case ICMP_HOST_UNREACH: s = "Host Unreachable"; break;
            case ICMP_PROT_UNREACH: s = "Proto Unreachable"; break;
            case ICMP_PORT_UNREACH: s = "Port Unreachable"; break;
            case ICMP_FRAG_NEEDED: s = "Frag Required (DF set)"; break;
            default: s = "Dest Unreachable"; break;
        }
    } else if (t == ICMP_ECHO) s = "Echo Request";
    else if (t == ICMP_TIME_EXCEEDED) s = "Time Exceeded (TTL)";
    snprintf(o, m, "%s", s);
}

void dissect_icmp6_details(uint8_t t, uint8_t c, char* o, int m) {
    (void)c;
    const char* s = "ICMPv6 Info";
    if (t == 128) s = "Echo Request";
    else if (t == 129) s = "Echo Reply";
    else if (t == 1) s = "Dest Unreachable";
    else if (t == 2) s = "Packet Too Big";
    else if (t == 3) s = "Time Exceeded";
    else if (t == 133) s = "Router Solicit";
    else if (t == 134) s = "Router Advert";
    else if (t == 135) s = "Neighbor Solicit";
    else if (t == 136) s = "Neighbor Advert";
    snprintf(o, m, "%s", s);
}

void dissect_nd(const u_char* p, int l, char* o, int m) {
    if (l < 8) return;
    uint8_t t = p[0];
    if (t == 135) snprintf(o, m, "ND Neighbor Solicitation");
    else if (t == 136) snprintf(o, m, "ND Neighbor Advertisement");
    else if (t == 133) snprintf(o, m, "ND Router Solicitation");
    else if (t == 134) snprintf(o, m, "ND Router Advertisement");
}

void dissect_ospf(const u_char* p, int l, char* o, int m) {
    if (l < 24) return;
    uint8_t type = p[1];
    const char* t[] = {"?", "Hello", "DbDesc", "LSReq", "LSUpdate", "LSAck"};
    if (type > 0 && type < 6) snprintf(o, m, "OSPFv%d %s", p[0], t[type]);
}

void dissect_stp(const u_char* p, int l, char* o, int m) {
    if (l < 35) return;
    uint8_t type = p[4];
    snprintf(o, m, "STP %s", (type == 0x00) ? "Config" : (type == 0x80) ? "TCN" : "BPDU");
}

void dissect_gre(const u_char* p, int l, char* o, int m) {
    if (l < 4) return;
    snprintf(o, m, "GRE Tunnel (Inner: 0x%04x)", ntohs(*(uint16_t*)(p + 2)));
}

void log_ssl_error(const std::string& msg) {
    std::cerr << "[ERROR] " << msg << std::endl;
    ERR_print_errors_fp(stderr);
}

void parse_tcp_options(const u_char* packet, int offset, int tcp_hlen, TransportInfo& t_info) {
    if (tcp_hlen <= 20) return;
    const u_char* options = packet + offset + 20;
    int opt_len = tcp_hlen - 20;
    for (int i = 0; i < opt_len; ) {
        uint8_t kind = options[i];
        if (kind == 0) break;
        if (kind == 1) { i++; continue; }
        if (i + 1 >= opt_len) break;
        uint8_t len = options[i+1];
        if (len < 2 || i + len > opt_len) break;
        if (kind == 2 && len == 4) {
            t_info.mss = ntohs(*(uint16_t*)(options + i + 2));
        } else if (kind == 3 && len == 3) {
            t_info.ws = options[i+2];
        } else if (kind == 29) {
            t_info.has_ao = true;
        }
        i += len;
    }
}

// Forward declarations to ensure visibility across the translation unit
void send_packet_info(SSL* ssl, const PacketInfo& info);
void dissect_ntp_core(const u_char* p, int l, PacketInfo& i);
void dissect_raw_packet(const RawPacket& raw, PacketInfo& info);
void worker_thread_main(CaptureContext* ctx);
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);

void send_packet_info(SSL* ssl, const PacketInfo& info) {
    if (!ssl) return;
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    HMAC(EVP_sha512(), shared_secret, (shared_secret ? (int)strlen(shared_secret) : 0),
         reinterpret_cast<const unsigned char*>(&info), sizeof(PacketInfo),
         hmac_result, &hash_len);

    uint8_t combined[sizeof(PacketInfo) + 64];
    memset(combined, 0, sizeof(combined));
    memcpy(combined, &info, sizeof(PacketInfo));
    memcpy(combined + sizeof(PacketInfo), hmac_result, hash_len);

    size_t total_size = sizeof(combined);
    const char* buffer = reinterpret_cast<const char*>(combined);
    ssize_t sent = 0;
    while ((size_t)sent < total_size) {
        ssize_t n = SSL_write(ssl, buffer + sent, (int)(total_size - sent));
        if (n <= 0) {
            int ssl_err = SSL_get_error(ssl, n);
            if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
                std::this_thread::yield(); 
                continue;
            }
            return;
        }
        sent += n;
    }
}

void signal_handler(int sig) {
    (void)sig;
    keep_running = false;
    if (global_pcap_handle) {
        pcap_breakloop(global_pcap_handle);
    }
}

void sender_thread_main(CaptureContext* ctx) {
    while (keep_running) {
        PacketInfo info;
        if (ctx->dissected_queue.pop(info)) {
            send_packet_info(ctx->ssl, info);
        } else {
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    }
    PacketInfo info;
    while (ctx->dissected_queue.pop(info)) {
        send_packet_info(ctx->ssl, info);
    }
}

void dissect_raw_packet(const RawPacket& raw, PacketInfo& info) {
    const u_char* packet = raw.data;
    const struct pcap_pkthdr* pkthdr = &raw.pkthdr;
    auto eth_info_opt = parse_ethernet_layer(packet, pkthdr->caplen);
    if (!eth_info_opt) return;
    EthernetInfo eth_info = *eth_info_opt;
    memset(&info, 0, sizeof(info));
    uint64_t current_ts = pkthdr->ts.tv_sec * 1000000LL + pkthdr->ts.tv_usec;
    info.timestamp = current_ts;
    info.delta_time = raw.delta_time;
    memcpy(info.src_mac, eth_info.header->ether_shost, 6);
    memcpy(info.dst_mac, eth_info.header->ether_dhost, 6);
    info.l3_offset = (uint8_t)eth_info.header_len;
    info.vlan_id = eth_info.vlan_id;
    info.wire_len = pkthdr->len;

    if (eth_info.ether_type == ETHERTYPE_IP || eth_info.ether_type == 0x86DD) {
        auto ip_info_opt = parse_ip_layer(packet, pkthdr->caplen, eth_info.header_len);
        if (ip_info_opt) {
            // IPv6 parsing skipped on Windows for brevity in this example
            IpInfo ip_info = *ip_info_opt;
            std::memcpy(info.src_ip, ip_info.src_ip, 16);
            std::memcpy(info.dst_ip, ip_info.dst_ip, 16);
            info.protocol = ip_info.protocol;
            info.l4_offset = (uint8_t)(eth_info.header_len + ip_info.header_len);
            info.ip_ttl = ip_info.ttl;
            info.ip_tos = ip_info.tos;
            info.ip_id = ip_info.id;
            info.is_ipv6 = ip_info.is_ipv6 ? 1 : 0;
            info.is_fragment = ip_info.is_fragment ? 1 : 0;
#ifndef _WIN32
            if (info.is_ipv6) {
                const ip6_hdr* v6 = (const ip6_hdr*)ip_info.header;
                info.ipv6_flow = ntohl(v6->ip6_flow) & 0x0FFFFF;
                int v6_off = info.l3_offset + 40;
                uint8_t nxt = v6->ip6_nxt;
                while (info.ipv6_ext_count < 10) {
                    if (nxt == 0 || nxt == 43 || nxt == 60) {
                        if (v6_off + 8 > (int)pkthdr->caplen) break;
                        nxt = packet[v6_off];
                        v6_off += (packet[v6_off+1] + 1) * 8;
                        info.ipv6_ext_count++;
                    } else if (nxt == 44) {
                        info.is_fragment = 1; nxt = packet[v6_off]; v6_off += 8; info.ipv6_ext_count++;
                    } else break;
                }
                info.protocol = nxt;
            }
#endif
            if (info.protocol == IPPROTO_ICMP || info.protocol == IPPROTO_ICMPV6) {
                if (info.protocol == IPPROTO_ICMP && (uint32_t)info.l4_offset + 8 <= pkthdr->caplen) {
                    // Using raw offsets for ICMP 
                    info.icmp_type = packet[info.l4_offset];
                    info.icmp_code = packet[info.l4_offset + 1];
                    dissect_icmp_details(info.icmp_type, info.icmp_code, info.extra_info, 128);
                    check_icmp_unreachable(info.icmp_type, info.icmp_code, info.extra_info, 128);
                } else if (info.protocol == IPPROTO_ICMPV6 && info.l4_offset + sizeof(struct icmp6_hdr) <= pkthdr->caplen) {
                    const struct icmp6_hdr* icmp_v6 = reinterpret_cast<const struct icmp6_hdr*>(packet + info.l4_offset);
                    info.icmp_type = icmp_v6->icmp6_type;
                    info.icmp_code = icmp_v6->icmp6_code;
                    dissect_icmp6_details(info.icmp_type, info.icmp_code, info.extra_info, 128);
                }
            }
            auto transport_info_opt = parse_transport_layer(packet, pkthdr->caplen, eth_info.header_len, ip_info);
            if (transport_info_opt) {
                TransportInfo transport_info = *transport_info_opt;
                info.src_port = transport_info.src_port;
                info.dst_port = transport_info.dst_port;
                if (info.protocol == IPPROTO_TCP) {
                    info.tcp_flags = transport_info.flags; info.tcp_seq = transport_info.seq; info.tcp_ack = transport_info.ack; info.tcp_win = transport_info.window;
                    parse_tcp_options_extended(packet, info.l3_offset + ip_info.header_len, (transport_info.payload_ptr ? (int)(transport_info.payload_ptr - (packet + info.l3_offset + ip_info.header_len)) : 20), info);
                    check_tcp_anomalies(info, transport_info);
                    if (transport_info.payload_ptr && transport_info.payload_len > 0) {
                        if (info.src_port == 80 || info.dst_port == 80) dissect_http(transport_info.payload_ptr, transport_info.payload_len, info.extra_info, 128);
                        else if (info.src_port == 4789 || info.dst_port == 4789) dissect_vxlan(transport_info.payload_ptr, transport_info.payload_len, info);
                        else if (info.tls_sni[0] == '\0') dissect_app_common(transport_info.payload_ptr, transport_info.payload_len, info.extra_info, 128);
                        else dissect_tls_sni(transport_info.payload_ptr, transport_info.payload_len, info.tls_sni, 64);
                    }
                } else if (info.protocol == IPPROTO_UDP) {
                    if ((info.src_port == 53 || info.dst_port == 53) && transport_info.payload_ptr) dissect_dns(transport_info.payload_ptr, transport_info.payload_len, info.dns_query, 64);
                    else if (info.src_port == 67 || info.dst_port == 67 || info.src_port == 68 || info.dst_port == 68) dissect_dhcp(transport_info.payload_ptr, transport_info.payload_len, info.extra_info, 128);
                    else if (info.src_port == 123 || info.dst_port == 123) { dissect_ntp(transport_info.payload_ptr, transport_info.payload_len, info); dissect_ntp_core(transport_info.payload_ptr, transport_info.payload_len, info); }
                }
                if (info.protocol == 89) dissect_ospf(packet + info.l4_offset, pkthdr->caplen - info.l4_offset, info.extra_info, 128);
                if (info.protocol == 47) dissect_gre(packet + info.l4_offset, pkthdr->caplen - info.l4_offset, info.extra_info, 128);
                if (info.protocol == 2) dissect_igmp(packet + info.l4_offset, pkthdr->caplen - info.l4_offset, info);
            }
        }
    } else if (eth_info.ether_type == ETHERTYPE_ARP) {
        info.protocol = 200;
        if (pkthdr->caplen >= (bpf_u_int32)eth_info.header_len + 28) {
            // Manual ARP parsing
            uint16_t pro = ntohs(*(uint16_t*)(packet + eth_info.header_len + 2));
            uint8_t hln = packet[eth_info.header_len + 4];
            uint8_t pln = packet[eth_info.header_len + 5];
            if (pro == ETHERTYPE_IP && pln == 4) {
                const u_char* arp_ptr = packet + eth_info.header_len + 8 + (2 * hln);
                memcpy(info.src_ip + 12, arp_ptr, 4);
                memcpy(info.dst_ip + 12, arp_ptr + 4 + hln, 4);
            }
        }
    } else if (eth_info.ether_type <= 1500) {
        if (eth_info.header->ether_dhost[0] == 0x01 && eth_info.header->ether_dhost[1] == 0x80 && 
            eth_info.header->ether_dhost[2] == 0xC2 && eth_info.header->ether_dhost[3] == 0x00 &&
            eth_info.header->ether_dhost[4] == 0x00 && eth_info.header->ether_dhost[5] == 0x00) {
            info.protocol = 202;
            dissect_stp(packet + eth_info.header_len, pkthdr->caplen - eth_info.header_len, info.extra_info, 128);
        }
    } else if (eth_info.ether_type == 0x88cc) {
        dissect_lldp(packet + eth_info.header_len, pkthdr->caplen - eth_info.header_len, info);
    } else return;
    
    uint32_t capture_len = (pkthdr->caplen < MAX_PAYLOAD_SIZE) ? pkthdr->caplen : MAX_PAYLOAD_SIZE;
    info.payload_len = (uint16_t)capture_len;
    info.entropy_scaled = calculate_entropy_scaled(packet, capture_len);
    calculate_byte_stats(packet, capture_len, info);
    memcpy(info.payload, packet, capture_len);
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    CaptureContext* ctx = reinterpret_cast<CaptureContext*>(user_data);
    if (!ctx) return;

    RawPacket raw;
    raw.pkthdr = *pkthdr;
    uint32_t caplen = (pkthdr->caplen < MAX_PAYLOAD_SIZE) ? pkthdr->caplen : MAX_PAYLOAD_SIZE;
    std::memcpy(raw.data, packet, caplen);

    static struct timeval last_ts = {0, 0};
    raw.delta_time = (last_ts.tv_sec == 0) ? 0 : 
        (uint32_t)((pkthdr->ts.tv_sec - last_ts.tv_sec) * 1000000 + (pkthdr->ts.tv_usec - last_ts.tv_usec));
    last_ts = pkthdr->ts;

    ctx->raw_queue.push(raw);
}

void worker_thread_main(CaptureContext* ctx) {
    while (keep_running) {
        RawPacket raw;
        if (ctx->raw_queue.pop(raw)) {
            PacketInfo info;
            dissect_raw_packet(raw, info);
            while (!ctx->dissected_queue.push(info) && keep_running) {
                std::this_thread::yield();
            }
        } else {
            std::this_thread::yield();
        }
    }
    RawPacket raw;
    while (ctx->raw_queue.pop(raw)) {
        PacketInfo info;
        dissect_raw_packet(raw, info);
        while (!ctx->dissected_queue.push(info)) {
            std::this_thread::yield();
        }
    }
}

void monitor_pcap_stats(pcap_t* handle) {
    while (keep_running) {
        struct pcap_stat ps;
        if (pcap_stats(handle, &ps) == 0) {
            static uint32_t last_recv = 0;
            static uint32_t last_drop = 0;
            uint32_t diff_recv = ps.ps_recv - last_recv;
            uint32_t diff_drop = ps.ps_drop - last_drop;
            if (diff_recv > 0 || diff_drop > 0) {
                printf("[STATS] Engine Captured: %u | Dropped: %u\n", diff_recv, diff_drop);
            }
            last_recv = ps.ps_recv; last_drop = ps.ps_drop;
        }
        for (int i = 0; i < 10 && keep_running; ++i) ::sleep(1);
    }
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return 1;
    }
#endif

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

#ifndef _WIN32
    if (geteuid() != 0) {
        fprintf(stderr, "[ERROR] pacsni capture requires root privileges. Please run with sudo.\n");
        return 1;
    }
#endif

    shared_secret = getenv("PACSNI_SHARED_SECRET");
    if (!shared_secret) {
        fprintf(stderr, "[WARN] PACSNI_SHARED_SECRET environment variable not set. Using default for development.\n");
        shared_secret = "pacsni_secure_shared_secret_123";
    }

    const char* dest_ip_env = getenv("RUST_SERVICE_HOST");
    const char* dest_ip = dest_ip_env ? dest_ip_env : "127.0.0.1";
    const int dest_port = 9001;

    if (SSL_library_init() != 1) {
        fprintf(stderr, "Error: SSL_library_init failed\n");
        return 1;
    }
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_client_method();
    if (!method) {
        fprintf(stderr, "Error: Unable to get TLS client method\n");
        return 1;
    }

    std::unique_ptr<SSL_CTX, SslCtxDeleter> ssl_ctx(SSL_CTX_new(method));
    if (!ssl_ctx) {
        log_ssl_error("Unable to create SSL context");
        return 1;
    }

    if (SSL_CTX_set_min_proto_version(ssl_ctx.get(), TLS1_3_VERSION) != 1) {
        fprintf(stderr, "Error: Failed to set minimum protocol version to TLS 1.3\n");
        return 1;
    }
    if (SSL_CTX_set_max_proto_version(ssl_ctx.get(), TLS1_3_VERSION) != 1) {
        fprintf(stderr, "Error: Failed to set maximum protocol version to TLS 1.3\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    std::memset(errbuf, 0, sizeof(errbuf));

    pcap_if_t* alldevs_raw = nullptr;
    if (pcap_findalldevs(&alldevs_raw, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 2;
    }
    std::unique_ptr<pcap_if_t, PcapIfDeleter> alldevs(alldevs_raw);

    pcap_if_t* d = nullptr;
    if (argc > 1) {
        const char* target = argv[1];
        for (pcap_if_t* iter = alldevs.get(); iter != nullptr; iter = iter->next) {
            if (std::strcmp(iter->name, target) == 0) {
                d = iter;
                break;
            }
        }
        if (d == nullptr) {
            fprintf(stderr, "Interface %s not found. Available devices:\n", target);
            for (pcap_if_t* iter = alldevs.get(); iter != nullptr; iter = iter->next) {
                fprintf(stderr, " - %s\n", iter->name);
            }
            return 2;
        }
    } else {
        for (d = alldevs.get(); d != nullptr; d = d->next) {
            if (!(d->flags & PCAP_IF_LOOPBACK)) {
                break;
            }
        }
        if (d == nullptr) d = alldevs.get();
    }

    if (d == nullptr) {
        fprintf(stderr, "No interfaces found! Make sure libpcap is installed.\n");
        return 2;
    }

    printf("Listening on %s\n", d->name);
    std::unique_ptr<pcap_t, PcapDeleter> handle(pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf));
    global_pcap_handle = handle.get();
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", d->name, errbuf);
        return 2;
    }

    if (argc > 2) {
        struct bpf_program fp;
        if (pcap_compile(handle.get(), &fp, argv[2], 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "BPF Error: %s\n", pcap_geterr(handle.get()));
            return 2;
        }
        if (pcap_setfilter(handle.get(), &fp) == -1) {
            fprintf(stderr, "Filter Error: %s\n", pcap_geterr(handle.get()));
            return 2;
        }
        pcap_freecode(&fp);
    }

    std::unique_ptr<SSL, SslDeleter> ssl;
    int sockfd = -1;

    while (keep_running) {
        if (sockfd != -1) close(sockfd);
        sockfd = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sockfd < 0) {
            std::perror("socket creation failed");
            ::sleep(2);
            continue;
        }

        int optval = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));

        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
#ifdef _WIN32
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout.tv_sec, sizeof(int));
#else
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#endif

        struct sockaddr_in serv_addr;
        std::memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(dest_port);
        if (inet_pton(AF_INET, dest_ip, &serv_addr.sin_addr) <= 0) {
            fprintf(stderr, "Invalid address: %s\n", dest_ip);
            close(sockfd);
            return 1;
        }

        std::cout << "[INFO] Connecting to Rust service at " << dest_ip << ":" << dest_port << "...\n" << std::flush;
        if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == 0) {
            ssl.reset(SSL_new(ssl_ctx.get()));
            if (!ssl) {
                log_ssl_error("SSL_new failed");
                continue;
            }

            if (SSL_set_fd(ssl.get(), sockfd) != 1) {
                log_ssl_error("SSL_set_fd failed");
                continue;
            }

            if (SSL_connect(ssl.get()) == 1) {
                printf("[SUCCESS] Connected successfully via TLS.\n");
                break;
            } else {
                log_ssl_error("TLS Handshake failed");
            }
            ssl.reset();
        }

        std::cerr << "[WARN] Connection failed. Retrying in 2 seconds...\n";
        ::sleep(2);
    }

    CaptureContext ctx;
    std::thread sender_thread;
    std::vector<std::thread> worker_pool;
    std::thread stats_thread;
    const int num_workers = 4;

    if (keep_running && handle && ssl) {
        ctx.ssl = ssl.get();
        sender_thread = std::thread(sender_thread_main, &ctx);
        stats_thread = std::thread(monitor_pcap_stats, handle.get());
        for (int i = 0; i < num_workers; ++i) worker_pool.push_back(std::thread(worker_thread_main, &ctx));

        if (pcap_loop(handle.get(), -1, packet_handler, reinterpret_cast<u_char*>(&ctx)) < 0) {
            fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle.get()));
        }
    }

    keep_running = false;

    for (auto& t : worker_pool) { if (t.joinable()) t.join(); }
    if (sender_thread.joinable()) sender_thread.join();
    if (stats_thread.joinable()) stats_thread.join();

    if (sockfd != -1) close(sockfd);
    printf("[INFO] Shutting down gracefully.\n");

    return 0;
}