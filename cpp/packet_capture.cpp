#include <pcap.h>
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
#endif

const char* DEST_IP = "127.0.0.1";
static const char* shared_secret = nullptr;
const int MAX_PAYLOAD_SIZE = 256;

#ifdef _WIN32
#pragma pack(push, 1)
#endif
struct 
#ifndef _WIN32
__attribute__((__packed__)) 
#endif
PacketInfo {
    uint64_t timestamp;
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  has_tcp_ao;
    uint8_t  tcp_flags;
    uint8_t  l3_offset;
    uint8_t  l4_offset;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint32_t delta_time;
    uint16_t vlan_id;
    uint8_t  ip_ttl;
    uint8_t  ip_tos;
    uint16_t tcp_win;
    uint16_t ip_id;
    uint8_t  is_ipv6;
    uint8_t  is_fragment;
    uint16_t tcp_mss;
    uint8_t  tcp_ws;
    uint8_t  ipv6_ext_count;
    uint32_t ipv6_flow;
    uint32_t wire_len;
    uint32_t tcp_ts_val;
    uint32_t tcp_ts_ecr;
    uint8_t  tcp_sack;
    uint32_t tcp_rtt;
    uint32_t vxlan_vni;
    uint32_t entropy_scaled;
    uint8_t  ntp_stratum;
    uint8_t  ntp_mode;
    uint8_t  igmp_type;
    uint8_t  igmp_group[4];
    char     lldp_chassis[32];
    char     lldp_port[32];
    uint32_t tcp_sack_edges[8];
    uint8_t  top_byte;
    uint8_t  top_byte_freq;
    uint8_t  pad[151];
    uint16_t payload_len;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    char     dns_query[64];
    char     tls_sni[64];
    char     extra_info[128];
    char     app_layer_info[128];
    uint8_t  payload[MAX_PAYLOAD_SIZE];
    uint8_t  final_pad[8]; // Corrected to fix memory alignment for exactly 1024 bytes
};
#ifdef _WIN32
#pragma pack(pop)
#endif

static_assert(sizeof(PacketInfo) == 1024, "PacketInfo struct must be exactly 1024 bytes for protocol compatibility.");

struct CaptureContext {
    SSL* ssl;
    std::queue<PacketInfo> queue;
    std::mutex mutex;
    std::condition_variable cv;
    const size_t max_queue_size = 5000;
};

// Helper struct for Ethernet layer info
struct EthernetInfo {
    const ether_header* header;
    int header_len;
    uint16_t ether_type;
    uint16_t vlan_id;
};

struct IpInfo {
    const void* header;
    int header_len;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
    uint8_t protocol;
    uint8_t ttl;
    uint8_t tos;
    uint16_t id;
    bool is_ipv6;
    bool is_fragment;
};

struct TransportInfo {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t window;
    uint8_t flags;
    uint16_t mss;
    uint8_t ws;
    bool has_ao;
    const u_char* payload_ptr;
    int payload_len;
};

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

static uint64_t last_packet_ts = 0;

void check_icmp_unreachable(uint8_t t, uint8_t c, char* o, int m) {
#ifndef _WIN32
    if (t == ICMP_DEST_UNREACH) {
        const char* reasons[] = {"Net", "Host", "Proto", "Port", "Frag", "SrcRoute", "DestNet", "DestHost"};
        if (c < 8) snprintf(o, m, "ICMP Unreachable: %s", reasons[c]);
    }
#endif
}

void dissect_ntp_core(const u_char* p, int l, PacketInfo& i) {
    if (l < 48) return;
    uint8_t mode = p[0] & 0x07;
    uint8_t stratum = p[1];
    const char* ms[] = {"Res", "SymA", "SymP", "Cli", "Srv", "Bcast", "Ctrl", "Priv"};
    snprintf(i.app_layer_info + strlen(i.app_layer_info), 128 - strlen(i.app_layer_info), " [Mode: %s, Stratum: %d]", ms[mode % 8], stratum);
}

void check_tcp_anomalies(PacketInfo& info, const TransportInfo& t) {
    if (t.window == 0 && (t.flags & TH_ACK) && !(t.flags & (TH_SYN|TH_FIN|TH_RST))) {
        snprintf(info.extra_info, 128, "TCP ZeroWindow");
    } else if (info.payload_len == 1 && t.seq + 1 == info.tcp_seq && !(t.flags & (TH_SYN|TH_FIN|TH_RST))) {
        snprintf(info.extra_info, 128, "TCP Keep-Alive");
    }
}

uint32_t calculate_entropy_scaled(const uint8_t* d, int l) {
    if (l <= 0) return 0;
    int f[256] = {0};
    for (int i = 0; i < l; i++) f[d[i]]++;
    double e = 0;
    for (int i = 0; i < 256; i++) {
        if (f[i] > 0) {
            double p = (double)f[i] / l;
            e -= p * std::log2(p);
        }
    }
    return (uint32_t)(e * 1000);
}

void dissect_dhcp(const u_char* p, int l, char* o, int m) {
    if (l < 240 || p[236] != 0x63 || p[237] != 0x82 || p[238] != 0x53 || p[239] != 0x63) return;
    const u_char* opts = p + 240;
    int i = 0;
    while (i < l - 240) {
        uint8_t c = opts[i++];
        if (c == 255) break;
        if (c == 0) continue;
        if (i >= l - 240) break;
        uint8_t len = opts[i++];
        if (i + len > l - 240) break;
        if (c == 53 && len == 1) {
            uint8_t t = opts[i];
            const char* ts[] = {"?", "DISCOVER", "OFFER", "REQUEST", "DECLINE", "ACK", "NAK", "RELEASE", "INFORM"};
            if (t > 0 && t < 9) snprintf(o, m, "DHCP %s", ts[t]);
            return;
        }
        i += len;
    }
}

void dissect_lldp(const u_char* p, int l, PacketInfo& i) {
    int o = 0;
    while (o + 2 <= l) {
        uint16_t tlv = ntohs(*(uint16_t*)(p + o));
        uint16_t type = tlv >> 9;
        uint16_t len = tlv & 0x01FF;
        o += 2;
        if (o + len > l) break;
        if (type == 1) {
            int sl = (len - 1 < 31) ? len - 1 : 31;
            memcpy(i.lldp_chassis, p + o + 1, sl);
            i.lldp_chassis[sl] = '\0';
        } else if (type == 2) {
            int sl = (len - 1 < 31) ? len - 1 : 31;
            memcpy(i.lldp_port, p + o + 1, sl);
            i.lldp_port[sl] = '\0';
        } else if (type == 0) break;
        o += len;
    }
    snprintf(i.app_layer_info, 128, "LLDP %s/%s", i.lldp_chassis, i.lldp_port);
}

void dissect_igmp(const u_char* p, int l, PacketInfo& i) {
    if (l < 8) return;
    i.igmp_type = p[0];
    memcpy(i.igmp_group, p + 4, 4);
    const char* ts[] = {"?", "Query", "v1 Report", "v2 Report", "v2 Leave", "v3 Report"};
    const char* t = (i.igmp_type == 0x11) ? ts[1] : (i.igmp_type == 0x12) ? ts[2] : (i.igmp_type == 0x16) ? ts[3] : (i.igmp_type == 0x17) ? ts[4] : (i.igmp_type == 0x22) ? ts[5] : ts[0];
    snprintf(i.extra_info, 128, "IGMP %s Group %u.%u.%u.%u", t, i.igmp_group[0], i.igmp_group[1], i.igmp_group[2], i.igmp_group[3]);
}

void calculate_byte_stats(const uint8_t* d, int l, PacketInfo& i) {
    if (l <= 0) return;
    uint32_t counts[256] = {0};
    uint32_t max_f = 0;
    for (int j = 0; j < l; j++) {
        counts[d[j]]++;
        if (counts[d[j]] > max_f) {
            max_f = counts[d[j]];
            i.top_byte = d[j];
        }
    }
    i.top_byte_freq = (uint8_t)((max_f * 100) / l);
}

void dissect_vxlan(const u_char* p, int l, PacketInfo& i) {
    if (l < 8) return;
    i.vxlan_vni = (p[4] << 16) | (p[5] << 8) | p[6];
    snprintf(i.app_layer_info, 128, "VXLAN VNI: %u", i.vxlan_vni);
}

void dissect_ntp(const u_char* p, int l, PacketInfo& i) {
    if (l < 48) return;
    i.ntp_mode = p[0] & 0x07;
    i.ntp_stratum = p[1];
    const char* ms[] = {"Res", "SymA", "SymP", "Cli", "Srv", "Bcast", "Ctrl", "Priv"};
    snprintf(i.app_layer_info, 128, "NTP %s (Stratum %d)", ms[i.ntp_mode], i.ntp_stratum);
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

void dissect_http(const u_char* p, int l, char* o, int m) {
    if (l < 10) return;
    const char* ms[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS "};
    for (int i = 0; i < 6; i++) {
        int ml = strlen(ms[i]);
        if (l > ml && memcmp(p, ms[i], ml) == 0) {
            int c = 0;
            while (c < l && c < m - 1 && p[c] != '\r' && p[c] != '\n') {
                o[c] = p[c];
                c++;
            }
            o[c] = '\0';
            const char* h = "\r\nHost: ";
            const u_char* hp = (const u_char*)memmem(p, l, h, strlen(h));
            if (hp) {
                snprintf(o + strlen(o), m - strlen(o), " [Host: %.*s]", 32, hp + 8);
            }
            return;
        }
    }
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

void parse_tcp_options_extended(const u_char* p, int o, int h, PacketInfo& i) {
    if (h <= 20) return;
    const u_char* opts = p + o + 20;
    int len = h - 20;
    for (int k = 0; k < len; ) {
        uint8_t kind = opts[k];
        if (kind == 0) break;
        if (kind == 1) { k++; continue; }
        if (k + 1 >= len) break;
        uint8_t l = opts[k+1];
        if (l < 2 || k + l > len) break;
        if (kind == 2 && l == 4) i.tcp_mss = ntohs(*(uint16_t*)(opts + k + 2));
        else if (kind == 3 && l == 3) i.tcp_ws = opts[k+2];
        else if (kind == 4 && l == 2) i.tcp_sack = 1;
        else if (kind == 5 && l >= 10) {
            int blocks = (l - 2) / 8;
            if (blocks > 4) blocks = 4;
            memcpy(i.tcp_sack_edges, opts + k + 2, blocks * 8);
        }
        else if (kind == 8 && l == 10) {
            i.tcp_ts_val = ntohl(*(uint32_t*)(opts + k + 2));
            i.tcp_ts_ecr = ntohl(*(uint32_t*)(opts + k + 6));
        } else if (kind == 29) i.has_tcp_ao = 1;
        k += l;
    }
}

void signal_handler(int sig) {
    (void)sig;
    keep_running = false;
    if (global_pcap_handle) {
        pcap_breakloop(global_pcap_handle);
    }
}

void dissect_dns(const u_char* payload, int len, char* out, int out_max) {
    if (len < 12) return;
    const u_char* data = payload + 12;
    int pos = 0;
    int out_pos = 0;
    
    while (pos < len - 12 && out_pos < out_max - 1) {
        int label_len = data[pos];
        if (label_len == 0) break;
        if (label_len > 63) break;
        
        pos++;
        for (int i = 0; i < label_len && pos < len - 12 && out_pos < out_max - 1; i++) {
            out[out_pos++] = (char)data[pos++];
        }
        if (out_pos < out_max - 1) out[out_pos++] = '.';
    }
    if (out_pos > 0) {
        out[out_pos - (out[out_pos-1] == '.' ? 1 : 0)] = '\0';
    } else {
        out[0] = '\0';
    }
}

void dissect_tls_sni(const u_char* payload, int len, char* out, int out_max) {
    if (len < 5) return;
    if (payload[0] != 0x16) return;
    
    int handshake_type_pos = 5;
    if (len < handshake_type_pos + 4 || payload[handshake_type_pos] != 0x01) return;
    
    int pos = handshake_type_pos + 38;
    if (pos >= len) return;
    
    int sid_len = payload[pos];
    pos += 1 + sid_len;
    
    if (pos + 2 >= len) return;
    uint16_t cs_len = ntohs(*(uint16_t*)(payload + pos));
    pos += 2 + cs_len;
    
    if (pos + 1 >= len) return;
    int comp_len = payload[pos];
    pos += 1 + comp_len;
    
    if (pos + 2 >= len) return;
    int ext_total_len = ntohs(*(uint16_t*)(payload + pos));
    pos += 2;
    int ext_end = pos + ext_total_len;
    
    while (pos + 4 <= len && pos < ext_end) {
        uint16_t ext_type = ntohs(*(uint16_t*)(payload + pos));
        uint16_t ext_len = ntohs(*(uint16_t*)(payload + pos + 2));
        pos += 4;
        
        if (ext_type == 0x00) {
            if (pos + 5 <= len) {
                int list_len = ntohs(*(uint16_t*)(payload + pos));
                if (pos + 5 + list_len > len) return;
                if (payload[pos+2] == 0x00) {
                    int name_len = ntohs(*(uint16_t*)(payload + pos + 3));
                    if (pos + 5 + name_len <= len) {
                        int actual_copy = (name_len < out_max - 1) ? name_len : out_max - 1;
                        memcpy(out, payload + pos + 5, actual_copy);
                        out[actual_copy] = '\0';
                        return;
                    }
                }
            }
        }
        pos += ext_len;
    }
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

std::optional<EthernetInfo> parse_ethernet_layer(const u_char* packet, uint32_t caplen) {
    if (caplen < sizeof(ether_header)) return std::nullopt;
    const ether_header* eth = reinterpret_cast<const ether_header*>(packet);
    uint16_t etype = ntohs(eth->ether_type);
    int hlen = sizeof(ether_header);
    uint16_t v_id = 0;
    while ((etype == 0x8100 || etype == 0x88a8) && caplen >= (uint32_t)(hlen + 4)) {
        v_id = ntohs(*(uint16_t*)(packet + hlen)) & 0x0FFF;
        etype = ntohs(*(uint16_t*)(packet + hlen + 2));
        hlen += 4;
    }
    return EthernetInfo{eth, hlen, etype, v_id};
}

std::optional<IpInfo> parse_ip_layer(const u_char* packet, uint32_t caplen, int eth_hlen) {
    if (caplen < (uint32_t)(eth_hlen + 1)) return std::nullopt;
    uint8_t version = (packet[eth_hlen] >> 4) & 0x0f;
    IpInfo info;
    std::memset(&info, 0, sizeof(info));
    if (version == 4) {
        if (caplen < (uint32_t)(eth_hlen + 20)) return std::nullopt;
        const ip* ip_hdr = reinterpret_cast<const ip*>(packet + eth_hlen);
        info.header_len = ip_hdr->ip_hl * 4;
        if (info.header_len < 20 || caplen < (uint32_t)(eth_hlen + info.header_len)) return std::nullopt;
        std::memcpy(info.src_ip + 12, &ip_hdr->ip_src.s_addr, 4);
        std::memcpy(info.dst_ip + 12, &ip_hdr->ip_dst.s_addr, 4);
        info.protocol = ip_hdr->ip_p;
        info.ttl = ip_hdr->ip_ttl;
        info.tos = ip_hdr->ip_tos;
        info.id = ntohs(ip_hdr->ip_id);
        info.is_ipv6 = false;
        info.is_fragment = (ntohs(ip_hdr->ip_off) & (IP_MF | IP_OFFMASK)) != 0;
        info.header = ip_hdr;
    } 
#ifndef _WIN32
    else if (version == 6) {
        if (caplen < (uint32_t)(eth_hlen + sizeof(ip6_hdr))) return std::nullopt;
        const ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(packet + eth_hlen);
        info.header_len = 40;
        std::memcpy(info.src_ip, &ip6->ip6_src, 16);
        std::memcpy(info.dst_ip, &ip6->ip6_dst, 16);
        info.protocol = ip6->ip6_nxt;
        info.ttl = ip6->ip6_hlim;
        info.tos = (ntohl(ip6->ip6_flow) >> 20) & 0xFF;
        info.is_ipv6 = true;
        info.header = ip6;
    } 
#endif
    else return std::nullopt;
    return info;
}

std::optional<TransportInfo> parse_transport_layer(const u_char* packet, uint32_t caplen, int eth_hlen, const IpInfo& ip_i) {
    TransportInfo t;
    std::memset(&t, 0, sizeof(t));
    int offset = eth_hlen + ip_i.header_len;
    // simplified protocol check for cross platform
    if (ip_i.protocol == 6) { // TCP
        if (caplen < (uint32_t)(offset + 20)) return std::nullopt;
        // Using offsets instead of tcphdr struct to avoid header conflicts
        int hlen = ((packet[offset + 12] >> 4) & 0x0f) * 4;
        if (hlen < 20 || caplen < (uint32_t)(offset + hlen)) return std::nullopt;
        t.src_port = ntohs(*(uint16_t*)(packet + offset));
        t.dst_port = ntohs(*(uint16_t*)(packet + offset + 2));
        t.seq = ntohl(*(uint32_t*)(packet + offset + 4));
        t.ack = ntohl(*(uint32_t*)(packet + offset + 8));
        t.window = ntohs(*(uint16_t*)(packet + offset + 14));
        t.flags = packet[offset + 13];
        parse_tcp_options(packet, offset, hlen, t);
        t.payload_ptr = packet + offset + hlen;
        t.payload_len = ntohs(((const ip*)ip_i.header)->ip_len) - ip_i.header_len - hlen;
    } else if (ip_i.protocol == 17) { // UDP
        if (caplen < (uint32_t)(offset + 8)) return std::nullopt;
        t.src_port = ntohs(*(uint16_t*)(packet + offset));
        t.dst_port = ntohs(*(uint16_t*)(packet + offset + 2));
        t.payload_ptr = packet + offset + 8;
        t.payload_len = ntohs(*(uint16_t*)(packet + offset + 4)) - 8;
    } else {
        t.payload_ptr = packet + offset;
        t.payload_len = ntohs(((const ip*)ip_i.header)->ip_len) - ip_i.header_len;
    }
    return t;
}

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
                std::this_thread::yield(); // Prevent pinning the CPU
                continue;
            }
            return;
        }
        sent += n;
    }
}

void sender_thread_main(CaptureContext* ctx) {
    while (keep_running || !ctx->queue.empty()) {
        PacketInfo info;
        {
            std::unique_lock<std::mutex> lock(ctx->mutex);
            ctx->cv.wait(lock, [ctx] { return !ctx->queue.empty() || !keep_running; });
            if (ctx->queue.empty()) {
                if (!keep_running) break;
                continue;
            }
            info = ctx->queue.front();
            ctx->queue.pop();
        }
        send_packet_info(ctx->ssl, info);
    }
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (!user_data || !pkthdr || !packet) return;
    CaptureContext* ctx = reinterpret_cast<CaptureContext*>(user_data);
    auto eth_info_opt = parse_ethernet_layer(packet, pkthdr->caplen);
    if (!eth_info_opt) return;
    EthernetInfo eth_info = *eth_info_opt;
    PacketInfo info;
    memset(&info, 0, sizeof(info));
    uint64_t current_ts = pkthdr->ts.tv_sec * 1000000LL + pkthdr->ts.tv_usec;
    info.timestamp = current_ts;
    if (last_packet_ts > 0) info.delta_time = (uint32_t)(current_ts - last_packet_ts);
    last_packet_ts = current_ts;
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

    {
        std::lock_guard<std::mutex> lock(ctx->mutex);
        if (ctx->queue.size() < ctx->max_queue_size) {
            ctx->queue.push(info);
            ctx->cv.notify_one();
        }
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
    if (keep_running && handle && ssl) {
        ctx.ssl = ssl.get();
        sender_thread = std::thread(sender_thread_main, &ctx);
        if (pcap_loop(handle.get(), -1, packet_handler, reinterpret_cast<u_char*>(&ctx)) < 0) {
            fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle.get()));
        }
    }

    keep_running = false;
    ctx.cv.notify_all();
    if (sender_thread.joinable()) sender_thread.join();

    if (sockfd != -1) close(sockfd);
    printf("[INFO] Shutting down gracefully.\n");

    return 0;
}