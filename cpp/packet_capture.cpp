#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <chrono>
#include <memory>
#include <optional> // For std::optional
#include <tuple>    // For std::tuple, though custom structs are used
#include <vector>
#include <atomic>
#include <signal.h>

const char* DEST_IP = "127.0.0.1";
const char* SHARED_SECRET = "pacsni_secure_shared_secret_123";
const int MAX_PAYLOAD_SIZE = 128;

struct __attribute__((__packed__)) PacketInfo {
    uint64_t timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  has_tcp_ao;
    uint16_t payload_len;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint8_t  payload[MAX_PAYLOAD_SIZE];
};

// Helper struct for Ethernet layer info
struct EthernetInfo {
    const ether_header* header;
    int header_len;
    uint16_t ether_type;
};

// Helper struct for IP layer info
struct IpInfo {
    const ip* header;
    int header_len;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t protocol;
};

// Helper struct for Transport layer info
struct TransportInfo {
    uint16_t src_port;
    uint16_t dst_port;
    const u_char* payload_ptr;
    int payload_len;
};

struct SslCtxDeleter { void operator()(SSL_CTX* ctx) { if (ctx) SSL_CTX_free(ctx); } };
struct SslDeleter { void operator()(SSL* ssl) { if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); } } };
struct PcapDeleter { void operator()(pcap_t* p) { if (p) pcap_close(p); } };
struct PcapIfDeleter { void operator()(pcap_if_t* i) { if (i) pcap_freealldevs(i); } };
struct EvpMacDeleter { void operator()(EVP_MAC* m) { if (m) EVP_MAC_free(m); } };
struct EvpMacCtxDeleter { void operator()(EVP_MAC_CTX* c) { if (c) EVP_MAC_CTX_free(c); } };

std::atomic<bool> keep_running(true);

void signal_handler(int sig) {
    (void)sig;
    keep_running = false;
}

void log_ssl_error(const std::string& msg) {
    std::cerr << "[ERROR] " << msg << std::endl;
    ERR_print_errors_fp(stderr);
}

void send_packet_info(SSL* ssl, const PacketInfo& info) {
    if (!ssl) {
        std::cerr << "[ERROR] SSL object is NULL in send_packet_info" << std::endl;
        return;
    }
    
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    size_t hash_len = 0;

    // Restored modern OpenSSL 3.0+ EVP_MAC API
    std::unique_ptr<EVP_MAC, EvpMacDeleter> mac(EVP_MAC_fetch(NULL, "HMAC", NULL));
    if (!mac) {
        log_ssl_error("EVP_MAC_fetch failed. Ensure OpenSSL 3.0+ is installed.");
        return;
    }

    std::unique_ptr<EVP_MAC_CTX, EvpMacCtxDeleter> hmac_ctx(EVP_MAC_CTX_new(mac.get()));
    if (!hmac_ctx) {
        return;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA512", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(hmac_ctx.get(), (const unsigned char*)SHARED_SECRET, strlen(SHARED_SECRET), params) != 1) {
        log_ssl_error("EVP_MAC_init failed");
        return;
    }

    if (EVP_MAC_update(hmac_ctx.get(), reinterpret_cast<const unsigned char*>(&info), sizeof(PacketInfo)) != 1) {
        log_ssl_error("EVP_MAC_update failed");
        return;
    }

    if (EVP_MAC_final(hmac_ctx.get(), hmac_result, &hash_len, sizeof(hmac_result)) != 1) {
        log_ssl_error("EVP_MAC_final failed");
        return;
    }

    uint8_t combined[sizeof(PacketInfo) + 64];
    memset(combined, 0, sizeof(combined));
    memcpy(combined, &info, sizeof(PacketInfo));
    memcpy(combined + sizeof(PacketInfo), hmac_result, hash_len);

    size_t total_size = sizeof(combined);
    const char* buffer = reinterpret_cast<const char*>(combined);
    ssize_t sent = 0;

    while ((size_t)sent < total_size) {
        ssize_t n = SSL_write(ssl, buffer + sent, total_size - sent);
        if (n <= 0) {
            int ssl_err = SSL_get_error(ssl, n);
            if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
                continue;
            }
            std::cerr << "[ERROR] SSL_write failed with error: " << ssl_err << std::endl;
            ERR_print_errors_fp(stderr);
            break;
        }
        sent += n;
    }
}

// Helper function to parse Ethernet layer
std::optional<EthernetInfo> parse_ethernet_layer(const u_char* packet, uint32_t caplen) {
    if (caplen < sizeof(ether_header)) {
        return std::nullopt;
    }
    const ether_header* eth_header = reinterpret_cast<const ether_header*>(packet);
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return std::nullopt;
    }
    return EthernetInfo{eth_header, sizeof(ether_header), ntohs(eth_header->ether_type)};
}

// Helper function to parse IP layer
std::optional<IpInfo> parse_ip_layer(const u_char* packet, uint32_t caplen, int eth_header_len) {
    if (caplen < (uint32_t)(eth_header_len + sizeof(ip))) {
        return std::nullopt;
    }
    const ip* ip_header = reinterpret_cast<const ip*>(packet + eth_header_len);
    if (ip_header->ip_v != 4) {
        return std::nullopt;
    }
    int ip_header_len = ip_header->ip_hl * 4;
    if (ip_header_len < 20 || caplen < (uint32_t)(eth_header_len + ip_header_len)) {
        return std::nullopt;
    }
    return IpInfo{ip_header, ip_header_len, ip_header->ip_src.s_addr, ip_header->ip_dst.s_addr, ip_header->ip_p};
}

// Helper function to parse Transport layer (TCP/UDP)
std::optional<TransportInfo> parse_transport_layer(const u_char* packet, uint32_t caplen, int eth_header_len, const IpInfo& ip_info) {
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    const u_char* payload_ptr = nullptr;
    int payload_len = 0;

    if (ip_info.protocol == IPPROTO_TCP) {
        if (caplen < (uint32_t)(eth_header_len + ip_info.header_len + sizeof(tcphdr))) {
            return std::nullopt;
        }
        const tcphdr* tcp_header = reinterpret_cast<const tcphdr*>(packet + eth_header_len + ip_info.header_len);
        int tcp_header_len = tcp_header->th_off * 4;
        if (tcp_header_len < 20 || caplen < (uint32_t)(eth_header_len + ip_info.header_len + tcp_header_len)) {
            return std::nullopt;
        }
        src_port = ntohs(tcp_header->source);
        dst_port = ntohs(tcp_header->dest);
        payload_ptr = packet + eth_header_len + ip_info.header_len + tcp_header_len;
        payload_len = ntohs(ip_info.header->ip_len) - ip_info.header_len - tcp_header_len;
    } else if (ip_info.protocol == IPPROTO_UDP) {
        if (caplen < (uint32_t)(eth_header_len + ip_info.header_len + sizeof(udphdr))) {
            return std::nullopt;
        }
        const udphdr* udp_header = reinterpret_cast<const udphdr*>(packet + eth_header_len + ip_info.header_len);
        src_port = ntohs(udp_header->source);
        dst_port = ntohs(udp_header->dest);
        payload_ptr = packet + eth_header_len + ip_info.header_len + sizeof(udphdr);
        payload_len = ntohs(udp_header->len) - sizeof(udphdr);
    } else {
        payload_ptr = packet + eth_header_len + ip_info.header_len;
        payload_len = ntohs(ip_info.header->ip_len) - ip_info.header_len;
    }
    return TransportInfo{src_port, dst_port, payload_ptr, payload_len};
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (!user_data || !pkthdr || !packet) return;

    SSL* ssl = reinterpret_cast<SSL*>(user_data);

    // Parse Ethernet Layer
    std::optional<EthernetInfo> eth_info_opt = parse_ethernet_layer(packet, pkthdr->caplen);
    if (!eth_info_opt) return;
    EthernetInfo eth_info = *eth_info_opt;

    // Parse IP Layer
    std::optional<IpInfo> ip_info_opt = parse_ip_layer(packet, pkthdr->caplen, eth_info.header_len);
    if (!ip_info_opt) return;
    IpInfo ip_info = *ip_info_opt;

    // Parse Transport Layer
    std::optional<TransportInfo> transport_info_opt = parse_transport_layer(packet, pkthdr->caplen, eth_info.header_len, ip_info);
    if (!transport_info_opt) return;
    TransportInfo transport_info = *transport_info_opt;

    // Restored functionality: Detect TCP Authentication Option (TCP-AO, Option 29)
    bool tcp_ao_info_opt = false;
    if (ip_info.protocol == IPPROTO_TCP) {
        const tcphdr* tcp = reinterpret_cast<const tcphdr*>(packet + eth_info.header_len + ip_info.header_len);
        const u_char* options = (const u_char*)(tcp + 1);
        int opt_len = (tcp->th_off * 4) - sizeof(tcphdr);
        for (int i = 0; i < opt_len; ) {
            if (options[i] == 0) break; // End of list
            if (options[i] == 1) { i++; continue; } // NOP
            if (options[i] == 29) { tcp_ao_info_opt = true; break; }
            uint8_t len = (i + 1 < opt_len) ? options[i+1] : 1;
            if (len < 2) len = 2; // Sanity check
            i += len;
        }
    }

    PacketInfo info;
    memset(&info, 0, sizeof(info));

    auto duration = std::chrono::microseconds(
        pkthdr->ts.tv_sec * 1000000LL + pkthdr->ts.tv_usec
    );
    info.timestamp = duration.count();
    info.src_ip = ip_info.src_ip;
    info.dst_ip = ip_info.dst_ip;
    info.src_port = transport_info.src_port;
    info.dst_port = transport_info.dst_port;
    info.protocol = ip_info.protocol;
    info.has_tcp_ao = tcp_ao_info_opt ? 1 : 0;
    info.payload_len = (transport_info.payload_len < 0) ? 0 : (uint16_t)transport_info.payload_len;
    memcpy(info.src_mac, eth_info.header->ether_shost, 6);
    memcpy(info.dst_mac, eth_info.header->ether_dhost, 6);

    if (transport_info.payload_len > 0 && transport_info.payload_ptr != nullptr) {
        uint32_t captured_payload_len = pkthdr->caplen - (uint32_t)(transport_info.payload_ptr - packet);
        size_t actual_copy = (transport_info.payload_len < (int)captured_payload_len) ? (size_t)transport_info.payload_len : (size_t)captured_payload_len;
        if (actual_copy > MAX_PAYLOAD_SIZE) actual_copy = MAX_PAYLOAD_SIZE;
        memcpy(info.payload, transport_info.payload_ptr, actual_copy);
    }

    send_packet_info(ssl, info);
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

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

    std::unique_ptr<SSL_CTX, SslCtxDeleter> ctx(SSL_CTX_new(method));
    if (!ctx) {
        log_ssl_error("Unable to create SSL context");
        return 1;
    }

    if (SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1) {
        fprintf(stderr, "Error: Failed to set minimum protocol version to TLS 1.3\n");
        return 1;
    }
    if (SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) != 1) {
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
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", d->name, errbuf);
        return 2;
    }

    std::unique_ptr<SSL, SslDeleter> ssl;
    int sockfd = -1;

    while (keep_running) {
        if (sockfd != -1) close(sockfd);
        sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

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
            ssl.reset(SSL_new(ctx.get()));
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

    if (keep_running && handle && ssl) {
        if (pcap_loop(handle.get(), -1, packet_handler, reinterpret_cast<u_char*>(ssl.get())) < 0) {
            fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle.get()));
        }
    }

    if (sockfd != -1) close(sockfd);
    printf("[INFO] Shutting down gracefully.\n");

    return 0;
}