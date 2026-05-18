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
#include <vector>
#include <atomic>
#include <signal.h>

const char* DEST_IP = "127.0.0.1";
const int DEST_PORT = 9001;
const char* SHARED_SECRET = "pacsni_secure_shared_secret_123";
const int MAX_PAYLOAD_SIZE = 128;

struct __attribute__((__packed__)) PacketInfo {
    uint64_t timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint16_t payload_len;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint8_t  payload[MAX_PAYLOAD_SIZE];
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

    std::unique_ptr<EVP_MAC, EvpMacDeleter> mac(EVP_MAC_fetch(NULL, "HMAC", NULL));
    if (!mac) return;

    std::unique_ptr<EVP_MAC_CTX, EvpMacCtxDeleter> hmac_ctx(EVP_MAC_CTX_new(mac.get()));
    if (!hmac_ctx) {
        return;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA512", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(hmac_ctx.get(), (const unsigned char*)SHARED_SECRET, strlen(SHARED_SECRET), params) != 1) {
        return;
    }

    if (EVP_MAC_update(hmac_ctx.get(), reinterpret_cast<const unsigned char*>(&info), sizeof(PacketInfo)) != 1) {
        return;
    }

    if (EVP_MAC_final(hmac_ctx.get(), hmac_result, &hash_len, sizeof(hmac_result)) != 1) {
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

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (!user_data || !pkthdr || !packet) return;

    SSL* ssl = reinterpret_cast<SSL*>(user_data);

    if (pkthdr->caplen < sizeof(struct ether_header)) return;
    struct ether_header* eth_header = (struct ether_header*)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    if (pkthdr->caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    if (ip_header->ip_v != 4) return;

    int ip_header_len = ip_header->ip_hl * 4;
    if (ip_header_len < 20 || pkthdr->caplen < (uint32_t)(sizeof(struct ether_header) + ip_header_len)) {
        return;
    }

    uint32_t src_ip = ip_header->ip_src.s_addr;
    uint32_t dst_ip = ip_header->ip_dst.s_addr;

    uint8_t protocol = ip_header->ip_p;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    const u_char* payload = nullptr;
    int payload_len = 0;

    if (protocol == IPPROTO_TCP) {
        if (pkthdr->caplen < (uint32_t)(sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr))) return;
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
        int tcp_header_len = tcp_header->th_off * 4;
        if (tcp_header_len < 20 || pkthdr->caplen < (uint32_t)(sizeof(struct ether_header) + ip_header_len + tcp_header_len)) return;

        src_port = ntohs(tcp_header->source);
        dst_port = ntohs(tcp_header->dest);
        payload = packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
        payload_len = ntohs(ip_header->ip_len) - ip_header_len - tcp_header_len;
    } else if (protocol == IPPROTO_UDP) {
        if (pkthdr->caplen < (uint32_t)(sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr))) return;
        struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
        src_port = ntohs(udp_header->source);
        dst_port = ntohs(udp_header->dest);
        payload = packet + sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr);
        payload_len = ntohs(udp_header->len) - sizeof(struct udphdr);
    } else {
        payload = packet + sizeof(struct ether_header) + ip_header_len;
        payload_len = ntohs(ip_header->ip_len) - ip_header_len;
    }

    PacketInfo info;
    memset(&info, 0, sizeof(info));

    auto duration = std::chrono::microseconds(
        pkthdr->ts.tv_sec * 1000000LL + pkthdr->ts.tv_usec
    );
    info.timestamp = duration.count();
    info.src_ip = src_ip;
    info.dst_ip = dst_ip;
    info.src_port = src_port;
    info.dst_port = dst_port;
    info.protocol = protocol;
    info.payload_len = (payload_len < 0) ? 0 : (uint16_t)payload_len;
    memcpy(info.src_mac, eth_header->ether_shost, 6);
    memcpy(info.dst_mac, eth_header->ether_dhost, 6);

    if (payload_len > 0 && payload != nullptr) {
        uint32_t captured_payload_len = pkthdr->caplen - (uint32_t)(payload - packet);
        size_t actual_copy = (payload_len < (int)captured_payload_len) ? (size_t)payload_len : (size_t)captured_payload_len;
        if (actual_copy > MAX_PAYLOAD_SIZE) actual_copy = MAX_PAYLOAD_SIZE;
        memcpy(info.payload, payload, actual_copy);
    }

    send_packet_info(ssl, info);
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

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
    for (d = alldevs.get(); d != nullptr; d = d->next) {
        if (!(d->flags & PCAP_IF_LOOPBACK)) {
            break;
        }
    }
    if (d == nullptr) d = alldevs.get();

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
        serv_addr.sin_port = htons(DEST_PORT);
        if (inet_pton(AF_INET, DEST_IP, &serv_addr.sin_addr) <= 0) {
            fprintf(stderr, "Invalid address: %s\n", DEST_IP);
            close(sockfd);
            return 1;
        }

        std::cout << "[INFO] Connecting to Rust service at " << DEST_IP << ":" << DEST_PORT << "...\n" << std::flush;
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