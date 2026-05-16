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
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <chrono>

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

void send_packet_info(SSL* ssl, const PacketInfo& info) {
    // Generate SHA-512 HMAC-style signature
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL) != 1) goto err;
    if (EVP_DigestUpdate(mdctx, &info, sizeof(PacketInfo)) != 1) goto err;
    if (EVP_DigestUpdate(mdctx, SHARED_SECRET, strlen(SHARED_SECRET)) != 1) goto err;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) goto err;

err:
    EVP_MD_CTX_free(mdctx);

    // Combine info and hash into one buffer
    uint8_t combined[sizeof(PacketInfo) + 64]; // 64 is SHA512_DIGEST_LENGTH
    memcpy(combined, &info, sizeof(PacketInfo));
    memcpy(combined + sizeof(PacketInfo), hash, 64);

    size_t total_size = sizeof(combined);
    const char* buffer = reinterpret_cast<const char*>(combined);
    ssize_t sent = 0;

    while ((size_t)sent < total_size) {
        ssize_t n = SSL_write(ssl, buffer + sent, total_size - sent);
        if (n <= 0) {
            break;
        }
        sent += n;
    }
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    SSL* ssl = reinterpret_cast<SSL*>(user_data);

    struct ether_header* eth_header = (struct ether_header*)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    int ip_header_len = ip_header->ip_hl * 4;

    uint32_t src_ip = ip_header->ip_src.s_addr;
    uint32_t dst_ip = ip_header->ip_dst.s_addr;

    uint8_t protocol = ip_header->ip_p;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    const u_char* payload = nullptr;
    int payload_len = 0;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
        int tcp_header_len = tcp_header->th_off * 4;
        src_port = ntohs(tcp_header->source);
        dst_port = ntohs(tcp_header->dest);
        payload = packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
        payload_len = ntohs(ip_header->ip_len) - ip_header_len - tcp_header_len;
    } else if (protocol == IPPROTO_UDP) {
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
    auto duration = std::chrono::microseconds(
        pkthdr->ts.tv_sec * 1000000LL + pkthdr->ts.tv_usec
    );
    info.timestamp = duration.count();
    info.src_ip = src_ip;
    info.dst_ip = dst_ip;
    info.src_port = src_port;
    info.dst_port = dst_port;
    info.protocol = protocol;
    info.payload_len = payload_len;
    memcpy(info.src_mac, eth_header->ether_shost, 6);
    memcpy(info.dst_mac, eth_header->ether_dhost, 6);
    memset(info.payload, 0, sizeof(info.payload));
    if (payload_len > 0 && payload != nullptr) {
        size_t copy_len = (payload_len > MAX_PAYLOAD_SIZE) ? MAX_PAYLOAD_SIZE : payload_len;
        memcpy(info.payload, payload, copy_len);
    }

    send_packet_info(ssl, info);
}

int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    // Force TLS 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    if (!ctx) {
        fprintf(stderr, "Error: Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    pcap_if_t* alldevs;
    pcap_if_t* d;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\r\n", errbuf);
        return 2;
    }
    for (d = alldevs; d != nullptr; d = d->next) {
        if (!(d->flags & PCAP_IF_LOOPBACK)) {
            break;
        }
    }
    if (d == nullptr) d = alldevs;

    if (d == nullptr) {
        fprintf(stderr, "No interfaces found! Make sure libpcap is installed.\r\n");
        pcap_freealldevs(alldevs);
        return 2;
    }

    printf("Listening on %s\r\n", d->name);
    handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\r\n", d->name, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    int sockfd = -1;
    SSL *ssl;
    while (true) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("socket creation failed");
            return 1;
        }

        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(DEST_PORT);
        inet_pton(AF_INET, DEST_IP, &serv_addr.sin_addr);

        std::cout << "Attempting to connect to Rust service at " << DEST_IP << ":" << DEST_PORT << "...\r\n" << std::flush;
        if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == 0) {
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, sockfd);
            if (SSL_connect(ssl) == 1) {
                printf("Connected successfully via TLS.\r\n");
                break;
            } else {
                fprintf(stderr, "TLS Handshake failed.\r\n");
                ERR_print_errors_fp(stderr);
            }
            SSL_free(ssl);
        }

        close(sockfd);
        fprintf(stderr, "Connection failed. Retrying in 2 seconds...\r\n");
        sleep(2);
    }

    pcap_loop(handle, -1, packet_handler, reinterpret_cast<u_char*>(ssl));
    pcap_close(handle);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    pcap_freealldevs(alldevs);

    return 0;
}