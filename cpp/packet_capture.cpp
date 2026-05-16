#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <chrono>

// Configuration
const char* DEST_IP = "127.0.0.1";
const int DEST_PORT = 9001;
const int MAX_PAYLOAD_SIZE = 128; // Fixed payload size we will send

// PacketInfo struct to send over TCP (fixed size, no padding)
struct __attribute__((__packed__)) PacketInfo {
    uint64_t timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint16_t payload_len;   // actual payload length in packet (for info)
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint8_t  payload[MAX_PAYLOAD_SIZE]; // fixed size payload buffer
};

// Function to send packet info via TCP
void send_packet_info(int sockfd, const PacketInfo& info) {
    // Send the fixed-size struct
    ssize_t sent = 0;
    const char* buffer = reinterpret_cast<const char*>(&info);
    size_t total_size = sizeof(PacketInfo);

    while ((size_t)sent < total_size) {
        ssize_t n = write(sockfd, buffer + sent, total_size - sent);
        if (n <= 0) {
            std::cerr << "Error sending data: " << strerror(errno) << std::endl;
            break;
        }
        sent += n;
    }
}

// Callback function for pcap
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Get the TCP socket from user_data (we'll pass it as u_char*)
    int* sockfd_ptr = reinterpret_cast<int*>(user_data);
    int sockfd = *sockfd_ptr;

    // Parse Ethernet header
    struct ether_header* eth_header = (struct ether_header*)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return; // Not an IP packet
    }

    // Parse IP header
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    int ip_header_len = ip_header->ip_hl * 4;

    // Extract IP addresses
    uint32_t src_ip = ip_header->ip_src.s_addr;
    uint32_t dst_ip = ip_header->ip_dst.s_addr;

    // Determine protocol and parse accordingly
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
        // Other protocols (like ICMP) - we still send but with zero ports
        payload = packet + sizeof(struct ether_header) + ip_header_len;
        payload_len = ntohs(ip_header->ip_len) - ip_header_len;
    }

    // Prepare PacketInfo
    PacketInfo info;
    // Convert timestamp to microseconds since epoch
    auto duration = std::chrono::microseconds(
        pkthdr->ts.tv_sec * 1000000LL + pkthdr->ts.tv_usec
    );
    info.timestamp = duration.count();
    info.src_ip = src_ip;
    info.dst_ip = dst_ip;
    info.src_port = src_port;
    info.dst_port = dst_port;
    info.protocol = protocol;
    info.payload_len = payload_len; // actual length (might be > MAX_PAYLOAD_SIZE)
    memcpy(info.src_mac, eth_header->ether_shost, 6);
    memcpy(info.dst_mac, eth_header->ether_dhost, 6);
    // Zero the payload buffer
    memset(info.payload, 0, sizeof(info.payload));
    // Copy up to MAX_PAYLOAD_SIZE bytes of payload
    if (payload_len > 0 && payload != nullptr) {
        size_t copy_len = (payload_len > MAX_PAYLOAD_SIZE) ? MAX_PAYLOAD_SIZE : payload_len;
        memcpy(info.payload, payload, copy_len);
    }

    // Send the packet info
    send_packet_info(sockfd, info);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Find a network interface
    pcap_if_t* alldevs;
    pcap_if_t* d;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 2;
    }

    // Find the first non-loopback interface
    for (d = alldevs; d != nullptr; d = d->next) {
        if (!(d->flags & PCAP_IF_LOOPBACK)) {
            break;
        }
    }
    if (d == nullptr) d = alldevs; // Fallback to first if only loopback exists

    if (d == nullptr) {
        fprintf(stderr, "No interfaces found! Make sure libpcap is installed.\n");
        pcap_freealldevs(alldevs);
        return 2;
    }

    printf("Listening on %s\n", d->name);

    // Open the interface in promiscuous mode
    handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", d->name, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    int sockfd = -1;
    while (true) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("socket");
            return 1;
        }

        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(DEST_PORT);
        inet_pton(AF_INET, DEST_IP, &serv_addr.sin_addr);

        std::cout << "Attempting to connect to Rust service at " << DEST_IP << ":" << DEST_PORT << "..." << std::endl;
        if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == 0) {
            printf("Connected successfully.\n");
            break;
        }

        close(sockfd);
        std::cerr << "Connection failed. Retrying in 2 seconds..." << std::endl;
        sleep(2);
    }

    // Pass the socketfd to the packet handler via user_data
    u_char* user_data = reinterpret_cast<u_char*>(&sockfd);

    // Start capturing packets
    pcap_loop(handle, -1, packet_handler, user_data);

    // Cleanup
    pcap_close(handle);
    close(sockfd);
    pcap_freealldevs(alldevs);

    return 0;
}