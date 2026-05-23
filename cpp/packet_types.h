#ifndef PACKET_TYPES_H
#define PACKET_TYPES_H

#include <cstdint>
#include <queue>
#include <atomic>
#include <pcap.h>
#include <openssl/ssl.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/if_ether.h>
#endif

template <typename T>
class LockFreeQueue {
public:
    explicit LockFreeQueue(size_t capacity) :
        capacity_mask_(capacity - 1),
        buffer_(new Node[capacity]) {
        for (size_t i = 0; i < capacity; ++i) {
            buffer_[i].sequence.store(i, std::memory_order_relaxed);
        }
    }
    ~LockFreeQueue() { delete[] buffer_; }

    LockFreeQueue(const LockFreeQueue&) = delete;
    LockFreeQueue& operator=(const LockFreeQueue&) = delete;

    bool push(const T& data) {
        size_t pos = enqueue_pos_.load(std::memory_order_relaxed);
        for (;;) {
            Node& node = buffer_[pos & capacity_mask_];
            size_t seq = node.sequence.load(std::memory_order_acquire);
            intptr_t diff = (intptr_t)seq - (intptr_t)pos;
            if (diff == 0) {
                if (enqueue_pos_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                    node.data = data;
                    node.sequence.store(pos + 1, std::memory_order_release);
                    return true;
                }
            } else if (diff < 0) {
                return false;
            } else {
                pos = enqueue_pos_.load(std::memory_order_relaxed);
            }
        }
    }

    bool pop(T& data) {
        size_t pos = dequeue_pos_.load(std::memory_order_relaxed);
        for (;;) {
            Node& node = buffer_[pos & capacity_mask_];
            size_t seq = node.sequence.load(std::memory_order_acquire);
            intptr_t diff = (intptr_t)seq - (intptr_t)(pos + 1);
            if (diff == 0) {
                if (dequeue_pos_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                    data = node.data;
                    node.sequence.store(pos + capacity_mask_ + 1, std::memory_order_release);
                    return true;
                }
            } else if (diff < 0) {
                return false;
            } else {
                pos = dequeue_pos_.load(std::memory_order_relaxed);
            }
        }
    }

private:
    struct Node {
        std::atomic<size_t> sequence;
        T data;
    };
    const size_t capacity_mask_;
    Node* const buffer_;
    alignas(64) std::atomic<size_t> enqueue_pos_{0};
    alignas(64) std::atomic<size_t> dequeue_pos_{0};
};

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
    uint8_t  final_pad[8];
};
#ifdef _WIN32
#pragma pack(pop)
#endif

static_assert(sizeof(PacketInfo) == 1024, "PacketInfo struct must be exactly 1024 bytes for protocol compatibility.");

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

struct RawPacket {
    struct pcap_pkthdr pkthdr;
    uint8_t data[MAX_PAYLOAD_SIZE];
    uint32_t delta_time;
};

struct CaptureContext {
    SSL* ssl;
    LockFreeQueue<PacketInfo> dissected_queue;
    LockFreeQueue<RawPacket> raw_queue;

    CaptureContext() : dissected_queue(8192), raw_queue(8192) {}
};

#endif