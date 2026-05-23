#ifndef PROTOCOL_DISSECTORS_H
#define PROTOCOL_DISSECTORS_H

#include "packet_types.h"
#include <pcap.h>
#include <optional>

// Transport info helper
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

std::optional<EthernetInfo> parse_ethernet_layer(const u_char* packet, uint32_t caplen);
std::optional<IpInfo> parse_ip_layer(const u_char* packet, uint32_t caplen, int eth_hlen);
std::optional<TransportInfo> parse_transport_layer(const u_char* packet, uint32_t caplen, int eth_hlen, const IpInfo& ip_i);

void dissect_dns(const u_char* payload, int len, char* out, int out_max);
void dissect_tls_sni(const u_char* payload, int len, char* out, int out_max);
void dissect_http(const u_char* p, int l, char* o, int m);
void dissect_dhcp(const u_char* p, int l, char* o, int m);
void dissect_ntp(const u_char* p, int l, PacketInfo& i);
void dissect_ntp_core(const u_char* p, int l, PacketInfo& i);
void dissect_lldp(const u_char* p, int l, PacketInfo& i);
void dissect_igmp(const u_char* p, int l, PacketInfo& i);
void dissect_vxlan(const u_char* p, int l, PacketInfo& i);

uint32_t calculate_entropy_scaled(const uint8_t* d, int l);
void calculate_byte_stats(const uint8_t* d, int l, PacketInfo& i);
void parse_tcp_options_extended(const u_char* p, int o, int h, PacketInfo& i);
void check_tcp_anomalies(PacketInfo& info, const TransportInfo& t);

#endif