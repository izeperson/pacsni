#include "protocol_dissectors.h"
#include <cstring>
#include <cmath>
#include <iostream>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#endif

#ifndef _WIN32
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
        const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + eth_hlen);
        info.header_len = ip_hdr->ip_hl * 4;
        if (info.header_len < 20 || caplen < (uint32_t)(eth_hlen + info.header_len)) return std::nullopt;
        std::memcpy(info.src_ip + 12, &ip_hdr->ip_src.s_addr, 4);
        std::memcpy(info.dst_ip + 12, &ip_hdr->ip_dst.s_addr, 4);
        info.protocol = ip_hdr->ip_p;
        info.ttl = ip_hdr->ip_ttl;
        info.tos = ip_hdr->ip_tos;
        info.id = ntohs(ip_hdr->ip_id);
        info.is_ipv6 = false;
        info.is_fragment = (ntohs(ip_hdr->ip_off) & (0x2000 | 0x1fff)) != 0;
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
    if (ip_i.protocol == 6) { // TCP
        if (caplen < (uint32_t)(offset + 20)) return std::nullopt;
        int hlen = ((packet[offset + 12] >> 4) & 0x0f) * 4;
        if (hlen < 20 || caplen < (uint32_t)(offset + hlen)) return std::nullopt;
        t.src_port = ntohs(*(uint16_t*)(packet + offset));
        t.dst_port = ntohs(*(uint16_t*)(packet + offset + 2));
        t.seq = ntohl(*(uint32_t*)(packet + offset + 4));
        t.ack = ntohl(*(uint32_t*)(packet + offset + 8));
        t.window = ntohs(*(uint16_t*)(packet + offset + 14));
        t.flags = packet[offset + 13];
        t.payload_ptr = packet + offset + hlen;
        t.payload_len = ntohs(((const struct ip*)ip_i.header)->ip_len) - ip_i.header_len - hlen;
    } else if (ip_i.protocol == 17) { // UDP
        if (caplen < (uint32_t)(offset + 8)) return std::nullopt;
        t.src_port = ntohs(*(uint16_t*)(packet + offset));
        t.dst_port = ntohs(*(uint16_t*)(packet + offset + 2));
        t.payload_ptr = packet + offset + 8;
        t.payload_len = ntohs(*(uint16_t*)(packet + offset + 4)) - 8;
    }
    return t;
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

void dissect_dns(const u_char* payload, int len, char* out, int out_max) {
    if (len < 12) return;
    const u_char* data = payload + 12;
    int pos = 0, out_pos = 0;
    while (pos < len - 12 && out_pos < out_max - 1) {
        int label_len = data[pos];
        if (label_len == 0 || label_len > 63) break;
        pos++;
        for (int i = 0; i < label_len && pos < len - 12 && out_pos < out_max - 1; i++)
            out[out_pos++] = (char)data[pos++];
        if (out_pos < out_max - 1) out[out_pos++] = '.';
    }
    if (out_pos > 0) out[out_pos - (out[out_pos-1] == '.' ? 1 : 0)] = '\0';
}

void dissect_tls_sni(const u_char* payload, int len, char* out, int out_max) {
    if (len < 43 || payload[0] != 0x16 || payload[5] != 0x01) return;
    int pos = 5 + 38; 
    int sid_len = payload[pos]; pos += 1 + sid_len;
    if (pos + 2 >= len) return;
    uint16_t cs_len = ntohs(*(uint16_t*)(payload + pos)); pos += 2 + cs_len;
    if (pos + 1 >= len) return;
    int comp_len = payload[pos]; pos += 1 + comp_len;
    if (pos + 2 >= len) return;
    int ext_total_len = ntohs(*(uint16_t*)(payload + pos)); pos += 2;
    int ext_end = std::min(pos + ext_total_len, len);
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = ntohs(*(uint16_t*)(payload + pos));
        uint16_t ext_len = ntohs(*(uint16_t*)(payload + pos + 2));
        pos += 4;
        if (ext_type == 0x00 && pos + 5 <= ext_end) {
            int name_len = ntohs(*(uint16_t*)(payload + pos + 3));
            if (pos + 5 + name_len <= ext_end) {
                int actual_copy = std::min(name_len, out_max - 1);
                memcpy(out, payload + pos + 5, actual_copy);
                out[actual_copy] = '\0';
                return;
            }
        }
        pos += ext_len;
    }
}

void dissect_http(const u_char* p, int l, char* o, int m) {
    if (l < 10) return;
    const char* ms[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS "};
    for (int i = 0; i < 6; i++) {
        int ml = strlen(ms[i]);
        if (l > ml && memcmp(p, ms[i], ml) == 0) {
            int c = 0;
            while (c < l && c < m - 1 && p[c] != '\r' && p[c] != '\n') { o[c] = p[c]; c++; }
            o[c] = '\0';
            const char* h = "\r\nHost: ";
            const u_char* hp = (const u_char*)memmem(p, l, h, strlen(h));
            if (hp) snprintf(o + strlen(o), m - strlen(o), " [Host: %.*s]", 32, hp + 8);
            return;
        }
    }
}

void dissect_dhcp(const u_char* p, int l, char* o, int m) {
    if (l < 240 || p[236] != 0x63 || p[237] != 0x82 || p[238] != 0x53 || p[239] != 0x63) return;
    const u_char* opts = p + 240;
    int i = 0;
    while (i < l - 240) {
        uint8_t c = opts[i++];
        if (c == 255) {
            break;
        }
        if (c == 0) {
            continue;
        }
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

void dissect_ntp(const u_char* p, int l, PacketInfo& i) {
    if (l < 48) return;
    i.ntp_mode = p[0] & 0x07;
    i.ntp_stratum = p[1];
    const char* ms[] = {"Res", "SymA", "SymP", "Cli", "Srv", "Bcast", "Ctrl", "Priv"};
    snprintf(i.app_layer_info, 128, "NTP %s (Stratum %d)", ms[i.ntp_mode % 8], i.ntp_stratum);
}

void dissect_ntp_core(const u_char* p, int l, PacketInfo& i) {
    if (l < 48) return;
    uint8_t mode = p[0] & 0x07;
    uint8_t stratum = p[1];
    const char* ms[] = {"Res", "SymA", "SymP", "Cli", "Srv", "Bcast", "Ctrl", "Priv"};
    snprintf(i.app_layer_info + strlen(i.app_layer_info), 128 - strlen(i.app_layer_info), " [Mode: %s, Stratum: %d]", ms[mode % 8], stratum);
}

void dissect_lldp(const u_char* p, int l, PacketInfo& i) {
    int o = 0;
    while (o + 2 <= l) {
        uint16_t tlv = ntohs(*(uint16_t*)(p + o));
        uint16_t type = tlv >> 9, len = tlv & 0x01FF;
        o += 2; if (o + len > l) break;
        if (type == 1) {
            int sl = std::min((int)len - 1, 31);
            memcpy(i.lldp_chassis, p + o + 1, sl); i.lldp_chassis[sl] = '\0';
        } else if (type == 2) {
            int sl = std::min((int)len - 1, 31);
            memcpy(i.lldp_port, p + o + 1, sl); i.lldp_port[sl] = '\0';
        } else if (type == 0) break;
        o += len;
    }
    snprintf(i.app_layer_info, 128, "LLDP %s/%s", i.lldp_chassis, i.lldp_port);
}

void dissect_igmp(const u_char* p, int l, PacketInfo& i) {
    if (l < 8) return;
    i.igmp_type = p[0]; memcpy(i.igmp_group, p + 4, 4);
    const char* ts[] = {"?", "Query", "v1 Report", "v2 Report", "v2 Leave", "v3 Report"};
    const char* t = (i.igmp_type == 0x11) ? ts[1] : (i.igmp_type == 0x12) ? ts[2] : (i.igmp_type == 0x16) ? ts[3] : (i.igmp_type == 0x17) ? ts[4] : (i.igmp_type == 0x22) ? ts[5] : ts[0];
    snprintf(i.extra_info, 128, "IGMP %s Group %u.%u.%u.%u", t, i.igmp_group[0], i.igmp_group[1], i.igmp_group[2], i.igmp_group[3]);
}

void dissect_vxlan(const u_char* p, int l, PacketInfo& i) {
    if (l < 8) return;
    i.vxlan_vni = (p[4] << 16) | (p[5] << 8) | p[6];
    snprintf(i.app_layer_info, 128, "VXLAN VNI: %u", i.vxlan_vni);
}

void parse_tcp_options_extended(const u_char* p, int o, int h, PacketInfo& i) {
    if (h <= 20) return;
    const u_char* opts = p + o + 20;
    int len = h - 20;
    for (int k = 0; k < len; ) {
        uint8_t kind = opts[k];
        if (kind == 0) {
            break;
        }
        if (kind == 1) {
            k++;
            continue;
        }
        if (k + 1 >= len) break;
        uint8_t l = opts[k+1];
        if (l < 2 || k + l > len) break;
        if (kind == 2 && l == 4) i.tcp_mss = ntohs(*(uint16_t*)(opts + k + 2));
        else if (kind == 3 && l == 3) i.tcp_ws = opts[k+2];
        else if (kind == 4 && l == 2) i.tcp_sack = 1;
        else if (kind == 5 && l >= 10) {
            int blocks = std::min((int)(l - 2) / 8, 4);
            memcpy(i.tcp_sack_edges, opts + k + 2, blocks * 8);
        }
        else if (kind == 8 && l == 10) {
            i.tcp_ts_val = ntohl(*(uint32_t*)(opts + k + 2));
            i.tcp_ts_ecr = ntohl(*(uint32_t*)(opts + k + 6));
        } else if (kind == 29) i.has_tcp_ao = 1;
        k += l;
    }
}

void check_tcp_anomalies(PacketInfo& info, const TransportInfo& t) {
    if (t.window == 0 && (t.flags & 0x10) && !(t.flags & (0x02|0x01|0x04))) { // ACK and not SYN/FIN/RST
        snprintf(info.extra_info, 128, "TCP ZeroWindow");
    } else if (info.payload_len == 1 && t.seq + 1 == info.tcp_seq && !(t.flags & (0x02|0x01|0x04))) {
        snprintf(info.extra_info, 128, "TCP Keep-Alive");
    }
}