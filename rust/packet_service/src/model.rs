use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DashboardPacket {
    pub timestamp: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub has_tcp_ao: bool,
    pub tcp_flags: u8,
    pub l3_offset: u8,
    pub l4_offset: u8,
    pub tcp_seq: u32,
    pub tcp_ack: u32,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub delta_time: u32,
    pub vlan_id: u16,
    pub ip_ttl: u8,
    pub ip_tos: u8,
    pub tcp_win: u16,
    pub ip_id: u16,
    pub is_ipv6: bool,
    pub is_fragment: bool,
    pub tcp_mss: u16,
    pub tcp_ws: u8,
    pub ipv6_ext_count: u8,
    pub ipv6_flow: u32,
    pub wire_len: u32,
    pub tcp_ts_val: u32,
    pub tcp_ts_ecr: u32,
    pub tcp_sack: bool,
    pub tcp_rtt: u32,
    pub vxlan_vni: u32,
    pub entropy_scaled: u32,
    pub ntp_stratum: u8,
    pub ntp_mode: u8,
    pub igmp_group: String,
    pub igmp_type: u8,
    pub lldp_chassis: String,
    pub lldp_port: String,
    pub tcp_sack_edges: Vec<u32>,
    pub top_byte_info: String,
    pub dns_query: String,
    pub tls_sni: String,
    pub extra_info: String,
    pub app_layer_info: String,
    pub payload: Vec<u8>,
    pub src_mac: String,
    pub dst_mac: String,
}

pub fn ip_addr_to_string(ip: &[u8; 16], is_v6: bool) -> String {
    if is_v6 {
        format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
            ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]
        )
    } else {
        format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15])
    }
}

pub fn mac_addr_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub fn protocol_to_string(proto: u8, src_port: u16, dst_port: u16) -> String {
    match proto {
        1 => "ICMP".to_string(),
        6 => {
            if src_port == 80 || dst_port == 80 {
                "HTTP".to_string()
            } else if src_port == 443 || dst_port == 443 {
                "HTTPS".to_string()
            } else {
                "TCP".to_string()
            }
        },
        17 => {
            if src_port == 67 || src_port == 68 || dst_port == 67 || dst_port == 68 {
                "DHCP".to_string()
            } else if src_port == 53 || dst_port == 53 {
                "DNS".to_string()
            } else {
                "UDP".to_string()
            }
        },
        58 => "ICMPv6".to_string(),
        89 => "OSPF".to_string(),
        200 => "ARP".to_string(),
        202 => "STP".to_string(),
        _ => format!("Unknown({})", proto),
    }
}