use std::sync::Arc;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream as TokioTcpStream};
use tokio::sync::broadcast::{self, Sender};
use bytes::{BytesMut, Buf};
use ring::hmac;
use std::sync::atomic::Ordering;
use crate::model::*;
use crate::{TOTAL_MSG_SIZE, STRUCT_SIZE, HASH_SIZE, SHARED_SECRET, PACKET_COUNT};

pub async fn handle_cpp_connection<S: io::AsyncRead + io::AsyncWrite + Unpin>(
    mut socket: S, 
    tx: Arc<Sender<DashboardPacket>>
) -> io::Result<()> {
    let mut buffer = BytesMut::with_capacity(TOTAL_MSG_SIZE * 10);
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, SHARED_SECRET);

    loop {
        if buffer.capacity() - buffer.len() < TOTAL_MSG_SIZE {
            buffer.reserve(1024);
        }

        let n = socket.read_buf(&mut buffer).await?;
        if n == 0 { break; }

        if buffer.len() > 2 * 1024 * 1024 {
            eprint!("[RUST] Buffer too large, clearing\r\n");
            buffer.clear();
            continue;
        }

        while buffer.len() >= TOTAL_MSG_SIZE {
            let chunk = &buffer[..STRUCT_SIZE];
            let received_hash = &buffer[STRUCT_SIZE..TOTAL_MSG_SIZE];

            if hmac::verify(&hmac_key, chunk, received_hash).is_err() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HMAC Authentication Failed"));
            }

            let timestamp = buffer.get_u64_le();
            let mut src_ip_raw = [0u8; 16]; buffer.copy_to_slice(&mut src_ip_raw);
            let mut dst_ip_raw = [0u8; 16]; buffer.copy_to_slice(&mut dst_ip_raw);
            let src_port = buffer.get_u16_le();
            let dst_port = buffer.get_u16_le();
            let protocol = buffer.get_u8();
            let has_tcp_ao = buffer.get_u8() != 0;
            let tcp_flags = buffer.get_u8();
            let l3_offset = buffer.get_u8();
            let l4_offset = buffer.get_u8();
            let tcp_seq = buffer.get_u32_le();
            let tcp_ack = buffer.get_u32_le();
            let icmp_type = buffer.get_u8();
            let icmp_code = buffer.get_u8();
            let delta_time = buffer.get_u32_le();
            let vlan_id = buffer.get_u16_le();
            let ip_ttl = buffer.get_u8();
            let ip_tos = buffer.get_u8();
            let tcp_win = buffer.get_u16_le();
            let ip_id = buffer.get_u16_le();
            let is_ipv6 = buffer.get_u8() != 0;
            let is_fragment = buffer.get_u8() != 0;
            let tcp_mss = buffer.get_u16_le();
            let tcp_ws = buffer.get_u8();
            let ipv6_ext_count = buffer.get_u8();
            let ipv6_flow = buffer.get_u32_le();
            let wire_len = buffer.get_u32_le();
            let tcp_ts_val = buffer.get_u32_le();
            let tcp_ts_ecr = buffer.get_u32_le();
            let tcp_sack = buffer.get_u8() != 0;
            let tcp_rtt = buffer.get_u32_le();
            let vxlan_vni = buffer.get_u32_le();
            let entropy_scaled = buffer.get_u32_le();
            let ntp_stratum = buffer.get_u8();
            let ntp_mode = buffer.get_u8();
            let igmp_type = buffer.get_u8();
            let mut igmp_group_raw = [0u8; 4]; buffer.copy_to_slice(&mut igmp_group_raw);
            let mut lldp_c_raw = [0u8; 32]; buffer.copy_to_slice(&mut lldp_c_raw);
            let mut lldp_p_raw = [0u8; 32]; buffer.copy_to_slice(&mut lldp_p_raw);
            let mut sack_edges = Vec::with_capacity(8);
            for _ in 0..8 { sack_edges.push(buffer.get_u32_le()); }
            let top_byte = buffer.get_u8();
            let top_freq = buffer.get_u8();
            
            buffer.advance(151); // Skip padding
            let payload_len = buffer.get_u16_le();
            let mut src_mac_raw = [0u8; 6]; buffer.copy_to_slice(&mut src_mac_raw);
            let mut dst_mac_raw = [0u8; 6]; buffer.copy_to_slice(&mut dst_mac_raw);
            let mut dns_raw = [0u8; 64]; buffer.copy_to_slice(&mut dns_raw);
            let mut sni_raw = [0u8; 64]; buffer.copy_to_slice(&mut sni_raw);
            let mut extra_raw = [0u8; 128]; buffer.copy_to_slice(&mut extra_raw);
            let mut app_raw = [0u8; 128]; buffer.copy_to_slice(&mut app_raw);
            let mut payload_raw = [0u8; 256]; buffer.copy_to_slice(&mut payload_raw);
            
            buffer.advance(8); // Final padding
            buffer.advance(HASH_SIZE);

            let packet = DashboardPacket {
                timestamp,
                src_ip: ip_addr_to_string(&src_ip_raw, is_ipv6),
                dst_ip: ip_addr_to_string(&dst_ip_raw, is_ipv6),
                src_port, dst_port,
                protocol: protocol_to_string(protocol, src_port, dst_port),
                has_tcp_ao, tcp_flags, l3_offset, l4_offset,
                tcp_seq, tcp_ack, icmp_type, icmp_code, delta_time, vlan_id,
                ip_ttl, ip_tos, tcp_win, ip_id, is_ipv6, is_fragment,
                tcp_mss, tcp_ws, ipv6_ext_count, ipv6_flow, wire_len,
                tcp_ts_val, tcp_ts_ecr, tcp_sack, tcp_rtt, vxlan_vni, entropy_scaled,
                ntp_stratum, ntp_mode,
                igmp_group: format!("{}.{}.{}.{}", igmp_group_raw[0], igmp_group_raw[1], igmp_group_raw[2], igmp_group_raw[3]),
                igmp_type,
                lldp_chassis: String::from_utf8_lossy(&lldp_c_raw).trim_matches('\0').to_string(),
                lldp_port: String::from_utf8_lossy(&lldp_p_raw).trim_matches('\0').to_string(),
                tcp_sack_edges: sack_edges,
                top_byte_info: format!("0x{:02x} ({}%)", top_byte, top_freq),
                dns_query: String::from_utf8_lossy(&dns_raw).trim_matches('\0').to_string(),
                tls_sni: String::from_utf8_lossy(&sni_raw).trim_matches('\0').to_string(),
                extra_info: String::from_utf8_lossy(&extra_raw).trim_matches('\0').to_string(),
                app_layer_info: String::from_utf8_lossy(&app_raw).trim_matches('\0').to_string(),
                payload: payload_raw[..(payload_len as usize).min(256)].to_vec(),
                src_mac: mac_addr_to_string(&src_mac_raw),
                dst_mac: mac_addr_to_string(&dst_mac_raw),
            };

            let _ = tx.send(packet);
            PACKET_COUNT.fetch_add(1, Ordering::SeqCst);
        }
    }
    Ok(())
}

pub async fn handle_go_connection(mut socket: TokioTcpStream, tx: Arc<Sender<DashboardPacket>>) -> io::Result<()> {
    let mut rx = tx.subscribe();
    loop {
        let packet: DashboardPacket = match rx.recv().await {
            Ok(pkt) => pkt,
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                eprint!("[RUST] Web Client Lagged: {} packets skipped\r\n", skipped);
                continue;
            }
            Err(_) => break,
        };

        let json = match serde_json::to_string(&packet) {
            Ok(j) => j,
            Err(_) => continue,
        };

        if let Err(_) = socket.write_all(format!("{}\n", json).as_bytes()).await {
            break;
        }
    }
    Ok(())
}