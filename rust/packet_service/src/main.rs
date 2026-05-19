use std::net::{SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::{TcpStream as TokioTcpStream, TcpSocket};
use tokio::sync::broadcast::{self, Sender};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use bytes::{BytesMut, Buf};
use tokio_rustls::rustls::{self, pki_types::{CertificateDer, PrivateKeyDer}};
use tokio_rustls::TlsAcceptor;
use ring::hmac;
use std::sync::atomic::{AtomicUsize, Ordering};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::io::BufReader;

const SHARED_SECRET: &[u8] = b"pacsni_secure_shared_secret_123";
const STRUCT_SIZE: usize = 1024;
const HASH_SIZE: usize = 64;
const TOTAL_MSG_SIZE: usize = STRUCT_SIZE + HASH_SIZE;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DashboardPacket {
    timestamp: u64,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
    has_tcp_ao: bool,
    tcp_flags: u8,
    l3_offset: u8,
    l4_offset: u8,
    tcp_seq: u32,
    tcp_ack: u32,
    icmp_type: u8,
    icmp_code: u8,
    delta_time: u32,
    vlan_id: u16,
    ip_ttl: u8,
    ip_tos: u8,
    tcp_win: u16,
    ip_id: u16,
    is_ipv6: bool,
    is_fragment: bool,
    tcp_mss: u16,
    tcp_ws: u8,
    ipv6_ext_count: u8,
    ipv6_flow: u32,
    wire_len: u32,
    tcp_ts_val: u32,
    tcp_ts_ecr: u32,
    tcp_sack: bool,
    tcp_rtt: u32,
    vxlan_vni: u32,
    entropy_scaled: u32,
    ntp_stratum: u8,
    ntp_mode: u8,
    igmp_group: String,
    igmp_type: u8,
    lldp_chassis: String,
    lldp_port: String,
    tcp_sack_edges: Vec<u32>,
    top_byte_info: String,
    dns_query: String,
    tls_sni: String,
    extra_info: String,
    app_layer_info: String,
    payload: Vec<u8>,
    src_mac: String,
    dst_mac: String,
}

fn ip_addr_to_string(ip: &[u8; 16], is_v6: bool) -> String {
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

fn mac_addr_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn protocol_to_string(proto: u8, src_port: u16, dst_port: u16) -> String {
    match proto {
        1 => "ICMP".to_string(),
        6 => {
            if src_port == 80 || dst_port == 80 {
                "HTTP".to_string()
            } else {
                "TCP".to_string()
            }
        },
        17 => {
            if src_port == 67 || src_port == 68 || dst_port == 67 || dst_port == 68 {
                "DHCP".to_string()
            } else {
                "UDP".to_string()
            }
        },
        58 => "ICMPv6".to_string(),
        89 => "OSPF".to_string(),
        200 => "ARP".to_string(),
        201 => "ND".to_string(),
        202 => "STP".to_string(),
        _ => format!("Unknown({})", proto),
    }
}

fn load_certs(path: &str) -> Vec<CertificateDer<'static>> {
    let file = File::open(path).expect("cannot open cert file");
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .map(|result| result.expect("invalid cert"))
        .collect()
}

fn load_key(path: &str) -> PrivateKeyDer<'static> {
    let file = File::open(path).expect("cannot open key file");
    let mut reader = BufReader::new(file);

    if let Some(Ok(key)) = rustls_pemfile::pkcs8_private_keys(&mut reader).next() {
        return key.into();
    }

    let mut reader = BufReader::new(File::open(path).expect("cannot reopen key file"));
    if let Some(Ok(key)) = rustls_pemfile::rsa_private_keys(&mut reader).next() {
        return key.into();
    }

    panic!("No valid private key found in {}. Ensure it is PKCS#8 or RSA format.", path);
}

static PACKET_COUNT: AtomicUsize = AtomicUsize::new(0);

#[tokio::main]
async fn main() {
    let (tx, _rx): (Sender<DashboardPacket>, _) = broadcast::channel(100);
    let tx_arc = Arc::new(tx);

    let certs = load_certs("server.crt");
    let key = load_key("server.key");
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("bad certificate/key");
    let acceptor = TlsAcceptor::from(Arc::new(config));

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            let count = PACKET_COUNT.swap(0, Ordering::SeqCst);
            if count > 0 {
                print!("METRICS: Processing {} packets/sec\r\n", count);
            }
        }
    });

    let cpp_addr = SocketAddr::from_str("127.0.0.1:9001").expect("Invalid CPP address");
    let go_addr = SocketAddr::from_str("127.0.0.1:9003").expect("Invalid GO address");

    let cpp_socket = TcpSocket::new_v4().expect("Failed to create CPP socket");
    cpp_socket.set_reuseaddr(true).expect("Failed to set reuseaddr on CPP socket");
    #[cfg(unix)]
    cpp_socket.set_reuseport(true).expect("Failed to set reuseport on CPP socket");
    cpp_socket.bind(cpp_addr).expect("Failed to bind CPP socket");
    let cpp_listener = cpp_socket.listen(1024).expect("Failed to listen on CPP socket");
    print!("Listening for C++ on {}\r\n", cpp_addr);

    let go_socket = TcpSocket::new_v4().expect("Failed to create GO socket");
    go_socket.set_reuseaddr(true).expect("Failed to set reuseaddr on GO socket");
    #[cfg(unix)]
    go_socket.set_reuseport(true).expect("Failed to set reuseport on GO socket");
    go_socket.bind(go_addr).expect("Failed to bind GO socket");
    let go_listener = go_socket.listen(1024).expect("Failed to listen on GO socket");
    print!("Listening for GO on {}\r\n", go_addr);

    let cpp_tx = tx_arc.clone();
    let go_tx = tx_arc.clone();

    let cpp_handle = tokio::spawn(async move {
        loop {
            match cpp_listener.accept().await {
                Ok((socket, addr)) => {
                    print!("[RUST] New C++ TLS connection from {}\r\n", addr);
                    let tx = cpp_tx.clone();
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(socket).await {
                            Ok(tls_stream) => {
                                if let Err(e) = handle_cpp_connection(tls_stream, tx).await {
                                    eprint!("[RUST] Error handling C++ connection: {}\r\n", e);
                                }
                            }
                            Err(e) => eprint!("TLS acceptance error: {}\r\n", e),
                        }
                    });
                }
                Err(e) => {
                    eprint!("Failed to accept C++ connection: {}\r\n", e);
                }
            }
        }
    });

    let go_handle = tokio::spawn(async move {
        loop {
            match go_listener.accept().await {
                Ok((socket, addr)) => {
                    print!("[RUST] New GO connection from {}\r\n", addr);
                    let tx = go_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_go_connection(socket, tx).await {
                            eprint!("Error handling GO connection: {}\r\n", e);
                        }
                    });
                }
                Err(e) => {
                    eprint!("Failed to accept GO connection: {}\r\n", e);
                }
            }
        }
    });

    let _ = tokio::try_join!(cpp_handle, go_handle);
}

async fn handle_cpp_connection<S: io::AsyncRead + io::AsyncWrite + Unpin>(mut socket: S, tx: Arc<Sender<DashboardPacket>>) -> io::Result<()> {
    let mut buffer = BytesMut::with_capacity(TOTAL_MSG_SIZE * 10);
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, SHARED_SECRET);

    loop {
        if buffer.capacity() - buffer.len() < TOTAL_MSG_SIZE {
            buffer.reserve(1024);
        }

        let n = socket.read_buf(&mut buffer).await?;
        if n == 0 {
            break;
        }

        if buffer.len() > 1024 * 1024 {
            eprint!("[RUST] Buffer overflow detected ({} bytes), clearing buffer\r\n", buffer.len());
            buffer.clear();
            continue;
        }

        while buffer.len() >= TOTAL_MSG_SIZE {
            let chunk = &buffer[..STRUCT_SIZE];
            let received_hash = &buffer[STRUCT_SIZE..TOTAL_MSG_SIZE];

            if hmac::verify(&hmac_key, chunk, received_hash).is_err() {
                eprint!("[RUST] CRITICAL: Authentication failed from peer {}. Dropping connection.\r\n", "C++");
                return Err(io::Error::new(io::ErrorKind::InvalidData, "SHA-512 Authentication Failed"));
            }

            let timestamp = buffer.get_u64_le();
            let mut src_ip_raw = [0u8; 16];
            buffer.copy_to_slice(&mut src_ip_raw);
            let mut dst_ip_raw = [0u8; 16];
            buffer.copy_to_slice(&mut dst_ip_raw);
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
            let mut igmp_group_raw = [0u8; 4];
            buffer.copy_to_slice(&mut igmp_group_raw);
            let mut lldp_c_raw = [0u8; 32];
            buffer.copy_to_slice(&mut lldp_c_raw);
            let mut lldp_p_raw = [0u8; 32];
            buffer.copy_to_slice(&mut lldp_p_raw);
            let mut sack_edges = Vec::with_capacity(8);
            for _ in 0..8 { sack_edges.push(buffer.get_u32_le()); }
            let top_byte = buffer.get_u8();
            let top_freq = buffer.get_u8();
            buffer.advance(151); // Synchronized with C++ 1024-byte alignment
            let payload_len = buffer.get_u16_le();
            
            let mut src_mac_raw = [0u8; 6];
            buffer.copy_to_slice(&mut src_mac_raw);
            let mut dst_mac_raw = [0u8; 6];
            buffer.copy_to_slice(&mut dst_mac_raw);

            let mut dns_raw = [0u8; 64];
            buffer.copy_to_slice(&mut dns_raw);
            let dns_query = String::from_utf8_lossy(&dns_raw).trim_matches(char::from(0)).to_string();

            let mut sni_raw = [0u8; 64];
            buffer.copy_to_slice(&mut sni_raw);
            let tls_sni = String::from_utf8_lossy(&sni_raw).trim_matches(char::from(0)).to_string();

            let mut extra_raw = [0u8; 128];
            buffer.copy_to_slice(&mut extra_raw);
            let extra_info = String::from_utf8_lossy(&extra_raw).trim_matches(char::from(0)).to_string();

            let mut app_raw = [0u8; 128];
            buffer.copy_to_slice(&mut app_raw);
            let app_layer_info = String::from_utf8_lossy(&app_raw).trim_matches(char::from(0)).to_string();

            let mut payload_raw = [0u8; 256];
            buffer.copy_to_slice(&mut payload_raw);
            
            buffer.advance(8); // Synchronized to match C++ struct padding for 1024-byte alignment
            buffer.advance(HASH_SIZE);

            let valid_len = (payload_len as usize).min(256);
            let valid_payload = &payload_raw[..valid_len];
            
            let packet = DashboardPacket {
                timestamp,
                src_ip: ip_addr_to_string(&src_ip_raw, is_ipv6),
                dst_ip: ip_addr_to_string(&dst_ip_raw, is_ipv6),
                src_port,
                dst_port,
                protocol: protocol_to_string(protocol, src_port, dst_port),
                has_tcp_ao,
                tcp_flags,
                l3_offset,
                l4_offset,
                tcp_seq,
                tcp_ack,
                icmp_type,
                icmp_code,
                delta_time,
                vlan_id,
                ip_ttl,
                ip_tos,
                tcp_win,
                ip_id,
                is_ipv6,
                is_fragment,
                tcp_mss,
                tcp_ws,
                ipv6_ext_count,
                ipv6_flow,
                wire_len,
                tcp_ts_val,
                tcp_ts_ecr,
                tcp_sack,
                tcp_rtt,
                vxlan_vni,
                entropy_scaled,
                ntp_stratum,
                ntp_mode,
                igmp_group: format!("{}.{}.{}.{}", igmp_group_raw[0], igmp_group_raw[1], igmp_group_raw[2], igmp_group_raw[3]),
                igmp_type,
                lldp_chassis: String::from_utf8_lossy(&lldp_c_raw).trim_matches(char::from(0)).to_string(),
                lldp_port: String::from_utf8_lossy(&lldp_p_raw).trim_matches(char::from(0)).to_string(),
                tcp_sack_edges: sack_edges,
                top_byte_info: format!("0x{:02x} ({}%)", top_byte, top_freq),
                dns_query,
                tls_sni,
                extra_info,
                app_layer_info,
                payload: valid_payload.to_vec(),
                src_mac: mac_addr_to_string(&src_mac_raw),
                dst_mac: mac_addr_to_string(&dst_mac_raw),
            };

            let _ = tx.send(packet);
            PACKET_COUNT.fetch_add(1, Ordering::SeqCst);
        }
    }

    Ok(())
}

async fn handle_go_connection(mut socket: TokioTcpStream, tx: Arc<Sender<DashboardPacket>>) -> io::Result<()> {
    let mut rx = tx.subscribe();
    loop {
        
        let packet = match rx.recv().await {
            Ok(pkt) => pkt,
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                eprint!("Go client lagged, skipped {} packets\r\n", skipped);
                continue;
            }
            Err(e) => {
                eprint!("Error receiving from broadcast channel: {}\r\n", e);
                break;
            }
        };

        let json = match serde_json::to_string(&packet) {
            Ok(j) => j,
            Err(e) => {
                eprint!("Error serializing packet to JSON: {}\r\n", e);
                continue;
            }
        };

        let line = format!("{}\n", json);
        if let Err(e) = socket.write_all(line.as_bytes()).await {
            eprint!("Failed to send data to Go dashboard ({}). Closing connection.\r\n", e);
            break;
        }
    }

    Ok(())
}