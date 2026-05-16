use std::net::{SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream as TokioTcpStream};
use tokio::sync::broadcast::{self, Sender};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use bytes::{BytesMut, Buf};
use tokio_rustls::rustls::{self, pki_types::{CertificateDer, PrivateKeyDer}};
use tokio_rustls::TlsAcceptor;
use std::sync::atomic::{AtomicUsize, Ordering};
use sha2::{Sha512, Digest};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::io::BufReader;

const SHARED_SECRET: &[u8] = b"pacsni_secure_shared_secret_123";
const STRUCT_SIZE: usize = 163;
const HASH_SIZE: usize = 64; // SHA-512
const TOTAL_MSG_SIZE: usize = STRUCT_SIZE + HASH_SIZE;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DashboardPacket {
    timestamp: u64,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
    payload: Vec<u8>,
    src_mac: String,
    dst_mac: String,
}

fn ip_addr_to_string(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn mac_addr_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn protocol_to_string(proto: u8) -> String {
    match proto {
        1 => "ICMP".to_string(),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
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

    // Attempt to load PKCS8 keys first
    if let Some(Ok(key)) = rustls_pemfile::pkcs8_private_keys(&mut reader).next() {
        return key.into();
    }

    // Fallback to RSA keys (standard for many self-signed certs)
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

    let cpp_listener = TcpListener::bind(&cpp_addr).await.expect("Failed to bind CPP listener");
    print!("Listening for C++ on {}\r\n", cpp_addr);

    let go_listener = TcpListener::bind(&go_addr).await.expect("Failed to bind GO listener");
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
    // Pre-allocate a reasonable buffer to reduce reallocations
    let mut buffer = BytesMut::with_capacity(TOTAL_MSG_SIZE * 10);
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
            // Peek at the data for hash verification before consuming
            let chunk = &buffer[..STRUCT_SIZE];
            let received_hash = &buffer[STRUCT_SIZE..TOTAL_MSG_SIZE];

            // Verify SHA-512 Signature
            let mut hasher = Sha512::new();
            hasher.update(chunk);
            hasher.update(SHARED_SECRET);
            let expected_hash = hasher.finalize();
            
            if received_hash != expected_hash.as_slice() {
                eprint!("[RUST] CRITICAL: Authentication failed from peer {}. Dropping connection.\r\n", "C++");
                return Err(io::Error::new(io::ErrorKind::InvalidData, "SHA-512 Authentication Failed"));
            }

            // Now safely consume the buffer using Buf trait
            let timestamp = buffer.get_u64_le();
            let src_ip_raw = buffer.get_u32();
            let dst_ip_raw = buffer.get_u32();
            let src_port = buffer.get_u16_le();
            let dst_port = buffer.get_u16_le();
            let protocol = buffer.get_u8();
            let payload_len = buffer.get_u16_le();
            
            let mut src_mac_raw = [0u8; 6];
            buffer.copy_to_slice(&mut src_mac_raw);
            let mut dst_mac_raw = [0u8; 6];
            buffer.copy_to_slice(&mut dst_mac_raw);

            let mut payload_raw = [0u8; 128];
            buffer.copy_to_slice(&mut payload_raw);
            
            // Advance past the hash (we already peeked at it)
            buffer.advance(HASH_SIZE);

            let valid_len = (payload_len as usize).min(128);
            let valid_payload = &payload_raw[..valid_len];
            
            let packet = DashboardPacket {
                timestamp,
                src_ip: ip_addr_to_string(&src_ip_raw.to_be_bytes()),
                dst_ip: ip_addr_to_string(&dst_ip_raw.to_be_bytes()),
                src_port,
                dst_port,
                protocol: protocol_to_string(protocol),
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