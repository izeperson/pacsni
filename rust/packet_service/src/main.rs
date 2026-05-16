use std::net::{SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream as TokioTcpStream};
use tokio::sync::broadcast::{self, Sender};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use bytes::{BytesMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use serde::{Deserialize, Serialize};
use serde_json;

// Define the packet structure that we will send to Go (as JSON)
#[derive(Debug, Serialize, Deserialize, Clone)]
struct DashboardPacket {
    timestamp: u64, // microseconds since UNIX epoch
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
    payload: Vec<u8>, // we'll limit the payload size for display
    src_mac: String,
    dst_mac: String,
}

// We'll define a helper to convert IP address bytes to string
fn ip_addr_to_string(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn mac_addr_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

// We'll define a helper to convert protocol number to string
fn protocol_to_string(proto: u8) -> String {
    match proto {
        1 => "ICMP".to_string(),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        _ => format!("Unknown({})", proto),
    }
}

static PACKET_COUNT: AtomicUsize = AtomicUsize::new(0);

#[tokio::main]
async fn main() {
    // Set up a broadcast channel for sharing packet data between tasks
    let (tx, _rx): (Sender<DashboardPacket>, _) = broadcast::channel(100);
    let tx_arc = Arc::new(tx);

    // Spawn a metrics thread to log PPS (Packets Per Second)
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            let count = PACKET_COUNT.swap(0, Ordering::SeqCst);
            if count > 0 {
                println!("METRICS: Processing {} packets/sec", count);
            }
        }
    });

    // Addresses for our TCP listeners
    let cpp_addr = SocketAddr::from_str("127.0.0.1:9001").expect("Invalid CPP address");
    let go_addr = SocketAddr::from_str("127.0.0.1:9003").expect("Invalid GO address");

    // Listener for C++ program (receiving raw packet data)
    let cpp_listener = TcpListener::bind(&cpp_addr).await.expect("Failed to bind CPP listener");
    println!("Listening for C++ on {}", cpp_addr);

    // Listener for Go program (sending JSON packet data)
    let go_listener = TcpListener::bind(&go_addr).await.expect("Failed to bind GO listener");
    println!("Listening for GO on {}", go_addr);

    // Clone the broadcast sender for each listener task
    let cpp_tx = tx_arc.clone();
    let go_tx = tx_arc.clone();

    // Spawn task to handle C++ connections
    let cpp_handle = tokio::spawn(async move {
        loop {
            match cpp_listener.accept().await {
                Ok((socket, addr)) => {
                    println!("New C++ connection from {}", addr);
                    let tx = cpp_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_cpp_connection(socket, tx).await {
                            eprintln!("Error handling C++ connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept C++ connection: {}", e);
                }
            }
        }
    });

    // Spawn task to handle Go connections
    let go_handle = tokio::spawn(async move {
        loop {
            match go_listener.accept().await {
                Ok((socket, addr)) => {
                    println!("New GO connection from {}", addr);
                    let tx = go_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_go_connection(socket, tx).await {
                            eprintln!("Error handling GO connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept GO connection: {}", e);
                }
            }
        }
    });

    // Wait for both tasks (they run forever, so we just wait)
    let _ = tokio::try_join!(cpp_handle, go_handle);
}

// Handle a connection from the C++ program
async fn handle_cpp_connection(mut socket: TokioTcpStream, tx: Arc<Sender<DashboardPacket>>) -> io::Result<()> {
    // We expect to receive PacketInfo structs from the C++ program.
    // The C++ program sends a fixed-size struct:
    //   timestamp (u64), src_ip (u32), dst_ip (u32), src_port (u16), dst_port (u16),
    //   protocol (u8), payload_len (u16), and then payload[MAX_PAYLOAD_SIZE] bytes.

    // Let's calculate the 163-byte packet size:
    //   timestamp: 8, src_ip: 4, dst_ip: 4, src_port: 2, dst_port: 2,
    //   protocol: 1, payload_len: 2, src_mac: 6, dst_mac: 6, payload: 128
    // Total: 8+4+4+2+2+1+2+6+6+128 = 163 bytes.

    let mut buffer = BytesMut::with_capacity(1024);
    loop {
        // Ensure the buffer has enough remaining capacity to read at least one full packet.
        // BytesMut::read_buf will only read into existing capacity.
        if buffer.capacity() - buffer.len() < 163 {
            buffer.reserve(1024);
        }

        let n = socket.read_buf(&mut buffer).await?;
        if n == 0 {
            // Connection closed
            break;
        }

        // Validation: ensure the buffer hasn't grown out of control (e.g., due to malformed data)
        if buffer.len() > 1024 * 1024 { // 1MB safety limit
            eprintln!("Buffer overflow detected ({} bytes), clearing buffer", buffer.len());
            buffer.clear();
            continue;
        }

        // We want to process packets only when we have at least 163 bytes
        while buffer.len() >= 163 {
            // Extract the first 163 bytes
            let chunk = buffer.split_to(163);

            // Now parse the chunk as our PacketInfo struct (from C++)
            // We'll use byteorder to read the fields in network byte order?
            // Actually, the C++ program sent the data in host byte order?
            // We sent the struct as is, which is in the host byte order of the machine running the C++ code.
            // Since we are on the same machine (localhost), we can assume the same endianness.
            // But to be safe, we should note that the C++ program did not convert to network byte order for the fields except for the IP addresses and ports?
            // Let's check the C++ code:
            //   We did:
            //       info.src_ip = src_ip;   // which is in_addr.s_addr (network byte order)
            //       info.dst_ip = dst_ip;   // same
            //       info.src_port = src_port; // ntohs(...) -> host byte order
            //       info.dst_port = dst_port; // ntohs(...) -> host byte order
            //   So the IP addresses are in network byte order, but the ports are in host byte order.
            //   The timestamp is host byte order (from chrono).
            //   The protocol is host byte order (just a u8).
            //   The payload_len is host byte order (we set it from payload_len which is from the packet, so it's the actual length in host byte order).
            //
            // Therefore, we need to convert:
            //   src_ip and dst_ip: from network byte order to host byte order (then we can format as string)
            //   src_port and dst_port: already in host byte order (because we used ntohs in C++)
            //   payload_len: host byte order (no conversion needed)
            //
            // However, note: the C++ program sent the struct via write() which sends the raw bytes.
            // The struct in C++ has:
            //   uint64_t timestamp;
            //   uint32_t src_ip;   // network byte order
            //   uint32_t dst_ip;   // network byte order
            //   uint16_t src_port; // host byte order
            //   uint16_t dst_port; // host byte order
            //   uint8_t  protocol;
            //   uint16_t payload_len; // host byte order
            //   uint8_t  payload[MAX_PAYLOAD_SIZE];
            //
            // So when we read the raw bytes, we need to interpret:
            //   timestamp: as is (little-endian on x86)
            //   src_ip: ntohl
            //   dst_ip: ntohl
            //   src_port: as is (already host byte order from ntohs in C++)
            //   dst_port: as is
            //   protocol: as is
            //   payload_len: as is (host byte order)
            //   payload: the first `payload_len` bytes are valid.

            // Let's parse the chunk accordingly.

            // We'll use the byteorder crate? But we don't have it as a dependency.
            // We can do it manually with slices and conversion functions.

            // Since we are on a little-endian machine (most likely), and the C++ program is also running on the same machine,
            // we can assume that the host byte order is little-endian.

            // However, the IP addresses are in network byte order (big-endian). So we need to convert them from big-endian to the host's byte order.
            // But note: the in_addr.s_addr is in network byte order (big-endian). So we read the 4 bytes as a big-endian uint32_t and then convert to host.

            // Let's parse without external dependencies:

            // timestamp: 8 bytes, little-endian (we'll read as u64 from little-endian bytes)
            let timestamp = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3],
                chunk[4], chunk[5], chunk[6], chunk[7],
            ]);

            // src_ip: 4 bytes, big-endian
            let src_ip = u32::from_be_bytes([
                chunk[8], chunk[9], chunk[10], chunk[11],
            ]);

            // dst_ip: 4 bytes, big-endian
            let dst_ip = u32::from_be_bytes([
                chunk[12], chunk[13], chunk[14], chunk[15],
            ]);

            // src_port: 2 bytes, little-endian (because we stored host byte order which is little-endian on x86)
            let src_port = u16::from_le_bytes([
                chunk[16], chunk[17],
            ]);

            // dst_port: 2 bytes, little-endian
            let dst_port = u16::from_le_bytes([
                chunk[18], chunk[19],
            ]);

            // protocol: 1 byte
            let protocol = chunk[20];

            // payload_len: 2 bytes, little-endian (host byte order)
            let payload_len = u16::from_le_bytes([
                chunk[21], chunk[22],
            ]);

            // src_mac: 6 bytes
            let src_mac = mac_addr_to_string(&[
                chunk[23], chunk[24], chunk[25], chunk[26], chunk[27], chunk[28],
            ]);

            // dst_mac: 6 bytes
            let dst_mac = mac_addr_to_string(&[
                chunk[29], chunk[30], chunk[31], chunk[32], chunk[33], chunk[34],
            ]);

            // payload: next 128 bytes are sent, but only up to payload_len or the buffer max (128)
            let payload = &chunk[35..163];
            let valid_len = (payload_len as usize).min(128);
            let valid_payload = &payload[..valid_len];

            // Now convert to our DashboardPacket
            let packet = DashboardPacket {
                timestamp,
                src_ip: ip_addr_to_string(&src_ip.to_be_bytes()),
                dst_ip: ip_addr_to_string(&dst_ip.to_be_bytes()),
                src_port,
                dst_port,
                protocol: protocol_to_string(protocol),
                payload: valid_payload.to_vec(),
                src_mac,
                dst_mac,
            };

            // Send the packet to the broadcast channel
            let _ = tx.send(packet);
            PACKET_COUNT.fetch_add(1, Ordering::SeqCst);
        }
    }

    Ok(())
}

// Handle a connection from the Go program
async fn handle_go_connection(mut socket: TokioTcpStream, tx: Arc<Sender<DashboardPacket>>) -> io::Result<()> {
    // We want to send JSON lines of DashboardPacket to the Go program.
    // We'll subscribe to the broadcast channel and send each packet as a JSON line.

    let mut rx = tx.subscribe();
    loop {
        // Wait for a packet from the broadcast channel
        let packet = match rx.recv().await {
            Ok(pkt) => pkt,
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                eprintln!("Go client lagged, skipped {} packets", skipped);
                continue;
            }
            Err(e) => {
                eprintln!("Error receiving from broadcast channel: {}", e);
                break;
            }
        };

        // Serialize the packet to JSON
        let json = match serde_json::to_string(&packet) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("Error serializing packet to JSON: {}", e);
                continue;
            }
        };

        // Send the JSON line followed by a newline
        let line = format!("{}\n", json);
        if let Err(e) = socket.write_all(line.as_bytes()).await {
            println!("Go dashboard disconnected: {}", e);
            break;
        }
        // We don't flush here because we are writing in chunks and the TCP stack will buffer.
        // But we can flush if we want to ensure immediate delivery.
        // However, for performance, we'll let the OS handle it.
    }

    Ok(())
}