mod model;
mod handlers;

use std::net::{SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::{TcpSocket};
use tokio::sync::broadcast::{self, Sender};
use tokio_rustls::rustls::{self, pki_types::{CertificateDer, PrivateKeyDer}};
use tokio_rustls::TlsAcceptor;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::fs::File;
use std::io::BufReader;
use crate::model::DashboardPacket;
use crate::handlers::{handle_cpp_connection, handle_go_connection};

pub const SHARED_SECRET: &[u8] = b"pacsni_secure_shared_secret_123";
pub const STRUCT_SIZE: usize = 1024;
pub const HASH_SIZE: usize = 64;
pub const TOTAL_MSG_SIZE: usize = STRUCT_SIZE + HASH_SIZE;
pub static PACKET_COUNT: AtomicUsize = AtomicUsize::new(0);

fn load_certs(path: &str) -> Vec<CertificateDer<'static>> {
    let mut reader = BufReader::new(File::open(path).expect("cannot open cert file"));
    rustls_pemfile::certs(&mut reader)
        .map(|result| result.expect("invalid cert"))
        .collect()
}

fn load_key(path: &str) -> PrivateKeyDer<'static> {
    let mut reader = BufReader::new(File::open(path).expect("cannot open key file"));
    if let Some(Ok(key)) = rustls_pemfile::pkcs8_private_keys(&mut reader).next() { return key.into(); }
    let mut reader = BufReader::new(File::open(path).expect("cannot reopen key file"));
    if let Some(Ok(key)) = rustls_pemfile::rsa_private_keys(&mut reader).next() { return key.into(); }
    panic!("No valid private key found in {}. Ensure it is PKCS#8 or RSA format.", path);
}

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
            } else {
                print!("METRICS: Heartbeat - Service Idle\r\n");
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