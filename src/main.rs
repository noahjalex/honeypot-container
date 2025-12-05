use chrono::Utc;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::fs::{create_dir_all, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};

const MAX_PAYLOAD_SIZE: usize = 65536; // 64KB
const CONNECTION_TIMEOUT: u64 = 300; // 5 minutes
const DISK_CHECK_INTERVAL: u64 = 30; // Check disk every 30 seconds

#[derive(Debug, Serialize)]
struct ConnectionLog {
    timestamp: String,
    connection_id: u64,
    remote_ip: String,
    remote_port: u16,
    local_port: u16,
    protocol: String,
}

#[derive(Debug, Serialize)]
struct PayloadLog {
    timestamp: String,
    connection_id: u64,
    direction: String,
    size: usize,
    data_hex: String,
    data_ascii: String,
}

#[derive(Debug, Serialize)]
struct SessionLog {
    timestamp: String,
    connection_id: u64,
    duration_seconds: f64,
    bytes_received: usize,
    bytes_sent: usize,
}

#[derive(Debug, Clone)]
struct Config {
    listen_host: String,
    listen_port: u16,
    log_dir: PathBuf,
    max_payload_size: usize,
    connection_timeout: u64,
    max_log_size_mb: u64,
}

impl Config {
    fn from_env() -> Self {
        Self {
            listen_host: std::env::var("HONEYPOT_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            listen_port: std::env::var("HONEYPOT_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30012),
            log_dir: std::env::var("LOG_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/logs")),
            max_payload_size: std::env::var("MAX_PAYLOAD_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(MAX_PAYLOAD_SIZE),
            connection_timeout: std::env::var("CONNECTION_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(CONNECTION_TIMEOUT),
            max_log_size_mb: std::env::var("MAX_LOG_SIZE_MB")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000), // Default 1GB
        }
    }
}

struct ConnectionLogger {
    log_dir: PathBuf,
    connection_count: Arc<AtomicU64>,
}

impl ConnectionLogger {
    fn new(log_dir: PathBuf) -> Self {
        Self {
            log_dir,
            connection_count: Arc::new(AtomicU64::new(0)),
        }
    }

    async fn init_dirs(&self) -> std::io::Result<()> {
        create_dir_all(&self.log_dir).await?;
        create_dir_all(self.log_dir.join("connections")).await?;
        create_dir_all(self.log_dir.join("payloads")).await?;
        create_dir_all(self.log_dir.join("sessions")).await?;
        Ok(())
    }

    async fn log_connection(
        &self,
        remote_addr: SocketAddr,
        local_port: u16,
    ) -> std::io::Result<u64> {
        let connection_id = self.connection_count.fetch_add(1, Ordering::SeqCst) + 1;
        let timestamp = Utc::now().to_rfc3339();

        let log = ConnectionLog {
            timestamp,
            connection_id,
            remote_ip: remote_addr.ip().to_string(),
            remote_port: remote_addr.port(),
            local_port,
            protocol: "TCP".to_string(),
        };

        let date_str = Utc::now().format("%Y%m%d").to_string();
        let log_file = self
            .log_dir
            .join("connections")
            .join(format!("{}.jsonl", date_str));

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
            .await?;

        let json = serde_json::to_string(&log).unwrap();
        file.write_all(format!("{}\n", json).as_bytes()).await?;

        info!(
            "Connection #{} from {}:{}",
            connection_id,
            remote_addr.ip(),
            remote_addr.port()
        );

        Ok(connection_id)
    }

    async fn log_data(
        &self,
        connection_id: u64,
        data: &[u8],
        direction: &str,
    ) -> std::io::Result<()> {
        let timestamp = Utc::now().to_rfc3339();
        let data_ascii: String = data
            .iter()
            .map(|&b| {
                if (32..127).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();

        let log = PayloadLog {
            timestamp,
            connection_id,
            direction: direction.to_string(),
            size: data.len(),
            data_hex: hex::encode(data),
            data_ascii,
        };

        let date_str = Utc::now().format("%Y%m%d").to_string();
        let log_file = self
            .log_dir
            .join("payloads")
            .join(format!("{}.jsonl", date_str));

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
            .await?;

        let json = serde_json::to_string(&log).unwrap();
        file.write_all(format!("{}\n", json).as_bytes()).await?;

        Ok(())
    }

    async fn log_session_end(
        &self,
        connection_id: u64,
        duration: f64,
        bytes_received: usize,
        bytes_sent: usize,
    ) -> std::io::Result<()> {
        let timestamp = Utc::now().to_rfc3339();

        let log = SessionLog {
            timestamp,
            connection_id,
            duration_seconds: duration,
            bytes_received,
            bytes_sent,
        };

        let date_str = Utc::now().format("%Y%m%d").to_string();
        let log_file = self
            .log_dir
            .join("sessions")
            .join(format!("{}.jsonl", date_str));

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
            .await?;

        let json = serde_json::to_string(&log).unwrap();
        file.write_all(format!("{}\n", json).as_bytes()).await?;

        info!(
            "Connection #{} ended: {:.2}s, RX: {}, TX: {}",
            connection_id, duration, bytes_received, bytes_sent
        );

        Ok(())
    }
}

/// Calculate total size of log directory in bytes
fn get_log_directory_size(
    log_dir: PathBuf,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<u64>> + Send>> {
    Box::pin(async move {
        let mut total_size = 0u64;

        let mut read_dir = tokio::fs::read_dir(&log_dir).await?;
        while let Some(entry) = read_dir.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_file() {
                total_size += metadata.len();
            } else if metadata.is_dir() {
                // Recursively check subdirectories
                if let Ok(subdir_size) = get_log_directory_size(entry.path()).await {
                    total_size += subdir_size;
                }
            }
        }

        Ok(total_size)
    })
}

/// Check if we should accept new connections based on disk usage
async fn should_accept_connections(log_dir: &PathBuf, config: &Config) -> bool {
    // Check log directory size
    match get_log_directory_size(log_dir.clone()).await {
        Ok(size_bytes) => {
            let size_mb = size_bytes / (1024 * 1024);
            if size_mb >= config.max_log_size_mb {
                warn!(
                    "Log directory size ({} MB) exceeds limit ({} MB). Rejecting new connections.",
                    size_mb, config.max_log_size_mb
                );
                return false;
            }
        }
        Err(e) => {
            error!("Failed to check log directory size: {}", e);
            // On error reject connections
            return false;
        }
    }

    true
}

async fn send_banner(stream: &mut TcpStream) -> std::io::Result<usize> {
    // Send SSH banner as default
    let banner = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n";
    stream.write_all(banner).await?;
    Ok(banner.len())
}

async fn analyze_and_respond(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<usize> {
    let decoded = String::from_utf8_lossy(data);
    let trimmed = decoded.trim();

    let response = if trimmed.starts_with("GET ")
        || trimmed.starts_with("POST ")
        || trimmed.starts_with("HEAD ")
        || trimmed.starts_with("PUT ")
        || trimmed.starts_with("DELETE ")
        || trimmed.starts_with("OPTIONS ")
    {
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!".as_slice()
    } else if data.starts_with(b"SSH-") {
        b"SSH-2.0-OpenSSH_8.2p1\r\n".as_slice()
    } else if matches!(
        trimmed.to_lowercase().as_str(),
        "help" | "ls" | "dir" | "pwd" | "whoami"
    ) {
        b"Command not found\r\n$ ".as_slice()
    } else if trimmed.to_uppercase().starts_with("HELO")
        || trimmed.to_uppercase().starts_with("EHLO")
        || trimmed.to_uppercase().starts_with("MAIL FROM")
        || trimmed.to_uppercase().starts_with("RCPT TO")
    {
        b"250 OK\r\n".as_slice()
    } else if trimmed.to_uppercase().starts_with("USER")
        || trimmed.to_uppercase().starts_with("PASS")
    {
        b"230 Login successful\r\n".as_slice()
    } else {
        // Generic prompt
        tokio::time::sleep(Duration::from_millis(500)).await;
        b"$ ".as_slice()
    };

    stream.write_all(response).await?;
    Ok(response.len())
}

async fn handle_connection(
    mut stream: TcpStream,
    remote_addr: SocketAddr,
    local_port: u16,
    logger: Arc<ConnectionLogger>,
    config: Config,
) {
    let start_time = std::time::Instant::now();
    let mut bytes_received = 0;
    let mut bytes_sent = 0;

    let connection_id = match logger.log_connection(remote_addr, local_port).await {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to log connection: {}", e);
            return;
        }
    };

    // Send initial banner
    match send_banner(&mut stream).await {
        Ok(n) => {
            bytes_sent += n;
            if let Err(e) = logger
                .log_data(
                    connection_id,
                    &b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"[..],
                    "outbound",
                )
                .await
            {
                error!("Failed to log banner: {}", e);
            }
        }
        Err(e) => {
            error!("Failed to send banner: {}", e);
            return;
        }
    }

    let mut buffer = vec![0u8; 4096];

    loop {
        let read_result = timeout(
            Duration::from_secs(config.connection_timeout),
            stream.read(&mut buffer),
        )
        .await;

        match read_result {
            Ok(Ok(0)) => {
                // Connection closed
                break;
            }
            Ok(Ok(n)) => {
                bytes_received += n;

                if let Err(e) = logger
                    .log_data(connection_id, &buffer[..n], "inbound")
                    .await
                {
                    error!("Failed to log inbound data: {}", e);
                }

                // Respond to the data
                match analyze_and_respond(&mut stream, &buffer[..n]).await {
                    Ok(sent) => {
                        bytes_sent += sent;
                        if let Err(e) = logger
                            .log_data(connection_id, &buffer[..sent], "outbound")
                            .await
                        {
                            error!("Failed to log outbound data: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to send response: {}", e);
                        break;
                    }
                }

                // Check payload size limit
                if bytes_received > config.max_payload_size {
                    warn!("Connection #{} exceeded max payload size", connection_id);
                    break;
                }
            }
            Ok(Err(e)) => {
                error!("Read error: {}", e);
                break;
            }
            Err(_) => {
                warn!("Connection #{} timed out", connection_id);
                break;
            }
        }
    }

    let duration = start_time.elapsed().as_secs_f64();
    if let Err(e) = logger
        .log_session_end(connection_id, duration, bytes_received, bytes_sent)
        .await
    {
        error!("Failed to log session end: {}", e);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_level(true)
        .init();

    let config = Config::from_env();

    info!("Starting Honeypot Server v{}", env!("CARGO_PKG_VERSION"));
    info!(
        "Configuration: Host={}, Port={}",
        config.listen_host, config.listen_port
    );
    info!("Log directory: {:?}", config.log_dir);

    let logger = Arc::new(ConnectionLogger::new(config.log_dir.clone()));

    // Initialize log directories
    if let Err(e) = logger.init_dirs().await {
        error!("Failed to create log directories: {}", e);
        return Err(e.into());
    }

    let addr = format!("{}:{}", config.listen_host, config.listen_port);
    let listener = TcpListener::bind(&addr).await?;

    info!("Honeypot listening on {}", addr);
    info!("Disk limits: Max log size = {} MB", config.max_log_size_mb);

    // Shared flag to control whether we're accepting connections
    let accepting_connections = Arc::new(AtomicBool::new(true));

    // Spawn background task to monitor disk usage
    let disk_monitor_handle = tokio::spawn({
        let log_dir = config.log_dir.clone();
        let config = config.clone();
        let accepting = Arc::clone(&accepting_connections);
        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(DISK_CHECK_INTERVAL));
            loop {
                interval.tick().await;

                let should_accept = should_accept_connections(&log_dir, &config).await;
                let was_accepting = accepting.swap(should_accept, Ordering::SeqCst);

                if should_accept && !was_accepting {
                    info!("Disk usage OK. Resuming connection acceptance.");
                } else if !should_accept && was_accepting {
                    warn!("Disk limit reached. Pausing connection acceptance.");
                }
            }
        }
    });

    // Spawn task to handle connections
    let server_handle = tokio::spawn({
        let logger = Arc::clone(&logger);
        let config = config.clone();
        let accepting = Arc::clone(&accepting_connections);
        async move {
            loop {
                match listener.accept().await {
                    Ok((stream, remote_addr)) => {
                        // Check if we should accept this connection
                        if !accepting.load(Ordering::SeqCst) {
                            warn!(
                                "Rejecting connection from {}:{} due to disk limits",
                                remote_addr.ip(),
                                remote_addr.port()
                            );
                            // Immediately drop the stream to close the connection
                            drop(stream);
                            continue;
                        }

                        let logger = Arc::clone(&logger);
                        let config = config.clone();
                        let local_port = config.listen_port;

                        tokio::spawn(async move {
                            handle_connection(stream, remote_addr, local_port, logger, config)
                                .await;
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        }
    });

    // Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Received shutdown signal, stopping server...");
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
        }
    }

    server_handle.abort();
    disk_monitor_handle.abort();
    info!("Honeypot server stopped");

    Ok(())
}
