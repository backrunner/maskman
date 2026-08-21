use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinHandle,
};

use crate::stats::{RuntimeSnapshot, RuntimeStats};

const MAX_REQUEST_BYTES: usize = 4 * 1024;
const MAX_CLIENTS: usize = 8;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct MetricsHandle {
    task: JoinHandle<()>,
    #[cfg(test)]
    address: SocketAddr,
}

pub(crate) async fn start(
    address: SocketAddr,
    stats: Arc<RuntimeStats>,
) -> Result<MetricsHandle, std::io::Error> {
    let listener = TcpListener::bind(address).await?;
    #[cfg(test)]
    let address = listener.local_addr()?;
    let task = tokio::spawn(run(listener, stats));
    Ok(MetricsHandle {
        task,
        #[cfg(test)]
        address,
    })
}

impl MetricsHandle {
    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.address
    }

    pub(crate) async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn run(listener: TcpListener, stats: Arc<RuntimeStats>) {
    let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            return;
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let stats = stats.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(CLIENT_TIMEOUT, serve(stream, &stats)).await;
        });
    }
}

async fn serve(mut stream: TcpStream, stats: &RuntimeStats) -> Result<(), std::io::Error> {
    let mut request = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    let mut complete = false;
    while request.len() < MAX_REQUEST_BYTES {
        let length = stream.read(&mut chunk).await?;
        if length == 0 {
            break;
        }
        let remaining = MAX_REQUEST_BYTES - request.len();
        request.extend_from_slice(&chunk[..length.min(remaining)]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            complete = true;
            break;
        }
    }
    let (status, body) = if !complete && request.len() >= MAX_REQUEST_BYTES {
        ("431 Request Header Fields Too Large", "# request too large\n".to_owned())
    } else if request.starts_with(b"GET /metrics HTTP/1.1")
        || request.starts_with(b"GET /metrics HTTP/1.0")
    {
        ("200 OK", render(stats.snapshot()))
    } else if request.starts_with(b"GET ") {
        ("404 Not Found", "# no such metrics path\n".to_owned())
    } else {
        ("405 Method Not Allowed", "# GET required\n".to_owned())
    };
    let header = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await
}

fn render(snapshot: RuntimeSnapshot) -> String {
    let mut output = String::with_capacity(768);
    metric(&mut output, "maskman_uptime_seconds", snapshot.uptime_seconds);
    metric(&mut output, "maskman_active_connections", snapshot.active_connections);
    metric(&mut output, "maskman_accepted_connections", snapshot.accepted_connections);
    metric(&mut output, "maskman_active_udp_sessions", snapshot.active_udp_sessions);
    metric(&mut output, "maskman_active_ip_sessions", snapshot.active_ip_sessions);
    metric(&mut output, "maskman_forwarded_packets_total", snapshot.forwarded_packets);
    metric(&mut output, "maskman_dropped_packets_total", snapshot.dropped_packets);
    output
}

fn metric(output: &mut String, name: &str, value: u64) {
    output.push_str(name);
    output.push(' ');
    output.push_str(&value.to_string());
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    use super::{render, start};
    use crate::stats::{ActivityKind, RuntimeStats};

    #[test]
    fn render_uses_stable_metric_names_without_sensitive_labels() {
        let stats = Arc::new(RuntimeStats::new());
        let _connection = stats.begin(ActivityKind::Connection);
        stats.packet_result(true);
        let body = render(stats.snapshot());
        assert!(body.contains("maskman_active_connections 1\n"));
        assert!(body.contains("maskman_forwarded_packets_total 1\n"));
        assert!(!body.contains("principal"));
    }

    #[tokio::test]
    async fn endpoint_serves_metrics_and_rejects_other_paths() {
        let stats = Arc::new(RuntimeStats::new());
        let handle =
            start("127.0.0.1:0".parse().unwrap_or_else(|error| panic!("addr: {error}")), stats)
                .await
                .unwrap_or_else(|error| panic!("start metrics: {error}"));
        let address = handle.local_addr();
        let mut stream = TcpStream::connect(address)
            .await
            .unwrap_or_else(|error| panic!("connect metrics: {error}"));
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap_or_else(|error| panic!("write metrics request: {error}"));
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .unwrap_or_else(|error| panic!("read metrics response: {error}"));
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response
            .windows(b"maskman_uptime_seconds".len())
            .any(|window| window == b"maskman_uptime_seconds"));
        handle.stop().await;
    }
}
