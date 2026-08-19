use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use maskman_config::CompiledLimits;
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle};

use crate::datagram;

const INGRESS_QUEUE: usize = 64;
const EGRESS_QUEUE: usize = 64;

#[derive(Clone)]
pub struct UdpSessionHandle {
    ingress: mpsc::Sender<Bytes>,
    limiter: Arc<Mutex<TokenBucket>>,
}

impl UdpSessionHandle {
    pub fn try_send(&self, payload: Bytes) -> bool {
        if !self
            .limiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .allow(payload.len())
        {
            return false;
        }
        self.ingress.try_send(payload).is_ok()
    }
}

pub struct UdpSession {
    pub handle: UdpSessionHandle,
    pub egress: mpsc::Receiver<Bytes>,
    pub task: JoinHandle<()>,
}

pub async fn start(
    target: std::net::SocketAddr,
    stream_id: u64,
    connection: quinn::Connection,
    max_payload: usize,
    idle_timeout: Duration,
    limits: CompiledLimits,
) -> Result<UdpSession, std::io::Error> {
    let socket = UdpSocket::bind(if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).await?;
    socket.connect(target).await?;
    let socket = Arc::new(socket);
    let (ingress_tx, mut ingress_rx) = mpsc::channel::<Bytes>(INGRESS_QUEUE);
    let (egress_tx, egress_rx) = mpsc::channel::<Bytes>(EGRESS_QUEUE);
    let ingress_limiter =
        Arc::new(Mutex::new(TokenBucket::new(limits.ingress_bytes_per_second, limits.burst_bytes)));
    let egress_limiter = TokenBucket::new(limits.egress_bytes_per_second, limits.burst_bytes);
    let task = tokio::spawn(async move {
        let mut buffer = vec![0u8; max_payload];
        let mut egress_limiter = egress_limiter;
        loop {
            tokio::select! {
                ingress = ingress_rx.recv() => match ingress {
                    Some(payload) => {
                        let _ = socket.send(&payload).await;
                    }
                    None => break,
                },
                result = tokio::time::timeout(idle_timeout, socket.recv(&mut buffer)) => match result {
                    Ok(Ok(length)) => send_to_client(
                        &connection,
                        stream_id,
                        &buffer[..length],
                        &egress_tx,
                        &mut egress_limiter,
                    ),
                    Ok(Err(_)) | Err(_) => break,
                },
            }
        }
    });
    Ok(UdpSession {
        handle: UdpSessionHandle { ingress: ingress_tx, limiter: ingress_limiter },
        egress: egress_rx,
        task,
    })
}

fn send_to_client(
    connection: &quinn::Connection,
    stream_id: u64,
    payload: &[u8],
    fallback: &mpsc::Sender<Bytes>,
    limiter: &mut TokenBucket,
) {
    if !limiter.allow(payload.len()) {
        return;
    }
    let mut http_payload = Vec::with_capacity(payload.len() + 1);
    if maskman_protocol::capsule::encode_datagram(0, payload, &mut http_payload).is_err() {
        return;
    }
    let http_payload = Bytes::from(http_payload);
    let Ok(encoded) = datagram::encode(stream_id, http_payload.clone()) else {
        return;
    };
    match connection.send_datagram(encoded) {
        Ok(()) | Err(quinn::SendDatagramError::TooLarge) => {}
        Err(quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled) => {
            let _ = fallback.try_send(http_payload);
        }
        Err(quinn::SendDatagramError::ConnectionLost(_)) => {}
    }
}

struct TokenBucket {
    tokens: u64,
    rate: u64,
    burst: u64,
    last: std::time::Instant,
}

impl TokenBucket {
    fn new(rate: u64, burst: u64) -> Self {
        Self { tokens: burst, rate, burst, last: std::time::Instant::now() }
    }

    fn allow(&mut self, amount: usize) -> bool {
        let elapsed = self.last.elapsed();
        let nanos = elapsed.as_nanos().min(u128::from(u64::MAX)) as u64;
        let replenished = (u128::from(self.rate) * u128::from(nanos) / 1_000_000_000) as u64;
        self.tokens = self.tokens.saturating_add(replenished).min(self.burst);
        self.last = std::time::Instant::now();
        let amount = amount as u64;
        if self.tokens < amount {
            return false;
        }
        self.tokens -= amount;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::TokenBucket;

    #[test]
    fn token_bucket_bounds_burst_and_refills() {
        let mut bucket = TokenBucket::new(10, 4);
        assert!(bucket.allow(4));
        assert!(!bucket.allow(1));
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(bucket.allow(1));
        assert!(!bucket.allow(4));
    }
}
