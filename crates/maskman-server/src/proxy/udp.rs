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
const VIOLATION_QUEUE: usize = 1;
const MAX_UDP_PAYLOAD_BYTES: usize = 65_527;

#[derive(Clone)]
pub struct UdpSessionHandle {
    ingress: mpsc::Sender<Bytes>,
    limiter: Arc<Mutex<TokenBucket>>,
    max_payload: usize,
    violations: mpsc::Sender<usize>,
}

impl UdpSessionHandle {
    pub fn try_send(&self, payload: Bytes) -> bool {
        if payload.len() > MAX_UDP_PAYLOAD_BYTES {
            let _ = self.violations.try_send(payload.len());
            return false;
        }
        if payload.len() > self.max_payload {
            return false;
        }
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
    pub violations: mpsc::Receiver<usize>,
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
    let (violation_tx, violation_rx) = mpsc::channel(VIOLATION_QUEUE);
    let ingress_limiter =
        Arc::new(Mutex::new(TokenBucket::new(limits.ingress_bytes_per_second, limits.burst_bytes)));
    let egress_limiter = TokenBucket::new(limits.egress_bytes_per_second, limits.burst_bytes);
    let task = tokio::spawn(async move {
        let mut buffer = vec![0u8; max_payload];
        let mut egress_limiter = egress_limiter;
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                ingress = ingress_rx.recv() => match ingress {
                    Some(payload) => {
                        if socket.send(&payload).await.is_err() {
                            break;
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                    }
                    None => break,
                },
                result = socket.recv(&mut buffer) => match result {
                    Ok(length) => {
                        send_to_client(
                            &connection,
                            stream_id,
                            &buffer[..length],
                            &egress_tx,
                            &mut egress_limiter,
                        );
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                    }
                    Err(_) => break,
                },
                () = &mut idle => break,
            }
        }
    });
    Ok(UdpSession {
        handle: UdpSessionHandle {
            ingress: ingress_tx,
            limiter: ingress_limiter,
            max_payload,
            violations: violation_tx,
        },
        egress: egress_rx,
        violations: violation_rx,
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
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use tokio::sync::mpsc;

    use super::{TokenBucket, UdpSessionHandle, MAX_UDP_PAYLOAD_BYTES};

    #[test]
    fn token_bucket_bounds_burst_and_refills() {
        let mut bucket = TokenBucket::new(10, 4);
        assert!(bucket.allow(4));
        assert!(!bucket.allow(1));
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(bucket.allow(1));
        assert!(!bucket.allow(4));
    }

    #[tokio::test]
    async fn session_enforces_configured_and_protocol_payload_limits() {
        let (ingress, mut ingress_rx) = mpsc::channel(1);
        let (violation_tx, mut violation_rx) = mpsc::channel(1);
        let handle = UdpSessionHandle {
            ingress,
            limiter: Arc::new(Mutex::new(TokenBucket::new(u64::MAX, u64::MAX))),
            max_payload: 4,
            violations: violation_tx,
        };

        assert!(!handle.try_send(Bytes::from_static(b"12345")));
        assert!(ingress_rx.try_recv().is_err());
        assert!(violation_rx.try_recv().is_err());

        assert!(!handle.try_send(Bytes::from(vec![0; MAX_UDP_PAYLOAD_BYTES + 1])));
        assert_eq!(violation_rx.recv().await, Some(MAX_UDP_PAYLOAD_BYTES + 1));
    }
}
