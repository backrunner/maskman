use std::sync::Arc;

use bytes::Bytes;
use maskman_platform::TunDevice;
use tokio::sync::mpsc;

use crate::transport::TransportContext;

pub async fn run(
    device: TunDevice,
    context: Arc<TransportContext>,
    mut outbound: mpsc::Receiver<Bytes>,
) -> Result<(), maskman_platform::PlatformError> {
    let mut packet = vec![0u8; 65_535];
    loop {
        tokio::select! {
            result = device.recv(&mut packet) => {
                let length = result?;
                let _ = context.dispatch_tun_packet(Bytes::copy_from_slice(&packet[..length]));
            }
            packet = outbound.recv() => match packet {
                Some(packet) => {
                    device.send(&packet).await?;
                }
                None => return Ok(()),
            }
        }
    }
}
