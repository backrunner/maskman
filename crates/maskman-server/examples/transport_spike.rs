use std::{net::SocketAddr, path::PathBuf, time::Duration};

use maskman_server::{server_config, TransportLimits, TransportMode, TransportServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let address: SocketAddr = arguments
        .next()
        .ok_or("usage: transport_spike <address> <certificate.pem> <private-key.pem>")?
        .into_string()
        .map_err(|_| "address must be valid UTF-8")?
        .parse()?;
    let certificate_file = PathBuf::from(arguments.next().ok_or("missing certificate path")?);
    let private_key_file = PathBuf::from(arguments.next().ok_or("missing private key path")?);
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }

    let server = TransportServer::bind(
        address,
        server_config(&certificate_file, &private_key_file)?,
        TransportLimits {
            max_connections: 16,
            max_requests_per_connection: 16,
            max_header_bytes: 16_384,
            idle_timeout: Duration::from_secs(120),
            drain_timeout: Duration::from_secs(5),
        },
        TransportMode::EchoDatagrams,
    )?;
    println!("transport spike listening on {}", server.local_addr()?);
    server.run().await?;
    Ok(())
}
