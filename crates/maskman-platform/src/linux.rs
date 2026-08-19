use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use rtnetlink::{new_connection, Handle, RouteMessageBuilder};
use tokio::task::JoinHandle;

use crate::{JournalEntry, NetworkJournal, PlatformError};

pub struct LinuxRouteManager {
    handle: Handle,
    connection: JoinHandle<()>,
}

impl LinuxRouteManager {
    pub fn connect() -> Result<Self, PlatformError> {
        let (connection, handle, _) =
            new_connection().map_err(|error| PlatformError::Network(error.to_string()))?;
        let connection = tokio::spawn(connection);
        Ok(Self { handle, connection })
    }

    pub async fn add_route(
        &self,
        route: IpNet,
        interface_index: u32,
        journal: &mut NetworkJournal,
    ) -> Result<(), PlatformError> {
        match route {
            IpNet::V4(route) => {
                let message = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(route.network(), route.prefix_len())
                    .output_interface(interface_index)
                    .build();
                self.handle
                    .route()
                    .add(message)
                    .execute()
                    .await
                    .map_err(|error| PlatformError::Network(error.to_string()))?;
            }
            IpNet::V6(route) => {
                let message = RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(route.network(), route.prefix_len())
                    .output_interface(interface_index)
                    .build();
                self.handle
                    .route()
                    .add(message)
                    .execute()
                    .await
                    .map_err(|error| PlatformError::Network(error.to_string()))?;
            }
        }
        journal.record(JournalEntry::Route { destination: route.to_string(), interface_index });
        Ok(())
    }

    pub async fn remove_route(
        &self,
        route: IpNet,
        interface_index: u32,
    ) -> Result<(), PlatformError> {
        match route {
            IpNet::V4(route) => {
                let message = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(route.network(), route.prefix_len())
                    .output_interface(interface_index)
                    .build();
                self.handle
                    .route()
                    .del(message)
                    .execute()
                    .await
                    .map_err(|error| PlatformError::Network(error.to_string()))?;
            }
            IpNet::V6(route) => {
                let message = RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(route.network(), route.prefix_len())
                    .output_interface(interface_index)
                    .build();
                self.handle
                    .route()
                    .del(message)
                    .execute()
                    .await
                    .map_err(|error| PlatformError::Network(error.to_string()))?;
            }
        }
        Ok(())
    }
}

impl Drop for LinuxRouteManager {
    fn drop(&mut self) {
        self.connection.abort();
    }
}
