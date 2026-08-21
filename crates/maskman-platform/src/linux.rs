use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};

use futures_util::TryStreamExt;
use ipnet::IpNet;
use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkInfo};
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
        self.add_route_inner(route, interface_index, journal, None).await
    }

    pub async fn add_route_persisted(
        &self,
        route: IpNet,
        interface_index: u32,
        journal: &mut NetworkJournal,
        journal_path: &Path,
    ) -> Result<(), PlatformError> {
        self.add_route_inner(route, interface_index, journal, Some(journal_path)).await
    }

    async fn add_route_inner(
        &self,
        route: IpNet,
        interface_index: u32,
        journal: &mut NetworkJournal,
        journal_path: Option<&Path>,
    ) -> Result<(), PlatformError> {
        let pending =
            JournalEntry::RoutePending { destination: route.to_string(), interface_index };
        if let Some(path) = journal_path {
            journal.prepare(pending.clone(), path)?;
        }
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
        let active = JournalEntry::Route { destination: route.to_string(), interface_index };
        if let Some(path) = journal_path {
            journal.promote_last(pending, active, path)?;
        } else {
            journal.record(active);
        }
        Ok(())
    }

    pub async fn remove_route(
        &self,
        route: IpNet,
        interface_index: u32,
    ) -> Result<(), PlatformError> {
        ensure_owned_interface(&self.handle, interface_index).await?;
        match route {
            IpNet::V4(route) => {
                let message = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(route.network(), route.prefix_len())
                    .output_interface(interface_index)
                    .build();
                self.handle.route().del(message).execute().await.or_else(ignore_missing_route)?;
            }
            IpNet::V6(route) => {
                let message = RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(route.network(), route.prefix_len())
                    .output_interface(interface_index)
                    .build();
                self.handle.route().del(message).execute().await.or_else(ignore_missing_route)?;
            }
        }
        Ok(())
    }

    pub async fn remove_tun(name: &str) -> Result<(), PlatformError> {
        let (connection, handle, _) =
            new_connection().map_err(|error| PlatformError::Network(error.to_string()))?;
        let connection = tokio::spawn(connection);
        let result = remove_owned_tun(&handle, name).await;
        connection.abort();
        result
    }
}

fn ignore_missing_route(error: rtnetlink::Error) -> Result<(), PlatformError> {
    let missing = matches!(
        &error,
        rtnetlink::Error::NetlinkError(message)
            if message.code.is_some_and(|code| matches!(code.get(), -2 | -3))
    );
    if missing {
        Ok(())
    } else {
        Err(PlatformError::Network(error.to_string()))
    }
}

async fn remove_owned_tun(handle: &Handle, name: &str) -> Result<(), PlatformError> {
    let mut links = handle.link().get().match_name(name).execute();
    let Some(link) =
        links.try_next().await.map_err(|error| PlatformError::Network(error.to_string()))?
    else {
        return Ok(());
    };

    let is_tun = link.attributes.iter().any(|attribute| {
        matches!(
            attribute,
            LinkAttribute::LinkInfo(infos)
                if infos.iter().any(|info| matches!(info, LinkInfo::Kind(InfoKind::Tun)))
        )
    });
    if !is_tun {
        return Err(PlatformError::UnsupportedCleanup(format!(
            "interface {name} is not a tun device"
        )));
    }

    handle
        .link()
        .del(link.header.index)
        .execute()
        .await
        .map_err(|error| PlatformError::Network(error.to_string()))
}

async fn ensure_owned_interface(handle: &Handle, index: u32) -> Result<(), PlatformError> {
    let mut links = handle.link().get().match_index(index).execute();
    let Some(link) =
        links.try_next().await.map_err(|error| PlatformError::Network(error.to_string()))?
    else {
        // A route attached to a deleted link is removed by the kernel with
        // the link. Treat that state as already cleaned; only an existing
        // foreign link is a hard ownership failure.
        return Ok(());
    };
    let is_owned = link.attributes.iter().any(
        |attribute| matches!(attribute, LinkAttribute::IfName(name) if name.starts_with("maskman")),
    ) && link.attributes.iter().any(|attribute| {
        matches!(
            attribute,
            LinkAttribute::LinkInfo(infos)
                if infos.iter().any(|info| matches!(info, LinkInfo::Kind(InfoKind::Tun)))
        )
    });
    if is_owned {
        Ok(())
    } else {
        Err(PlatformError::UnsupportedCleanup(format!(
            "interface index {index} is not an owned Maskman TUN"
        )))
    }
}

impl Drop for LinuxRouteManager {
    fn drop(&mut self) {
        self.connection.abort();
    }
}
