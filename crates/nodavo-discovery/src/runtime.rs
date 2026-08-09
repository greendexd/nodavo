use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use mdns_sd::{ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::{DiscoveryError, DiscoveryLocation, DiscoveryRecord};

pub const SERVICE_TYPE: &str = "_nodavo._udp.local.";

pub struct MdnsRuntime {
    daemon: ServiceDaemon,
    registered_fullname: Option<String>,
}

impl MdnsRuntime {
    /// Starts the local mDNS daemon.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::RuntimeUnavailable`] when the platform mDNS
    /// runtime cannot be created.
    pub fn new() -> Result<Self, DiscoveryError> {
        Ok(Self {
            daemon: ServiceDaemon::new().map_err(|_| DiscoveryError::RuntimeUnavailable)?,
            registered_fullname: None,
        })
    }

    /// Publishes one bounded location/bootstrap record.
    ///
    /// # Errors
    ///
    /// Rejects duplicate registration, invalid host names, and mDNS backend failures.
    pub fn advertise(
        &mut self,
        record: &DiscoveryRecord,
        host_name: &str,
    ) -> Result<(), DiscoveryError> {
        if self.registered_fullname.is_some()
            || host_name.is_empty()
            || !host_name.ends_with(".local.")
        {
            return Err(DiscoveryError::RuntimeUnavailable);
        }
        let properties = record
            .txt_fields()
            .into_iter()
            .filter_map(|field| {
                let (key, value) = field.split_once('=')?;
                Some((key.to_owned(), value.to_owned()))
            })
            .collect::<HashMap<_, _>>();
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            record.instance_name(),
            host_name,
            "",
            record.port(),
            properties,
        )
        .map_err(|_| DiscoveryError::RuntimeUnavailable)?
        .enable_addr_auto();
        let fullname = service.get_fullname().to_owned();
        self.daemon
            .register(service)
            .map_err(|_| DiscoveryError::RuntimeUnavailable)?;
        self.registered_fullname = Some(fullname);
        Ok(())
    }

    /// Starts a bounded discovery event stream.
    ///
    /// # Errors
    ///
    /// Returns an error when browsing or its worker thread cannot be started.
    pub fn browse(&self) -> Result<MdnsBrowser, DiscoveryError> {
        let source = self
            .daemon
            .browse(SERVICE_TYPE)
            .map_err(|_| DiscoveryError::RuntimeUnavailable)?;
        let (sender, receiver) = mpsc::sync_channel(32);
        let worker = thread::Builder::new()
            .name("nodavo-mdns-browser".to_owned())
            .spawn(move || {
                while let Ok(event) = source.recv() {
                    let mapped = match event {
                        ServiceEvent::ServiceResolved(service) => resolve_service(&service),
                        ServiceEvent::ServiceRemoved(_, fullname) => {
                            Some(DiscoveryRuntimeEvent::Removed { fullname })
                        }
                        _ => None,
                    };
                    if mapped.is_some_and(|event| sender.send(event).is_err()) {
                        break;
                    }
                }
            })
            .map_err(|_| DiscoveryError::RuntimeUnavailable)?;
        Ok(MdnsBrowser {
            daemon: self.daemon.clone(),
            receiver,
            worker: Some(worker),
        })
    }
}

impl Drop for MdnsRuntime {
    fn drop(&mut self) {
        if let Some(fullname) = self.registered_fullname.take() {
            let _ = self.daemon.unregister(&fullname);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryRuntimeEvent {
    Resolved {
        fullname: String,
        locations: Vec<DiscoveryLocation>,
    },
    Removed {
        fullname: String,
    },
    InvalidAdvertisement,
}

pub struct MdnsBrowser {
    daemon: ServiceDaemon,
    receiver: Receiver<DiscoveryRuntimeEvent>,
    worker: Option<thread::JoinHandle<()>>,
}

impl MdnsBrowser {
    /// Waits up to `timeout` for the next bounded discovery event.
    ///
    /// # Errors
    ///
    /// Returns the standard channel timeout or disconnect error.
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<DiscoveryRuntimeEvent, RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }
}

impl Drop for MdnsBrowser {
    fn drop(&mut self) {
        let _ = self.daemon.stop_browse(SERVICE_TYPE);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn resolve_service(service: &ResolvedService) -> Option<DiscoveryRuntimeEvent> {
    let txt_fields = service
        .get_properties()
        .iter()
        .map(|property| format!("{}={}", property.key(), property.val_str()))
        .collect::<Vec<_>>();
    let borrowed_txt = txt_fields.iter().map(String::as_bytes).collect::<Vec<_>>();
    let instance = service
        .get_fullname()
        .strip_suffix(SERVICE_TYPE)?
        .trim_end_matches('.')
        .replace("\\.", ".")
        .replace("\\\\", "\\");
    let Ok(record) =
        DiscoveryRecord::parse_untrusted(instance.as_bytes(), service.get_port(), &borrowed_txt)
    else {
        return Some(DiscoveryRuntimeEvent::InvalidAdvertisement);
    };
    let locations = service
        .get_addresses()
        .iter()
        .filter_map(|address| scoped_socket_address(address, record.port()))
        .filter_map(|address| DiscoveryLocation::mdns(address, record.clone()).ok())
        .collect::<Vec<_>>();
    if locations.is_empty() {
        return Some(DiscoveryRuntimeEvent::InvalidAdvertisement);
    }
    Some(DiscoveryRuntimeEvent::Resolved {
        fullname: service.get_fullname().to_owned(),
        locations,
    })
}

fn scoped_socket_address(address: &ScopedIp, port: u16) -> Option<SocketAddr> {
    match address {
        ScopedIp::V4(value) => Some(SocketAddr::new(IpAddr::V4(*value.addr()), port)),
        ScopedIp::V6(value) => Some(SocketAddr::V6(SocketAddrV6::new(
            *value.addr(),
            port,
            0,
            value.scope_id().index,
        ))),
        _ => None,
    }
}
