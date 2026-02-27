//! Windows TUN implementation using WinTUN
//!
//! WinTUN is a high-performance TUN driver for Windows, used by WireGuard.

use crate::error::{TunnelError, TunnelResult};
use std::net::IpAddr;
use std::sync::Arc;
use wintun::{Adapter, Session};

/// Windows TUN device using WinTUN
pub struct WindowsTun {
    name: String,
    #[allow(dead_code)]
    adapter: Arc<Adapter>,
    session: Arc<Session>,
}

impl WindowsTun {
    /// Get device name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Create a new WinTUN adapter
    pub fn create(name: &str) -> TunnelResult<Self> {
        // Load WinTUN driver
        let wintun = unsafe {
            wintun::load()
                .map_err(|e| TunnelError::DeviceCreation(format!("Failed to load WinTUN: {}", e)))?
        };

        // Create or open adapter - these return Arc<Adapter> directly
        let adapter: Arc<Adapter> = match Adapter::open(&wintun, name) {
            Ok(adapter) => adapter,
            Err(_) => Adapter::create(&wintun, name, "DyberVPN", None).map_err(|e| {
                TunnelError::DeviceCreation(format!("Failed to create adapter: {}", e))
            })?,
        };

        // Start session with ring buffer
        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| TunnelError::DeviceCreation(format!("Failed to start session: {}", e)))?;

        Ok(Self {
            name: name.to_string(),
            adapter,
            session: Arc::new(session),
        })
    }

    /// Set the device IP address
    pub fn set_address(&self, addr: IpAddr, prefix: u8) -> TunnelResult<()> {
        use std::process::Command;

        let addr_str = addr.to_string();

        match addr {
            IpAddr::V4(_) => {
                let mask = prefix_to_mask_v4(prefix);

                Command::new("netsh")
                    .args([
                        "interface",
                        "ip",
                        "set",
                        "address",
                        &format!("name=\"{}\"", self.name),
                        "source=static",
                        &format!("addr={}", addr_str),
                        &format!("mask={}", mask),
                    ])
                    .output()
                    .map_err(|e| TunnelError::Config(format!("Failed to set address: {}", e)))?;
            }
            IpAddr::V6(_) => {
                Command::new("netsh")
                    .args([
                        "interface",
                        "ipv6",
                        "add",
                        "address",
                        &format!("interface=\"{}\"", self.name),
                        &format!("address={}/{}", addr_str, prefix),
                    ])
                    .output()
                    .map_err(|e| TunnelError::Config(format!("Failed to set address: {}", e)))?;
            }
        }

        Ok(())
    }

    /// Set the MTU
    pub fn set_mtu(&self, mtu: u16) -> TunnelResult<()> {
        use std::process::Command;

        Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &self.name,
                &format!("mtu={}", mtu),
                "store=persistent",
            ])
            .output()
            .map_err(|e| TunnelError::Config(format!("Failed to set MTU: {}", e)))?;

        Ok(())
    }

    /// Bring the device up
    pub fn up(&self) -> TunnelResult<()> {
        Ok(())
    }

    /// Bring the device down
    pub fn down(&self) -> TunnelResult<()> {
        Ok(())
    }

    /// Read a packet from the device (blocking)
    pub fn read(&self, buf: &mut [u8]) -> TunnelResult<usize> {
        match self.session.receive_blocking() {
            Ok(packet) => {
                let bytes = packet.bytes();
                let len = bytes.len().min(buf.len());
                buf[..len].copy_from_slice(&bytes[..len]);
                Ok(len)
            }
            Err(e) => Err(TunnelError::Io(std::io::Error::other(format!(
                "Failed to receive packet: {}",
                e
            )))),
        }
    }

    /// Write a packet to the device
    pub fn write(&self, buf: &[u8]) -> TunnelResult<usize> {
        let mut packet = self
            .session
            .allocate_send_packet(buf.len() as u16)
            .map_err(|e| {
                TunnelError::Io(std::io::Error::other(format!(
                    "Failed to allocate packet: {}",
                    e
                )))
            })?;

        packet.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(packet);

        Ok(buf.len())
    }
}

/// Convert CIDR prefix to IPv4 subnet mask
fn prefix_to_mask_v4(prefix: u8) -> String {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };

    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF
    )
}

impl Drop for WindowsTun {
    fn drop(&mut self) {
        tracing::debug!("Closing WinTUN adapter: {}", self.name);
    }
}
