//! Linux TUN implementation
//!
//! Uses the standard Linux TUN/TAP driver via /dev/net/tun

use crate::device::TunDevice;
use crate::error::{TunnelError, TunnelResult};
use std::net::IpAddr;
use std::os::unix::io::AsRawFd;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

/// Linux TUN device
pub struct LinuxTun {
    name: String,
    fd: File,
}

// ioctl constants
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _padding: [u8; 22],
}

impl LinuxTun {
    /// Create a new TUN device
    pub fn create(name: &str) -> TunnelResult<Self> {
        // Open /dev/net/tun
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::EACCES) {
                    TunnelError::PermissionDenied(
                        "Cannot open /dev/net/tun. Try running as root or with CAP_NET_ADMIN".into()
                    )
                } else {
                    TunnelError::DeviceCreation(format!("Failed to open /dev/net/tun: {}", e))
                }
            })?;
        
        // Create interface request
        let mut ifr = IfReq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _padding: [0; 22],
        };
        
        // Copy name
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }
        
        // Create interface via ioctl
        let ret = unsafe {
            libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &mut ifr as *mut IfReq)
        };
        
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return Err(TunnelError::DeviceCreation(format!(
                "Failed to create TUN device: {}", err
            )));
        }
        
        // Get actual device name
        let actual_name = unsafe {
            let ptr = ifr.ifr_name.as_ptr();
            let len = libc::strlen(ptr);
            let slice = std::slice::from_raw_parts(ptr as *const u8, len);
            String::from_utf8_lossy(slice).to_string()
        };
        
        tracing::info!("Created TUN device: {}", actual_name);
        
        Ok(Self {
            name: actual_name,
            fd,
        })
    }
    
    /// Run an ip command
    fn run_ip_cmd(&self, args: &[&str]) -> TunnelResult<()> {
        use std::process::Command;
        
        let output = Command::new("ip")
            .args(args)
            .output()
            .map_err(|e| TunnelError::Config(format!("Failed to run ip command: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunnelError::Config(format!("ip command failed: {}", stderr)));
        }
        
        Ok(())
    }
    
    /// Get raw file descriptor (for advanced use)
    #[allow(dead_code)]
    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}

impl TunDevice for LinuxTun {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn set_address(&self, addr: IpAddr, prefix: u8) -> TunnelResult<()> {
        let addr_str = format!("{}/{}", addr, prefix);
        self.run_ip_cmd(&["addr", "add", &addr_str, "dev", &self.name])
    }
    
    fn set_mtu(&self, mtu: u16) -> TunnelResult<()> {
        let mtu_str = mtu.to_string();
        self.run_ip_cmd(&["link", "set", "dev", &self.name, "mtu", &mtu_str])
    }
    
    fn up(&self) -> TunnelResult<()> {
        self.run_ip_cmd(&["link", "set", "dev", &self.name, "up"])
    }
    
    fn down(&self) -> TunnelResult<()> {
        self.run_ip_cmd(&["link", "set", "dev", &self.name, "down"])
    }
    
    fn read(&self, buf: &mut [u8]) -> TunnelResult<usize> {
        let mut fd = &self.fd;
        fd.read(buf).map_err(TunnelError::Io)
    }
    
    fn write(&self, buf: &[u8]) -> TunnelResult<usize> {
        let mut fd = &self.fd;
        fd.write(buf).map_err(TunnelError::Io)
    }
}

impl Drop for LinuxTun {
    fn drop(&mut self) {
        tracing::debug!("Closing TUN device: {}", self.name);
        let _ = self.down();
    }
}
