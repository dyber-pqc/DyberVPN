//! macOS TUN implementation
//!
//! Uses the built-in utun driver

use crate::device::TunDevice;
use crate::error::{TunnelError, TunnelResult};
use std::net::IpAddr;
use std::os::unix::io::RawFd;

/// macOS TUN device using utun
pub struct MacOsTun {
    name: String,
    fd: RawFd,
}

// System call constants for macOS
const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
const AF_SYS_CONTROL: libc::c_int = 2;
const SYSPROTO_CONTROL: libc::c_int = 2;

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

impl MacOsTun {
    /// Create a new utun device
    pub fn create(name: &str) -> TunnelResult<Self> {
        // Parse the utun number from name (e.g., "utun5" -> 6, since utun0 is unit 1)
        let unit: u32 = if name.starts_with("utun") {
            name[4..].parse::<u32>().unwrap_or(0) + 1
        } else {
            0 // Auto-assign
        };

        // Create a system control socket
        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };

        if fd < 0 {
            return Err(TunnelError::DeviceCreation(format!(
                "Failed to create socket: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Get control info
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };

        // Copy control name
        let name_len = UTUN_CONTROL_NAME.len().min(96);
        info.ctl_name[..name_len].copy_from_slice(&UTUN_CONTROL_NAME[..name_len]);

        let ret = unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut info as *mut CtlInfo) };

        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(TunnelError::DeviceCreation(format!(
                "Failed to get control info: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Connect to utun
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };

        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const SockaddrCtl as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as u32,
            )
        };

        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(TunnelError::DeviceCreation(format!(
                "Failed to connect to utun: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Get actual device name
        let actual_name = format!("utun{}", unit - 1);

        tracing::info!("Created TUN device: {}", actual_name);

        Ok(Self {
            name: actual_name,
            fd,
        })
    }

    /// Run an ifconfig command
    fn run_ifconfig(&self, args: &[&str]) -> TunnelResult<()> {
        use std::process::Command;

        let mut full_args = vec![&self.name[..]];
        full_args.extend(args.iter());

        let output = Command::new("ifconfig")
            .args(&full_args)
            .output()
            .map_err(|e| TunnelError::Config(format!("Failed to run ifconfig: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunnelError::Config(format!("ifconfig failed: {}", stderr)));
        }

        Ok(())
    }

    /// Get raw file descriptor (for advanced use)
    #[allow(dead_code)]
    pub fn raw_fd(&self) -> i32 {
        self.fd
    }
}

impl TunDevice for MacOsTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn set_address(&self, addr: IpAddr, prefix: u8) -> TunnelResult<()> {
        match addr {
            IpAddr::V4(v4) => {
                // For point-to-point, we need a destination address
                // Use the same address as a placeholder
                let addr_str = v4.to_string();
                self.run_ifconfig(&[
                    "inet",
                    &addr_str,
                    &addr_str,
                    "netmask",
                    &prefix_to_mask_v4(prefix),
                ])
            }
            IpAddr::V6(v6) => {
                let addr_str = format!("{}/{}", v6, prefix);
                self.run_ifconfig(&["inet6", &addr_str])
            }
        }
    }

    fn set_mtu(&self, mtu: u16) -> TunnelResult<()> {
        let mtu_str = mtu.to_string();
        self.run_ifconfig(&["mtu", &mtu_str])
    }

    fn up(&self) -> TunnelResult<()> {
        self.run_ifconfig(&["up"])
    }

    fn down(&self) -> TunnelResult<()> {
        self.run_ifconfig(&["down"])
    }

    fn read(&self, buf: &mut [u8]) -> TunnelResult<usize> {
        // macOS utun prepends a 4-byte header
        let mut full_buf = vec![0u8; buf.len() + 4];
        let n = unsafe {
            libc::read(
                self.fd,
                full_buf.as_mut_ptr() as *mut libc::c_void,
                full_buf.len(),
            )
        };

        if n < 0 {
            return Err(TunnelError::Io(std::io::Error::last_os_error()));
        }

        let n = n as usize;
        if n <= 4 {
            return Ok(0);
        }

        let copy_len = (n - 4).min(buf.len());
        buf[..copy_len].copy_from_slice(&full_buf[4..4 + copy_len]);

        Ok(copy_len)
    }

    fn write(&self, buf: &[u8]) -> TunnelResult<usize> {
        // Prepend 4-byte header (AF_INET or AF_INET6)
        let mut full_buf = vec![0u8; buf.len() + 4];

        // Determine address family from IP version
        let af: u32 = if !buf.is_empty() && (buf[0] >> 4) == 6 {
            libc::AF_INET6 as u32
        } else {
            libc::AF_INET as u32
        };

        full_buf[0..4].copy_from_slice(&af.to_be_bytes());
        full_buf[4..].copy_from_slice(buf);

        let n = unsafe {
            libc::write(
                self.fd,
                full_buf.as_ptr() as *const libc::c_void,
                full_buf.len(),
            )
        };

        if n < 0 {
            return Err(TunnelError::Io(std::io::Error::last_os_error()));
        }

        Ok((n as usize).saturating_sub(4))
    }
}

/// Convert CIDR prefix to IPv4 subnet mask string
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

impl Drop for MacOsTun {
    fn drop(&mut self) {
        tracing::debug!("Closing TUN device: {}", self.name);
        unsafe { libc::close(self.fd) };
    }
}
