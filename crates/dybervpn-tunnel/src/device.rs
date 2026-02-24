//! TUN device abstraction
//!
//! This module provides a cross-platform interface for TUN devices.

use crate::error::TunnelResult;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use crate::error::TunnelError;
use std::net::IpAddr;

/// TUN device trait for cross-platform operations
pub trait TunDevice: Send + Sync {
    /// Get the device name
    fn name(&self) -> &str;
    
    /// Set the device IP address
    fn set_address(&self, addr: IpAddr, prefix: u8) -> TunnelResult<()>;
    
    /// Set the MTU
    fn set_mtu(&self, mtu: u16) -> TunnelResult<()>;
    
    /// Bring the device up
    fn up(&self) -> TunnelResult<()>;
    
    /// Bring the device down
    fn down(&self) -> TunnelResult<()>;
    
    /// Read a packet from the device (blocking)
    fn read(&self, buf: &mut [u8]) -> TunnelResult<usize>;
    
    /// Write a packet to the device
    fn write(&self, buf: &[u8]) -> TunnelResult<usize>;
}

/// Handle to a TUN device - cross-platform wrapper
pub struct DeviceHandle {
    #[cfg(target_os = "linux")]
    inner: crate::linux::LinuxTun,
    
    #[cfg(target_os = "macos")]
    inner: crate::macos::MacOsTun,
    
    #[cfg(target_os = "windows")]
    inner: crate::windows::WindowsTun,
}

impl DeviceHandle {
    /// Create a new TUN device
    pub fn create(name: &str) -> TunnelResult<Self> {
        #[cfg(target_os = "linux")]
        {
            let inner = crate::linux::LinuxTun::create(name)?;
            Ok(Self { inner })
        }
        
        #[cfg(target_os = "macos")]
        {
            let inner = crate::macos::MacOsTun::create(name)?;
            Ok(Self { inner })
        }
        
        #[cfg(target_os = "windows")]
        {
            let inner = crate::windows::WindowsTun::create(name)?;
            Ok(Self { inner })
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(TunnelError::PlatformNotSupported(
                "TUN devices not supported on this platform".into()
            ))
        }
    }
    
    /// Get device name
    pub fn name(&self) -> &str {
        #[cfg(target_os = "linux")]
        { self.inner.name() }
        
        #[cfg(target_os = "macos")]
        { self.inner.name() }
        
        #[cfg(target_os = "windows")]
        { self.inner.name() }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        { "unknown" }
    }
    
    /// Configure the device
    pub fn configure(&self, addr: IpAddr, prefix: u8, mtu: u16) -> TunnelResult<()> {
        #[cfg(target_os = "linux")]
        {
            use crate::device::TunDevice;
            self.inner.set_address(addr, prefix)?;
            self.inner.set_mtu(mtu)?;
            self.inner.up()?;
            Ok(())
        }
        
        #[cfg(target_os = "macos")]
        {
            use crate::device::TunDevice;
            self.inner.set_address(addr, prefix)?;
            self.inner.set_mtu(mtu)?;
            self.inner.up()?;
            Ok(())
        }
        
        #[cfg(target_os = "windows")]
        {
            self.inner.set_address(addr, prefix)?;
            self.inner.set_mtu(mtu)?;
            self.inner.up()?;
            Ok(())
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(TunnelError::PlatformNotSupported(
                "TUN devices not supported on this platform".into()
            ))
        }
    }
    
    /// Read a packet from the device
    pub fn read_packet(&self, buf: &mut [u8]) -> TunnelResult<usize> {
        #[cfg(target_os = "linux")]
        {
            use crate::device::TunDevice;
            self.inner.read(buf)
        }
        
        #[cfg(target_os = "macos")]
        {
            use crate::device::TunDevice;
            self.inner.read(buf)
        }
        
        #[cfg(target_os = "windows")]
        {
            self.inner.read(buf)
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(TunnelError::PlatformNotSupported(
                "TUN devices not supported on this platform".into()
            ))
        }
    }
    
    /// Write a packet to the device
    pub fn write_packet(&self, buf: &[u8]) -> TunnelResult<usize> {
        #[cfg(target_os = "linux")]
        {
            use crate::device::TunDevice;
            self.inner.write(buf)
        }
        
        #[cfg(target_os = "macos")]
        {
            use crate::device::TunDevice;
            self.inner.write(buf)
        }
        
        #[cfg(target_os = "windows")]
        {
            self.inner.write(buf)
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(TunnelError::PlatformNotSupported(
                "TUN devices not supported on this platform".into()
            ))
        }
    }
    
    /// Bring device down
    pub fn shutdown(&self) -> TunnelResult<()> {
        #[cfg(target_os = "linux")]
        {
            use crate::device::TunDevice;
            self.inner.down()
        }
        
        #[cfg(target_os = "macos")]
        {
            use crate::device::TunDevice;
            self.inner.down()
        }
        
        #[cfg(target_os = "windows")]
        {
            self.inner.down()
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Ok(())
        }
    }
}
