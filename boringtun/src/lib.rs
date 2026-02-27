// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! <code>git clone https://github.com/cloudflare/boringtun.git</code>

// Platform-specific code (sleepyinstant, device) differs between targets
#![allow(
    unused_imports,
    unused_variables,
    dead_code,
    unused_mut,
    clippy::needless_borrows_for_generic_args,
    clippy::redundant_closure,
    clippy::doc_lazy_continuation,
    clippy::manual_is_multiple_of,
    clippy::bool_comparison
)]

#[cfg(feature = "device")]
pub mod device;

#[cfg(feature = "ffi-bindings")]
pub mod ffi;
#[cfg(feature = "jni-bindings")]
pub mod jni;
pub mod noise;

#[cfg(not(feature = "mock-instant"))]
pub(crate) mod sleepyinstant;

pub(crate) mod serialization;

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}
