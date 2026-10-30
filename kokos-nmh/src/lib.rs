//! Native-messaging host library, shared by the `kokos-nmh` binary and the
//! Kokos app. Holds ONLY the wire contract (framing + envelope + argv parsing
//! + socket path). It links neither kokos-core nor tauri: the host process
//! must be unable to touch a vault file or a key.

pub mod framing;
pub mod protocol;

/// Host build version, reported in `ping` when the app is unreachable.
pub const HOST_VERSION: &str = env!("CARGO_PKG_VERSION");
