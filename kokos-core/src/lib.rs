//! Kokos vault core: format, crypto, storage. No Tauri dependency.

pub mod attachments;
pub mod audit;
pub mod crypto;
pub mod db;
pub mod entries;
pub mod error;
pub mod folders;
pub mod format;
pub mod sync;
pub mod generator;
pub mod health;
pub mod hibp;
pub mod kdbx;
pub mod portable;
pub mod keyfile;
pub mod logins;
pub mod nmh_grants;
pub mod relations;
pub mod search;
pub mod session;
pub mod strength;
pub mod tags;
pub mod templates;
pub mod totp;
pub mod trash;
pub mod url_match;
pub mod vault;

#[cfg(test)]
mod testutil;

pub use error::{Result, VaultError};
