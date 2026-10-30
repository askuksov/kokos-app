//! Prints hint and flags without a password — the header is unencrypted.
//! Usage: cargo run -p kokos-core --example vault_info -- <path>

fn main() {
    let path = std::env::args().nth(1).expect("usage: vault_info <path>");
    let h = kokos_core::format::header::read_header_only(std::path::Path::new(&path)).expect("read header");
    println!("format version : {}", h.version);
    println!("requires keyfile: {}", h.requires_keyfile());
    println!("hint           : {:?}", h.hint);
    println!("argon2         : memory={} KiB, time={}, parallelism={}", h.kdf.memory_kib, h.kdf.time_cost, h.kdf.parallelism);
}
