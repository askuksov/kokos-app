//! Writes a v1 fixture back through the Rust implementation so the Go
//! version can be asked to read it. Usage:
//!   cargo run -p kokos-core --example write_for_go -- <src.vault> <dst.vault>
//!
//! NOTE: since the v3 KOKOS magic rebrand, `Header::write` always emits the
//! `KOKOS\0\0\0` magic regardless of the header's own version field, so the
//! file this example produces is no longer byte-compatible with the Go
//! reference reader — even a re-saved v1 header (version number unchanged)
//! now carries the new magic. Go byte-compat is intentionally dropped from
//! v3 onward; this example is kept for historical/manual cross-checking only.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (src, dst) = (&args[1], &args[2]);
    std::fs::copy(src, dst).expect("copy");

    let mut v = kokos_core::vault::open(std::path::Path::new(dst), b"fixture-password", None)
        .expect("open");
    v.conn
        .execute(
            "INSERT INTO entries (id, folder_id, title, created_at, updated_at)
             VALUES ('rust-written', 'root', 'Written by Rust', 1, 1)",
            [],
        )
        .expect("insert");
    kokos_core::vault::save(&mut v).expect("save");
    println!("saved {dst} (version {})", v.header.version);
}
