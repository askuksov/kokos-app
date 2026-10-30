//! Opens a vault with an interactively supplied password and prints statistics.
//! Usage: cargo run -p kokos-core --example vault_open -- <path> [keyfile]

use zeroize::Zeroizing;

fn main() {
    let path = std::env::args().nth(1).expect("usage: vault_open <path> [keyfile]");
    let keyfile = std::env::args().nth(2);

    let pw = Zeroizing::new(rpassword::prompt_password("password: ").expect("failed to read password"));

    let v = kokos_core::vault::open(
        std::path::Path::new(&path),
        pw.as_bytes(),
        keyfile.as_ref().map(std::path::Path::new),
    )
    .expect("open failed");

    let entries: i64 = v.conn.query_row("SELECT COUNT(*) FROM entries WHERE is_deleted = 0", [], |r| r.get(0)).unwrap();
    let deleted: i64 = v.conn.query_row("SELECT COUNT(*) FROM entries WHERE is_deleted = 1", [], |r| r.get(0)).unwrap();
    let folders: i64 = v.conn.query_row("SELECT COUNT(*) FROM folders", [], |r| r.get(0)).unwrap();
    let tags: i64 = v.conn.query_row("SELECT COUNT(*) FROM tags", [], |r| r.get(0)).unwrap();
    let favs: i64 = v.conn.query_row("SELECT COUNT(*) FROM entries WHERE is_favorite = 1 AND is_deleted = 0", [], |r| r.get(0)).unwrap();

    println!("format version : {}", v.header.version);
    println!("schema migrated: {}", v.migrated);
    println!("entries        : {entries} (deleted: {deleted})");
    println!("folders        : {folders}");
    println!("tags           : {tags}");
    println!("favorites      : {favs}");
}
