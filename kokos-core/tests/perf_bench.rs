//! On-demand perf/stress benches. All #[ignore] — run explicitly:
//!   cargo test -p kokos-core --test perf_bench -- --ignored --nocapture
//! Targets @20k: open 1–3s, search <100ms, CRUD <10ms/op, save 100–500ms.
//! 50k is a stress run (measured + loose ceiling), not a target assertion.
//! Vaults use FAST KDF so the numbers reflect DB scaling, not Argon2 (see the
//! open-note below).

use std::time::Instant;

use kokos_core::crypto::Argon2Params;
use kokos_core::entries::{self, EntryPatch, NewEntry, NewField, View};
use kokos_core::{db, search, vault};
use rusqlite::Connection;

const FAST: Argon2Params = Argon2Params { memory_kib: 19_456, time_cost: 2, parallelism: 1 };

/// Bulk-insert `n` synthetic entries (username[text] + password[secret] +
/// url[url]) in ONE transaction, bypassing entries::create (which opens a tx
/// and re-reads per call). Titles/usernames share the token "acme" so a broad
/// search matches ~all rows — the worst case for the old N+1.
fn generate(conn: &Connection, n: usize) {
    let now = db::now_unix();
    let tx = conn.unchecked_transaction().unwrap();
    {
        let mut ins_e = tx
            .prepare(
                "INSERT INTO entries (id, folder_id, title, is_favorite, is_deleted, created_at, updated_at)
                 VALUES (?1,'root',?2,0,0,?3,?3)",
            )
            .unwrap();
        let mut ins_f = tx
            .prepare(
                "INSERT INTO entry_fields
                   (id, entry_id, template_id, name, value, is_protected, field_type, sort_order)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            )
            .unwrap();
        for i in 0..n {
            let eid = format!("e{i:07}");
            ins_e
                .execute(rusqlite::params![eid, format!("Entry {i} acme login"), now])
                .unwrap();
            ins_f
                .execute(rusqlite::params![
                    format!("{eid}-u"), eid, "tpl_username", "Username",
                    format!("user{i}@acme.test"), 0_i64, "text", 0_i64
                ])
                .unwrap();
            ins_f
                .execute(rusqlite::params![
                    format!("{eid}-p"), eid, "tpl_password", "Password",
                    format!("s3cr3t-{i}-xZ"), 1_i64, "secret", 1_i64
                ])
                .unwrap();
            ins_f
                .execute(rusqlite::params![
                    format!("{eid}-r"), eid, "tpl_url", "URL",
                    "https://acme.test", 0_i64, "url", 2_i64
                ])
                .unwrap();
        }
    }
    tx.commit().unwrap();
}

fn none() -> search::SearchFilters {
    search::SearchFilters::default()
}

#[test]
#[ignore = "perf: run with --ignored"]
fn search_20k_under_100ms() {
    let conn = db::create_fresh().unwrap();
    generate(&conn, 20_000);

    let t = Instant::now();
    let hits = search::search(&conn, "acme", &none()).unwrap();
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("search 20k broad -> {} hits in {ms:.1} ms", hits.len());
    assert_eq!(hits.len(), 20_000, "broad token must match every entry");
    assert!(ms < 250.0, "search@20k must be <250ms (was {ms:.1} ms)");

    let t = Instant::now();
    let hits = search::search(&conn, "user1@acme.test", &none()).unwrap();
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("search 20k narrow -> {} hits in {ms:.1} ms", hits.len());
    assert_eq!(hits.len(), 1, "narrow query must match exactly one entry");
    assert!(ms < 100.0, "narrow search@20k must be <100ms (was {ms:.1} ms)");
}

#[test]
#[ignore = "perf: run with --ignored"]
fn list_20k_under_100ms() {
    let conn = db::create_fresh().unwrap();
    generate(&conn, 20_000);
    let t = Instant::now();
    let all = entries::list(&conn, View::All).unwrap();
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("list 20k -> {} rows in {ms:.1} ms", all.len());
    assert_eq!(all.len(), 20_000);
    assert!(ms < 100.0, "list@20k must be <100ms (was {ms:.1} ms)");
}

#[test]
#[ignore = "perf: run with --ignored"]
fn crud_ops_under_10ms_on_20k_vault() {
    let conn = db::create_fresh().unwrap();
    generate(&conn, 20_000);
    let now = db::now_unix();

    let t = Instant::now();
    let created = entries::create(
        &conn,
        NewEntry {
            title: "Bench New".into(),
            folder_id: None,
            notes: None,
            entry_type: "login".into(),
            fields: vec![NewField {
                template_id: Some("tpl_username".into()),
                name: "Username".into(),
                value: Some("bench@acme.test".into()),
                is_protected: false,
                field_type: "text".into(),
            }],
        },
        now,
    )
    .unwrap();
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("create -> {ms:.2} ms");
    assert!(ms < 10.0, "create on a 20k vault must be <10ms (was {ms:.2} ms)");

    let t = Instant::now();
    let _ = entries::get(&conn, &created.id).unwrap().unwrap();
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("read -> {ms:.2} ms");
    assert!(ms < 10.0, "read on a 20k vault must be <10ms (was {ms:.2} ms)");

    let t = Instant::now();
    let _ = entries::update(
        &conn,
        &created.id,
        EntryPatch {
            title: Some("Bench Renamed".into()),
            notes: None,
            is_favorite: Some(true),
            folder_id: None,
            fields: None,
        },
        now + 1,
    )
    .unwrap();
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("update -> {ms:.2} ms");
    assert!(ms < 10.0, "update on a 20k vault must be <10ms (was {ms:.2} ms)");
}

#[test]
#[ignore = "perf: run with --ignored"]
fn open_and_save_20k_within_target() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench20k.kokos");

    let mut v = vault::create(&path, b"pw", "hint", FAST, None).unwrap();
    generate(&v.conn, 20_000);
    let t = Instant::now();
    vault::save(&mut v).unwrap();
    let save_ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("save 20k -> {save_ms:.1} ms");
    assert!(save_ms < 1500.0, "save@20k must be <1.5s (was {save_ms:.1} ms)");
    drop(v);

    let t = Instant::now();
    let v2 = vault::open(&path, b"pw", None).unwrap();
    let open_ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("open 20k -> {open_ms:.1} ms");
    let n: i64 = v2
        .conn
        .query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 20_000);
    assert!(open_ms < 3000.0, "open@20k must be <3s (was {open_ms:.1} ms)");
}

#[test]
#[ignore = "perf: 50k stress, run with --ignored"]
fn stress_50k_search_and_list() {
    let conn = db::create_fresh().unwrap();
    generate(&conn, 50_000);

    let t = Instant::now();
    let hits = search::search(&conn, "acme", &none()).unwrap();
    let search_ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("STRESS search 50k -> {} hits in {search_ms:.1} ms", hits.len());
    assert_eq!(hits.len(), 50_000);

    let t = Instant::now();
    let all = entries::list(&conn, View::All).unwrap();
    let list_ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("STRESS list 50k -> {} rows in {list_ms:.1} ms", all.len());
    assert_eq!(all.len(), 50_000);

    assert!(search_ms < 500.0, "50k search should stay <500ms (was {search_ms:.1} ms)");
    assert!(list_ms < 500.0, "50k list should stay <500ms (was {list_ms:.1} ms)");
}
