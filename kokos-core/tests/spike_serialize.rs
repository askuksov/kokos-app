//! Spike: prove the `rusqlite` `serialize` cargo feature actually round-trips
//! an in-memory database on this toolchain/platform before the rest of the
//! vault format (DB in memory -> bytes -> encrypted file) is built on top of it.
use rusqlite::{serialize::Data, Connection, DatabaseName};

#[test]
fn in_memory_db_survives_serialize_deserialize() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE t (id TEXT PRIMARY KEY); INSERT INTO t VALUES ('x');")
        .unwrap();

    let data = conn.serialize(DatabaseName::Main).unwrap();
    assert!(!data.is_empty(), "serialize produced no bytes");
    assert_eq!(&data[0..15], b"SQLite format 3", "not a SQLite image");

    let Data::Owned(owned) = data else {
        panic!("expected Data::Owned for a freshly-serialized in-memory db");
    };

    let mut restored = Connection::open_in_memory().unwrap();
    restored
        .deserialize(DatabaseName::Main, owned, false)
        .unwrap();
    let got: String = restored
        .query_row("SELECT id FROM t", [], |r| r.get(0))
        .unwrap();
    assert_eq!(got, "x");
}
