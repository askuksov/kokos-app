//! Attachment CRUD. Attachments are inline BLOBs stored inside the encrypted
//! vault DB, capped at `MAX_ATTACHMENT_SIZE` (10 MB). `list()` never
//! selects the `data` column so browsing an entry's attachments stays cheap;
//! only `get()` pulls the bytes.

use rusqlite::{Connection, OptionalExtension};

use crate::error::{Result, VaultError};

pub const MAX_ATTACHMENT_SIZE: usize = 10 * 1024 * 1024;

/// Combined attachment bytes allowed per vault: the saved file must stay
/// under `vault::MAX_VAULT_FILE_SIZE` or `open()` rejects it, so leave
/// 64 MiB of headroom for the rest of the DB and the container overhead.
const MAX_TOTAL_ATTACHMENT_BYTES: i64 =
    crate::vault::MAX_VAULT_FILE_SIZE as i64 - 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct AttachmentMeta {
    pub id: String,
    pub entry_id: String,
    pub filename: String,
    pub mime_type: Option<String>,
    pub size: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct Attachment {
    pub meta: AttachmentMeta,
    pub data: Vec<u8>,
}

pub fn add(
    conn: &Connection,
    entry_id: &str,
    filename: &str,
    mime: Option<&str>,
    data: &[u8],
    now: i64,
) -> Result<AttachmentMeta> {
    if data.len() > MAX_ATTACHMENT_SIZE {
        return Err(VaultError::AttachmentTooLarge);
    }
    let size = data.len() as i64;
    let total: i64 =
        conn.query_row("SELECT COALESCE(SUM(size), 0) FROM attachments", [], |r| r.get(0))?;
    if total.saturating_add(size) > MAX_TOTAL_ATTACHMENT_BYTES {
        return Err(VaultError::AttachmentTooLarge);
    }
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO attachments (id, entry_id, filename, mime_type, data, size, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![id, entry_id, filename, mime, data, size, now],
    )?;
    Ok(AttachmentMeta {
        id,
        entry_id: entry_id.to_string(),
        filename: filename.to_string(),
        mime_type: mime.map(str::to_string),
        size,
        created_at: now,
    })
}

pub fn list(conn: &Connection, entry_id: &str) -> Result<Vec<AttachmentMeta>> {
    let mut stmt = conn.prepare(
        "SELECT id, entry_id, filename, mime_type, size, created_at
         FROM attachments WHERE entry_id = ?1 ORDER BY created_at ASC, filename ASC",
    )?;
    let rows = stmt.query_map([entry_id], |r| {
        Ok(AttachmentMeta {
            id: r.get(0)?,
            entry_id: r.get(1)?,
            filename: r.get(2)?,
            mime_type: r.get(3)?,
            size: r.get(4)?,
            created_at: r.get(5)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn get(conn: &Connection, id: &str) -> Result<Attachment> {
    conn.query_row(
        "SELECT id, entry_id, filename, mime_type, data, size, created_at
         FROM attachments WHERE id = ?1",
        [id],
        |r| {
            Ok(Attachment {
                meta: AttachmentMeta {
                    id: r.get(0)?,
                    entry_id: r.get(1)?,
                    filename: r.get(2)?,
                    mime_type: r.get(3)?,
                    size: r.get(5)?,
                    created_at: r.get(6)?,
                },
                data: r.get(4)?,
            })
        },
    )
    .optional()?
    .ok_or(VaultError::AttachmentNotFound)
}

pub fn delete(conn: &Connection, id: &str) -> Result<()> {
    let n = conn.execute("DELETE FROM attachments WHERE id = ?1", [id])?;
    if n == 0 {
        return Err(VaultError::AttachmentNotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{both_dbs, seed_entry};

    #[test]
    fn add_enforces_10mb_cap() {
        for (label, conn) in both_dbs() {
            crate::testutil::seed_entry(&conn, "att-e", "E", 0);
            let too_big = vec![0u8; MAX_ATTACHMENT_SIZE + 1];
            assert!(matches!(add(&conn, "att-e", "big.bin", None, &too_big, 1), Err(VaultError::AttachmentTooLarge)), "[{label}] over cap rejected");
            let ok = add(&conn, "att-e", "ok.txt", Some("text/plain"), b"hello", 1000).unwrap();
            assert_eq!((ok.filename.as_str(), ok.size), ("ok.txt", 5), "[{label}] meta stored");
            let exactly_cap = vec![0u8; MAX_ATTACHMENT_SIZE];
            assert!(add(&conn, "att-e", "exact.bin", None, &exactly_cap, 1).is_ok(), "[{label}] exactly at cap accepted");
        }
    }

    #[test]
    fn add_enforces_vault_wide_budget() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "att-budget", "Budget", 0);
            let existing: i64 = conn
                .query_row("SELECT COALESCE(SUM(size), 0) FROM attachments", [], |r| r.get(0))
                .unwrap();
            // A tiny blob whose recorded size fills the budget up to 5 bytes short.
            conn.execute(
                "INSERT INTO attachments (id, entry_id, filename, mime_type, data, size, created_at)
                 VALUES ('att-huge', 'att-budget', 'huge.bin', NULL, x'00', ?1, 1)",
                [MAX_TOTAL_ATTACHMENT_BYTES - existing - 5],
            )
            .unwrap();
            assert!(matches!(add(&conn, "att-budget", "over.bin", None, b"123456", 1), Err(VaultError::AttachmentTooLarge)),
                "[{label}] exceeding the vault-wide budget rejected");
            assert!(add(&conn, "att-budget", "fits.bin", None, b"12345", 1).is_ok(),
                "[{label}] exactly filling the budget accepted");
        }
    }

    #[test]
    fn list_omits_data_get_returns_it_delete_removes() {
        for (label, conn) in both_dbs() {
            crate::testutil::seed_entry(&conn, "att-e2", "E2", 0);
            let m = add(&conn, "att-e2", "f.txt", None, b"bytes", 1).unwrap();
            let metas = list(&conn, "att-e2").unwrap();
            assert_eq!(metas.len(), 1, "[{label}] listed");
            let full = get(&conn, &m.id).unwrap();
            assert_eq!(full.data, b"bytes", "[{label}] get returns data");
            delete(&conn, &m.id).unwrap();
            assert!(list(&conn, "att-e2").unwrap().is_empty(), "[{label}] deleted");
            assert!(matches!(get(&conn, &m.id), Err(VaultError::AttachmentNotFound)), "[{label}] gone -> NotFound");
        }
    }

    #[test]
    fn mime_round_trips_both_ways() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "att-mime", "Mime", 0);

            let with_mime = add(&conn, "att-mime", "img.png", Some("image/png"), b"png-bytes", 1).unwrap();
            let fetched = get(&conn, &with_mime.id).unwrap();
            assert_eq!(fetched.meta.mime_type.as_deref(), Some("image/png"), "[{label}] mime_type round-trips Some");

            let without_mime = add(&conn, "att-mime", "blob.bin", None, b"raw-bytes", 2).unwrap();
            let fetched2 = get(&conn, &without_mime.id).unwrap();
            assert_eq!(fetched2.meta.mime_type, None, "[{label}] mime_type round-trips None");
        }
    }

    #[test]
    fn list_scopes_by_entry() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "att-a", "A", 0);
            seed_entry(&conn, "att-b", "B", 0);
            let a = add(&conn, "att-a", "a.txt", None, b"aaa", 1).unwrap();
            add(&conn, "att-b", "b.txt", None, b"bbb", 1).unwrap();

            let list_a = list(&conn, "att-a").unwrap();
            assert_eq!(list_a.len(), 1, "[{label}] only A's attachment listed");
            assert_eq!(list_a[0].id, a.id, "[{label}] listed attachment is A's, not B's");
        }
    }

    #[test]
    fn get_preserves_binary_data_exactly() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "att-bin", "Bin", 0);
            let bytes = vec![0x00u8, 0xFFu8, 0x00u8];
            let m = add(&conn, "att-bin", "bin.dat", None, &bytes, 1).unwrap();
            let fetched = get(&conn, &m.id).unwrap();
            assert_eq!(fetched.data, bytes, "[{label}] binary data (incl. 0x00/0xFF bytes) round-trips byte-identical");
        }
    }

    #[test]
    fn delete_missing_id_returns_not_found() {
        for (label, conn) in both_dbs() {
            assert!(matches!(delete(&conn, "ghost"), Err(VaultError::AttachmentNotFound)), "[{label}] missing id -> AttachmentNotFound");
        }
    }
}
