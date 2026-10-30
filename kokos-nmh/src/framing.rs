//! Chrome/Firefox native-messaging framing: `[u32 length, platform byte
//! order][UTF-8 JSON]`. The 1 MiB cap is enforced on BOTH
//! directions: the length prefix is checked BEFORE allocating, so a hostile
//! prefix cannot make the host reserve gigabytes.

use std::io::{self, Read, Write};

/// Chrome's per-message limit; also our own outbound limit.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Reads one frame. `Ok(None)` = clean EOF (the browser closed the port),
/// which is the normal shutdown signal — not an error.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_ne_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {MAX_FRAME} byte limit"),
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Writes one frame, flushing so the browser sees it immediately.
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "response of {} bytes exceeds the {MAX_FRAME} byte limit",
                payload.len()
            ),
        ));
    }
    w.write_all(&(payload.len() as u32).to_ne_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_frame_is_the_one_mib_the_protocol_mandates() {
        assert_eq!(
            MAX_FRAME,
            1024 * 1024,
            "the frame cap is 1 MiB in both directions; it is part of the wire contract, not a tunable"
        );
    }

    #[test]
    fn round_trip_one_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, br#"{"id":"a"}"#).unwrap();
        assert_eq!(
            &buf[..4],
            &(10u32).to_ne_bytes(),
            "length prefix is 4 bytes, platform byte order"
        );
        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(read_frame(&mut cursor).unwrap().unwrap(), br#"{"id":"a"}"#);
    }

    #[test]
    fn two_frames_read_in_order() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"one").unwrap();
        write_frame(&mut buf, b"two").unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(read_frame(&mut cursor).unwrap().unwrap(), b"one");
        assert_eq!(read_frame(&mut cursor).unwrap().unwrap(), b"two");
        assert!(
            read_frame(&mut cursor).unwrap().is_none(),
            "clean EOF -> None, not an error"
        );
    }

    #[test]
    fn truncated_body_is_an_error_not_a_short_frame() {
        let mut buf = (5u32).to_ne_bytes().to_vec();
        buf.extend_from_slice(b"ab");
        let mut cursor = std::io::Cursor::new(buf);
        assert!(read_frame(&mut cursor).is_err());
    }

    #[test]
    fn oversize_length_prefix_is_rejected_without_allocating() {
        let mut buf = ((MAX_FRAME + 1) as u32).to_ne_bytes().to_vec();
        buf.extend_from_slice(b"x");
        let mut cursor = std::io::Cursor::new(buf);
        let e = read_frame(&mut cursor).expect_err("over the 1 MiB cap must fail");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn writing_over_the_cap_is_rejected() {
        let big = vec![b'x'; MAX_FRAME + 1];
        let mut buf = Vec::new();
        assert!(write_frame(&mut buf, &big).is_err());
        assert!(
            buf.is_empty(),
            "nothing must be written when the payload is refused"
        );
    }
}
