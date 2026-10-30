use flate2::read::GzDecoder;
#[cfg(feature = "save_kdbx4")]
use flate2::write::GzEncoder;
#[cfg(feature = "save_kdbx4")]
use flate2::Compression as Flate2Compression;
use std::io::Read;
#[cfg(feature = "save_kdbx4")]
use std::io::Write;

/// Kokos patch: upper bound on decompressed database payload size.
const MAX_DECOMPRESSED_SIZE: u64 = 1024 * 1024 * 1024;

pub trait Compression {
    #[cfg(feature = "save_kdbx4")]
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error>;
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error>;
}

pub struct NoCompression;

impl Compression for NoCompression {
    #[cfg(feature = "save_kdbx4")]
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        Ok(in_buffer.to_vec())
    }
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        Ok(in_buffer.to_vec())
    }
}

pub struct GZipCompression;

impl Compression for GZipCompression {
    #[cfg(feature = "save_kdbx4")]
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut res = Vec::new();
        let mut encoder = GzEncoder::new(&mut res, Flate2Compression::default());
        encoder.write_all(in_buffer)?;
        encoder.flush()?;
        encoder.finish()?;
        Ok(res)
    }
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut res = Vec::new();
        // Kokos patch: cap inflated output so a gzip bomb fails with an error
        // instead of exhausting memory and aborting the process.
        GzDecoder::new(in_buffer)
            .take(MAX_DECOMPRESSED_SIZE + 1)
            .read_to_end(&mut res)?;
        if res.len() as u64 > MAX_DECOMPRESSED_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed payload exceeds size limit",
            ));
        }
        Ok(res)
    }
}
