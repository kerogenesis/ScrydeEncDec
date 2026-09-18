use crate::error::{AppError, Result};
use crate::gamekit::{
    HEADER_111_FULL, HEADER_120_FULL, HEADER_121_FULL, HEADER_211_FULL, HEADER_212_FULL,
    HEADER_413_FULL,
};
use cipher::KeyInit;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use num_bigint::BigUint;
use obfstr::obfstr;
use std::io::{Read, Write};
use std::sync::LazyLock;

pub const KEY_211: [u8; 8] = [0x1E, 0x52, 0x46, 0xF9, 0x96, 0x10, 0xCD, 0x33];
pub const KEY_212: [u8; 8] = [0x42, 0xC1, 0x36, 0xE6, 0x6C, 0x1F, 0x68, 0xE6];

pub const RSA_MODULUS_KEY1: [u8; 128] = [
    0x39, 0x20, 0xae, 0x94, 0x60, 0xc6, 0xd4, 0x13, 0x64, 0xd2, 0x93, 0xaa, 0xa3, 0xc6, 0xa4, 0xc3,
    0x67, 0xae, 0x69, 0xd0, 0xb3, 0xc3, 0x67, 0xb5, 0xab, 0x81, 0x88, 0x10, 0xd2, 0xf1, 0x7a, 0x70,
    0xe3, 0x5d, 0x20, 0xae, 0x5b, 0xb6, 0x7b, 0xd8, 0x04, 0x56, 0xc8, 0x67, 0xc2, 0x29, 0x01, 0x07,
    0x19, 0x93, 0x30, 0x43, 0xfa, 0xed, 0x79, 0x46, 0x3e, 0x2f, 0xc0, 0xb1, 0x4e, 0x43, 0xd9, 0x1f,
    0xfd, 0x9b, 0xf6, 0x83, 0x0a, 0x89, 0xc0, 0x72, 0x7d, 0x5d, 0xc5, 0x95, 0x34, 0x32, 0x16, 0x8f,
    0xc1, 0xa5, 0xb1, 0x7b, 0xc8, 0x91, 0xce, 0xa1, 0x3d, 0x65, 0xb3, 0x88, 0x62, 0x44, 0x93, 0x55,
    0x63, 0x57, 0x87, 0x9b, 0xaf, 0x6d, 0x55, 0x89, 0xe2, 0xb1, 0xb8, 0x55, 0xfc, 0x09, 0x2e, 0x3d,
    0xf4, 0x69, 0x58, 0x12, 0xcf, 0x1a, 0x8a, 0x06, 0x44, 0x65, 0x01, 0x5c, 0xde, 0xd6, 0xb4, 0x75,
];

pub const RSA_MODULUS_KEY2: [u8; 128] = [
    0x83, 0x2d, 0xd7, 0x8f, 0x66, 0xc1, 0x3d, 0x12, 0x38, 0xdc, 0x89, 0x6a, 0xa8, 0xba, 0x51, 0x45,
    0x74, 0xc5, 0x9b, 0xd0, 0x11, 0x05, 0xd4, 0x14, 0x93, 0x74, 0xb6, 0x67, 0x78, 0x8f, 0xe6, 0x50,
    0xe4, 0x3c, 0x08, 0x29, 0xe3, 0x4b, 0x8d, 0xc0, 0xb7, 0x5e, 0xb4, 0xf2, 0x9e, 0x7d, 0xa6, 0xc9,
    0x02, 0x3a, 0x79, 0x81, 0x38, 0x63, 0x55, 0x86, 0x60, 0x03, 0x1d, 0xb7, 0xa0, 0xc0, 0x2c, 0xe7,
    0xbd, 0xd7, 0xb5, 0xe5, 0xdd, 0xd1, 0x3e, 0x4d, 0x27, 0xea, 0x6e, 0xbe, 0x03, 0x7d, 0x41, 0xb6,
    0x50, 0x88, 0xa1, 0x94, 0x73, 0x6e, 0xe4, 0x75, 0x01, 0xf9, 0x9e, 0xda, 0x2d, 0x29, 0x19, 0xfc,
    0x3c, 0x4c, 0x6e, 0x1c, 0xbc, 0x29, 0xe8, 0xd6, 0xe1, 0x8a, 0x8a, 0xa3, 0x61, 0x16, 0xef, 0x0f,
    0x2f, 0x17, 0x8d, 0x7e, 0xd1, 0x0c, 0x0a, 0xef, 0x37, 0xf7, 0xdd, 0x72, 0x84, 0x39, 0xdf, 0x97,
];

pub const RSA_PRIVATE_EXPONENT_KEY1: [u8; 128] = [
    0x65, 0xde, 0xc1, 0x81, 0x50, 0x95, 0x1e, 0xc9, 0x3e, 0x22, 0xdb, 0xc7, 0x16, 0xb8, 0x2d, 0x6f,
    0xfc, 0xe2, 0x46, 0xf7, 0x53, 0x85, 0xa2, 0x5c, 0xfe, 0x5d, 0xad, 0x18, 0x76, 0x95, 0xa1, 0x31,
    0xb6, 0xc1, 0x93, 0xd4, 0xcb, 0x62, 0x15, 0x8c, 0x9a, 0xda, 0x6d, 0x3a, 0x25, 0xa7, 0x43, 0x4e,
    0xf0, 0xc2, 0x14, 0x1c, 0x3d, 0xfe, 0xc6, 0x63, 0x82, 0x1f, 0x54, 0xae, 0xd9, 0x43, 0x10, 0x83,
    0x4d, 0xb3, 0x77, 0x0a, 0xe1, 0x2f, 0x35, 0xd7, 0x9d, 0x90, 0xf0, 0x72, 0xf2, 0x0b, 0xdd, 0x4c,
    0x12, 0x5f, 0x1d, 0x9d, 0x64, 0xd2, 0x43, 0x66, 0xb8, 0x32, 0x7f, 0xa2, 0xfc, 0xf8, 0x07, 0x6a,
    0x4c, 0x50, 0x5b, 0x40, 0xc4, 0xe6, 0xd3, 0x38, 0x78, 0x1d, 0x29, 0x00, 0xe4, 0x76, 0x97, 0x71,
    0x1e, 0x84, 0x8e, 0x3c, 0x06, 0x75, 0x5c, 0x14, 0x86, 0x70, 0xd4, 0x98, 0xd7, 0xc2, 0xb4, 0x30,
];

static MODULUS_KEY1: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::from_bytes_le(&RSA_MODULUS_KEY1));
static MODULUS_KEY2: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::from_bytes_le(&RSA_MODULUS_KEY2));
static EXPONENT_29: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(29u32));
static EXPONENT_53: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(53u32));
static PRIVATE_MODULUS_KEY1: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::from_bytes_le(&RSA_MODULUS_KEY1));
static PRIVATE_EXPONENT_KEY1: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::from_bytes_le(&RSA_PRIVATE_EXPONENT_KEY1));

fn transform_bytes(
    payload: &[u8],
    on_progress: Option<&dyn Fn(usize, usize)>,
    mut f: impl FnMut(usize, u8) -> u8,
) -> Vec<u8> {
    let total = payload.len();
    if total == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(total);
    for (i, &b) in payload.iter().enumerate() {
        if let Some(cb) = on_progress
            && (i % 8192 == 0 || i == total - 1)
        {
            cb(i + 1, total);
        }
        out.push(f(i, b));
    }
    out
}

pub fn decrypt_111(payload: &[u8], on_progress: Option<&dyn Fn(usize, usize)>) -> Vec<u8> {
    transform_bytes(payload, on_progress, |_, b| b ^ 0xAC)
}

pub fn encrypt_111(plaintext: &[u8], on_progress: Option<&dyn Fn(usize, usize)>) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_111_FULL.len() + plaintext.len());
    out.extend_from_slice(HEADER_111_FULL);
    out.extend(decrypt_111(plaintext, on_progress));
    out
}

fn key_120_byte(i: usize) -> u8 {
    let a1 = (i + 230) as u32;
    let key_low = ((a1 ^ (a1 >> 8)) & 0x0F) as u8;
    let key_high = ((((a1 >> 4) ^ (a1 >> 12)) & 0x0F) << 4) as u8;
    key_low | key_high
}

pub fn decrypt_120(payload: &[u8], on_progress: Option<&dyn Fn(usize, usize)>) -> Vec<u8> {
    transform_bytes(payload, on_progress, |i, b| b ^ key_120_byte(i))
}

pub fn encrypt_120(plaintext: &[u8], on_progress: Option<&dyn Fn(usize, usize)>) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_120_FULL.len() + plaintext.len());
    out.extend_from_slice(HEADER_120_FULL);
    out.extend(decrypt_120(plaintext, on_progress));
    out
}

pub fn key_121_from_filename(filename: &str) -> u8 {
    let sum: u32 = filename
        .bytes()
        .map(|b| b.to_ascii_lowercase() as u32)
        .sum();
    (sum & 0xFF) as u8
}

const MAGIC_121_VTX: [u8; 4] = [0xC1, 0x83, 0x2A, 0x9E];
const MAGIC_121_OGG: [u8; 4] = *b"OggS";
const MAGIC_121_L2SD: [u8; 4] = *b"L2SD";

pub fn decrypt_121(
    payload: &[u8],
    filename: &str,
    on_progress: Option<&dyn Fn(usize, usize)>,
) -> Vec<u8> {
    let is_bmp = filename.to_ascii_lowercase().ends_with(".bmp");
    let found_key = (payload.len() >= 4)
        .then(|| {
            (0..=255u8).find(|&candidate| {
                let p0 = payload[0] ^ candidate;
                let p1 = payload[1] ^ candidate;
                let p2 = payload[2] ^ candidate;
                let p3 = payload[3] ^ candidate;
                [p0, p1, p2, p3] == MAGIC_121_VTX
                    || [p0, p1, p2, p3] == MAGIC_121_OGG
                    || [p0, p1, p2, p3] == MAGIC_121_L2SD
                    || (is_bmp && p0 == b'B' && p1 == b'M')
            })
        })
        .flatten();
    let key = found_key.unwrap_or_else(|| key_121_from_filename(filename));
    transform_bytes(payload, on_progress, |_, b| b ^ key)
}

pub fn encrypt_121(
    plaintext: &[u8],
    filename: &str,
    on_progress: Option<&dyn Fn(usize, usize)>,
) -> Vec<u8> {
    let key = key_121_from_filename(filename);
    let mut out = Vec::with_capacity(HEADER_121_FULL.len() + plaintext.len());
    out.extend_from_slice(HEADER_121_FULL);
    out.extend(transform_bytes(plaintext, on_progress, |_, b| b ^ key));
    out
}

pub fn decrypt_211(payload: &[u8], on_progress: Option<&dyn Fn(usize, usize)>) -> Vec<u8> {
    transform_bytes(payload, on_progress, |i, b| b ^ KEY_211[i % 8])
}

pub fn encrypt_211(plaintext: &[u8], on_progress: Option<&dyn Fn(usize, usize)>) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_211_FULL.len() + plaintext.len());
    out.extend_from_slice(HEADER_211_FULL);
    out.extend(decrypt_211(plaintext, on_progress));
    out
}

pub fn decrypt_212(payload: &[u8], on_progress: Option<&dyn Fn(usize, usize)>) -> Vec<u8> {
    transform_bytes(payload, on_progress, |i, b| b ^ KEY_212[i % 8])
}

pub fn encrypt_212(plaintext: &[u8], on_progress: Option<&dyn Fn(usize, usize)>) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_212_FULL.len() + plaintext.len());
    out.extend_from_slice(HEADER_212_FULL);
    out.extend(decrypt_212(plaintext, on_progress));
    out
}

fn rsa_modpow(block: &[u8; 128], modulus: &BigUint, exponent: &BigUint) -> [u8; 128] {
    let base = BigUint::from_bytes_be(block);
    let result = base.modpow(exponent, modulus);
    let res_bytes = result.to_bytes_be();
    let mut out = [0u8; 128];
    if res_bytes.len() <= 128 {
        let offset = 128 - res_bytes.len();
        out[offset..].copy_from_slice(&res_bytes);
    }
    out
}

fn align_413_chunk_size(size: usize) -> usize {
    (size + 3) & !3
}

fn decoded_413_chunk_payload(block: &[u8; 128], chunk_size: usize) -> Option<&[u8]> {
    if chunk_size == 0 || chunk_size > 124 {
        return None;
    }
    let aligned_size = align_413_chunk_size(chunk_size);
    let start = 128usize.checked_sub(aligned_size)?;
    Some(&block[start..start + chunk_size])
}

fn decompress_413_payload(reconstructed_zlib: &[u8]) -> Option<Vec<u8>> {
    if reconstructed_zlib.len() <= 4 {
        return None;
    }
    let expected_size = u32::from_le_bytes([
        reconstructed_zlib[0],
        reconstructed_zlib[1],
        reconstructed_zlib[2],
        reconstructed_zlib[3],
    ]) as usize;
    let mut zlib_decoder = ZlibDecoder::new(&reconstructed_zlib[4..]);
    let mut decompressed = Vec::with_capacity(expected_size);
    if zlib_decoder.read_to_end(&mut decompressed).is_ok() && decompressed.len() == expected_size {
        Some(decompressed)
    } else {
        None
    }
}

fn try_rsa_key(
    payload: &[u8],
    block_count: usize,
    exponent: &BigUint,
    modulus: &BigUint,
    on_progress: Option<&dyn Fn(usize, usize)>,
) -> Option<Vec<u8>> {
    let mut reconstructed_zlib = Vec::with_capacity(block_count * 124);
    for idx in 0..block_count {
        if let Some(cb) = on_progress {
            cb(idx + 1, block_count);
        }
        let chunk = payload.get(idx * 128..(idx + 1) * 128)?;
        let block_arr: &[u8; 128] = chunk.try_into().ok()?;
        let decrypted_block = rsa_modpow(block_arr, modulus, exponent);
        let chunk_size = u32::from_be_bytes([
            decrypted_block[0],
            decrypted_block[1],
            decrypted_block[2],
            decrypted_block[3],
        ]) as usize;
        let is_last = idx == block_count - 1;
        if (!is_last && chunk_size != 124) || chunk_size > 124 {
            return None;
        }
        if chunk_size == 0 {
            continue;
        }
        let chunk_payload = decoded_413_chunk_payload(&decrypted_block, chunk_size)?;
        reconstructed_zlib.extend_from_slice(chunk_payload);
    }
    decompress_413_payload(&reconstructed_zlib)
}

fn try_blowfish_key(payload: &[u8], bf_key: &[u8]) -> Option<Vec<u8>> {
    let aligned_len = payload.len() - (payload.len() % 8);
    if aligned_len < 8 {
        return None;
    }
    let cipher = blowfish::Blowfish::<byteorder::BE>::new_from_slice(bf_key).ok()?;
    let mut decrypted = payload[..aligned_len].to_vec();
    for chunk in decrypted.as_chunks_mut::<8>().0 {
        let mut block = cipher::Block::<blowfish::Blowfish<byteorder::BE>>::default();
        block.copy_from_slice(chunk);
        cipher::BlockCipherDecrypt::decrypt_block(&cipher, &mut block);
        chunk.copy_from_slice(&block);
    }
    decompress_413_payload(&decrypted)
}

pub fn decrypt_413(payload: &[u8], on_progress: Option<&dyn Fn(usize, usize)>) -> Result<Vec<u8>> {
    if payload.is_empty() {
        return Err(AppError::InvalidHeader);
    }
    if payload.len() >= 128 {
        let block_count = payload.len() / 128;
        for (exponent, modulus) in [(&EXPONENT_29, &MODULUS_KEY1), (&EXPONENT_53, &MODULUS_KEY2)] {
            if let Some(decompressed) =
                try_rsa_key(payload, block_count, exponent, modulus, on_progress)
            {
                return Ok(decompressed);
            }
        }
    }
    if let Some(decompressed) =
        try_blowfish_key(payload, &[0x59, 0x3B, 0x5D, 0x2C, 0x47, 0x74, 0x3D, 0x31])
    {
        return Ok(decompressed);
    }
    if let Some(decompressed) = try_blowfish_key(payload, obfstr!("Lineage2").as_bytes()) {
        return Ok(decompressed);
    }
    Err(AppError::DecompressionFailed)
}

pub fn encrypt_413(
    plaintext: &[u8],
    on_progress: Option<&dyn Fn(usize, usize)>,
) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plaintext)?;
    let compressed = encoder.finish()?;
    let mut stream = Vec::with_capacity(4 + compressed.len());
    stream.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    stream.extend_from_slice(&compressed);
    let chunk_count = stream.len().div_ceil(124);
    let total_size = HEADER_413_FULL.len() + 128 * chunk_count + 20;
    let mut out = vec![0u8; total_size];
    out[..HEADER_413_FULL.len()].copy_from_slice(HEADER_413_FULL);
    for (i, chunk) in stream.chunks(124).enumerate() {
        if let Some(cb) = on_progress {
            cb(i + 1, chunk_count);
        }
        let mut block = [0u8; 128];
        let size = chunk.len();
        if i == chunk_count - 1 {
            let aligned = align_413_chunk_size(size);
            let start = 128usize.checked_sub(aligned).unwrap();
            block[start..start + size].copy_from_slice(chunk);
        } else {
            block[4..4 + size].copy_from_slice(chunk);
        }
        block[..4].copy_from_slice(&(size as u32).to_be_bytes());
        let encrypted = rsa_modpow(&block, &PRIVATE_MODULUS_KEY1, &PRIVATE_EXPONENT_KEY1);
        out[HEADER_413_FULL.len() + i * 128..HEADER_413_FULL.len() + (i + 1) * 128]
            .copy_from_slice(&encrypted);
    }
    let crc = crc32fast::hash(&out[..total_size - 20]);
    out[total_size - 8..total_size - 4].copy_from_slice(&crc.to_le_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_413_roundtrip() {
        let plain = b"Test payload for ver413 roundtrip verification. ".repeat(20);
        let encrypted = encrypt_413(&plain, None).expect("encryption failed");
        assert!(encrypted.starts_with(HEADER_413_FULL));
        let decrypted =
            decrypt_413(&encrypted[HEADER_413_FULL.len()..], None).expect("decryption failed");
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn encrypt_120_known_keys() {
        let encrypted = encrypt_120(&[0u8; 27], None);
        assert!(encrypted.starts_with(HEADER_120_FULL));
        let payload = &encrypted[HEADER_120_FULL.len()..];
        let expected: Vec<u8> = (230..=255u32).map(|v| v as u8).chain([0x01]).collect();
        assert_eq!(
            payload,
            expected.as_slice(),
            "key schedule must match expected ver120 transformation"
        );
        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let enc = encrypt_120(plaintext, None);
        assert!(enc.starts_with(HEADER_120_FULL));
        assert_eq!(decrypt_120(&enc[28..], None).as_slice(), plaintext);
    }

    #[test]
    fn decrypt_121_magic_vtx_and_bm() {
        for (magic, filename) in [
            (MAGIC_121_VTX.as_slice(), "texture.utx"),
            (b"BM".as_slice(), "bitmap.bmp"),
        ] {
            let mut plain = magic.to_vec();
            plain.extend_from_slice(b"sample_data");
            let enc = encrypt_121(&plain, filename, None);
            assert!(enc.starts_with(HEADER_121_FULL));
            assert_eq!(
                decrypt_121(&enc[28..], filename, None).as_slice(),
                plain.as_slice()
            );
        }
    }

    #[test]
    fn decrypt_121_bm_false_positive_prevention() {
        let payload = vec![0x10, 0x1F, 0x00, 0x00, 0xAA, 0xBB];
        let dec_non_bmp = decrypt_121(&payload, "codec.utx", None);
        let expected_key = key_121_from_filename("codec.utx");
        let expected_dec: Vec<u8> = payload.iter().map(|b| b ^ expected_key).collect();
        assert_eq!(dec_non_bmp, expected_dec);
    }

    #[test]
    fn decrypt_413_blowfish_fallback() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let plain = b"Blowfish 413 fallback test plaintext data!";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut stream = Vec::new();
        stream.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        stream.extend_from_slice(&compressed);

        while stream.len() % 8 != 0 {
            stream.push(0);
        }

        let bf_key = b"Lineage2";
        let cipher = blowfish::Blowfish::<byteorder::BE>::new_from_slice(bf_key).unwrap();
        let mut encrypted = stream.clone();
        for chunk in encrypted.as_chunks_mut::<8>().0 {
            let mut block = cipher::Block::<blowfish::Blowfish<byteorder::BE>>::default();
            block.copy_from_slice(chunk);
            cipher::BlockCipherEncrypt::encrypt_block(&cipher, &mut block);
            chunk.copy_from_slice(&block);
        }

        let decrypted = decrypt_413(&encrypted, None).expect("Blowfish 413 fallback failed");
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn decrypt_121_fallback_uses_filename_key() {
        let plain = b"HelloWorld-no-magic-head";
        let enc = encrypt_121(plain, "OggS.tar", None);
        assert_eq!(decrypt_121(&enc[28..], "OggS.tar", None).as_slice(), plain);
    }

    #[test]
    fn decrypt_121_key_zero_is_not_fallback() {
        let payload = b"OggS-zero-key";
        let dec = decrypt_121(payload, "OggS.tar", None);
        assert_eq!(dec.as_slice(), payload);
    }

    #[test]
    fn encrypt_121_known_vector() {
        let enc = encrypt_121(b"OggS", "OggS.tar", None);
        assert_eq!(&enc[..28], HEADER_121_FULL);
        assert_eq!(&enc[28..], &[0x6A, 0x42, 0x42, 0x76]);
    }

    #[test]
    fn encrypt_211_212_roundtrip() {
        let plain = b"some 211/212 test payload, not a real format, just a round-trip: 0123456789";
        let enc211 = encrypt_211(plain, None);
        assert!(enc211.starts_with(HEADER_211_FULL));
        assert_eq!(decrypt_211(&enc211[28..], None).as_slice(), plain);
        let enc212 = encrypt_212(plain, None);
        assert!(enc212.starts_with(HEADER_212_FULL));
        assert_eq!(decrypt_212(&enc212[28..], None).as_slice(), plain);
    }

    #[test]
    fn encrypt_111_roundtrip() {
        let plain = b"111 payload round-trip";
        let enc = encrypt_111(plain, None);
        assert!(enc.starts_with(HEADER_111_FULL));
        assert_eq!(decrypt_111(&enc[28..], None).as_slice(), plain);
    }
}
