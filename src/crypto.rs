use crate::error::{AppError, Result};
use crate::gamekit::{HEADER_111, HEADER_120, HEADER_121, HEADER_211, HEADER_212, HEADER_413};
use cipher::KeyInit;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use num_bigint::BigUint;
use obfstr::obfstr;
use std::io::{Read, Write};
use std::sync::LazyLock;

pub const XOR_KEY_211: [u8; 8] = [0x1E, 0x52, 0x46, 0xF9, 0x96, 0x10, 0xCD, 0x33];
pub const XOR_KEY_212: [u8; 8] = [0x42, 0xC1, 0x36, 0xE6, 0x6C, 0x1F, 0x68, 0xE6];

pub const RSA_MODULUS_L2ENCDEC: [u8; 128] = [
    0x39, 0x20, 0xae, 0x94, 0x60, 0xc6, 0xd4, 0x13, 0x64, 0xd2, 0x93, 0xaa, 0xa3, 0xc6, 0xa4, 0xc3,
    0x67, 0xae, 0x69, 0xd0, 0xb3, 0xc3, 0x67, 0xb5, 0xab, 0x81, 0x88, 0x10, 0xd2, 0xf1, 0x7a, 0x70,
    0xe3, 0x5d, 0x20, 0xae, 0x5b, 0xb6, 0x7b, 0xd8, 0x04, 0x56, 0xc8, 0x67, 0xc2, 0x29, 0x01, 0x07,
    0x19, 0x93, 0x30, 0x43, 0xfa, 0xed, 0x79, 0x46, 0x3e, 0x2f, 0xc0, 0xb1, 0x4e, 0x43, 0xd9, 0x1f,
    0xfd, 0x9b, 0xf6, 0x83, 0x0a, 0x89, 0xc0, 0x72, 0x7d, 0x5d, 0xc5, 0x95, 0x34, 0x32, 0x16, 0x8f,
    0xc1, 0xa5, 0xb1, 0x7b, 0xc8, 0x91, 0xce, 0xa1, 0x3d, 0x65, 0xb3, 0x88, 0x62, 0x44, 0x93, 0x55,
    0x63, 0x57, 0x87, 0x9b, 0xaf, 0x6d, 0x55, 0x89, 0xe2, 0xb1, 0xb8, 0x55, 0xfc, 0x09, 0x2e, 0x3d,
    0xf4, 0x69, 0x58, 0x12, 0xcf, 0x1a, 0x8a, 0x06, 0x44, 0x65, 0x01, 0x5c, 0xde, 0xd6, 0xb4, 0x75,
];

pub const RSA_MODULUS_413: [u8; 128] = [
    0x83, 0x2d, 0xd7, 0x8f, 0x66, 0xc1, 0x3d, 0x12, 0x38, 0xdc, 0x89, 0x6a, 0xa8, 0xba, 0x51, 0x45,
    0x74, 0xc5, 0x9b, 0xd0, 0x11, 0x05, 0xd4, 0x14, 0x93, 0x74, 0xb6, 0x67, 0x78, 0x8f, 0xe6, 0x50,
    0xe4, 0x3c, 0x08, 0x29, 0xe3, 0x4b, 0x8d, 0xc0, 0xb7, 0x5e, 0xb4, 0xf2, 0x9e, 0x7d, 0xa6, 0xc9,
    0x02, 0x3a, 0x79, 0x81, 0x38, 0x63, 0x55, 0x86, 0x60, 0x03, 0x1d, 0xb7, 0xa0, 0xc0, 0x2c, 0xe7,
    0xbd, 0xd7, 0xb5, 0xe5, 0xdd, 0xd1, 0x3e, 0x4d, 0x27, 0xea, 0x6e, 0xbe, 0x03, 0x7d, 0x41, 0xb6,
    0x50, 0x88, 0xa1, 0x94, 0x73, 0x6e, 0xe4, 0x75, 0x01, 0xf9, 0x9e, 0xda, 0x2d, 0x29, 0x19, 0xfc,
    0x3c, 0x4c, 0x6e, 0x1c, 0xbc, 0x29, 0xe8, 0xd6, 0xe1, 0x8a, 0x8a, 0xa3, 0x61, 0x16, 0xef, 0x0f,
    0x2f, 0x17, 0x8d, 0x7e, 0xd1, 0x0c, 0x0a, 0xef, 0x37, 0xf7, 0xdd, 0x72, 0x84, 0x39, 0xdf, 0x97,
];

pub const RSA_PUBLIC_EXPONENT_L2ENCDEC: [u8; 128] = [
    0x65, 0xde, 0xc1, 0x81, 0x50, 0x95, 0x1e, 0xc9, 0x3e, 0x22, 0xdb, 0xc7, 0x16, 0xb8, 0x2d, 0x6f,
    0xfc, 0xe2, 0x46, 0xf7, 0x53, 0x85, 0xa2, 0x5c, 0xfe, 0x5d, 0xad, 0x18, 0x76, 0x95, 0xa1, 0x31,
    0xb6, 0xc1, 0x93, 0xd4, 0xcb, 0x62, 0x15, 0x8c, 0x9a, 0xda, 0x6d, 0x3a, 0x25, 0xa7, 0x43, 0x4e,
    0xf0, 0xc2, 0x14, 0x1c, 0x3d, 0xfe, 0xc6, 0x63, 0x82, 0x1f, 0x54, 0xae, 0xd9, 0x43, 0x10, 0x83,
    0x4d, 0xb3, 0x77, 0x0a, 0xe1, 0x2f, 0x35, 0xd7, 0x9d, 0x90, 0xf0, 0x72, 0xf2, 0x0b, 0xdd, 0x4c,
    0x12, 0x5f, 0x1d, 0x9d, 0x64, 0xd2, 0x43, 0x66, 0xb8, 0x32, 0x7f, 0xa2, 0xfc, 0xf8, 0x07, 0x6a,
    0x4c, 0x50, 0x5b, 0x40, 0xc4, 0xe6, 0xd3, 0x38, 0x78, 0x1d, 0x29, 0x00, 0xe4, 0x76, 0x97, 0x71,
    0x1e, 0x84, 0x8e, 0x3c, 0x06, 0x75, 0x5c, 0x14, 0x86, 0x70, 0xd4, 0x98, 0xd7, 0xc2, 0xb4, 0x30,
];

static MODULUS_L2ENCDEC: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::from_bytes_le(&RSA_MODULUS_L2ENCDEC));
static MODULUS_413: LazyLock<BigUint> = LazyLock::new(|| BigUint::from_bytes_le(&RSA_MODULUS_413));
static PRIVATE_EXPONENT_411: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(29u32));
static PRIVATE_EXPONENT_413: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(53u32));
static PUBLIC_EXPONENT_L2ENCDEC: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::from_bytes_le(&RSA_PUBLIC_EXPONENT_L2ENCDEC));

#[inline]
pub fn xor_111_mut(data: &mut [u8]) {
    for b in data.iter_mut() {
        *b ^= 0xAC;
    }
}

#[inline]
pub fn xor_121_mut(data: &mut [u8], key: u8) {
    for b in data.iter_mut() {
        *b ^= key;
    }
}

#[inline]
pub fn xor_repeating_8byte_mut(data: &mut [u8], key: [u8; 8]) {
    let key_u64 = u64::from_ne_bytes(key);
    let (chunks, rem) = data.as_chunks_mut::<8>();
    for chunk in chunks {
        let val = u64::from_ne_bytes(*chunk);
        *chunk = (val ^ key_u64).to_ne_bytes();
    }
    for (i, b) in rem.iter_mut().enumerate() {
        *b ^= key[i];
    }
}

#[inline]
fn key_120_byte(position: usize) -> u8 {
    let counter = (position + 230) as u32;
    let low = ((counter ^ (counter >> 8)) & 0x0F) as u8;
    let high = ((((counter >> 4) ^ (counter >> 12)) & 0x0F) << 4) as u8;
    low | high
}

pub fn xor_120_mut(data: &mut [u8]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key_120_byte(i);
    }
}

#[inline]
fn encrypt_with_header(
    header: &[u8],
    plaintext: &[u8],
    mut encrypt_in_place: impl FnMut(&mut [u8]),
) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + plaintext.len());
    out.extend_from_slice(header);
    out.extend_from_slice(plaintext);
    encrypt_in_place(&mut out[header.len()..]);
    out
}

#[allow(dead_code)]
pub fn decrypt_111(payload: &[u8]) -> Vec<u8> {
    let mut out = payload.to_vec();
    xor_111_mut(&mut out);
    out
}

pub fn encrypt_111(plaintext: &[u8]) -> Vec<u8> {
    encrypt_with_header(HEADER_111, plaintext, xor_111_mut)
}

#[allow(dead_code)]
pub fn decrypt_120(payload: &[u8]) -> Vec<u8> {
    let mut out = payload.to_vec();
    xor_120_mut(&mut out);
    out
}

pub fn encrypt_120(plaintext: &[u8]) -> Vec<u8> {
    encrypt_with_header(HEADER_120, plaintext, xor_120_mut)
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

pub const RSA_BLOCK_SIZE: usize = 128;
pub const RSA_CHUNK_PAYLOAD_CAPACITY: usize = 124;
pub const RSA_FILE_TRAILER_SIZE: usize = 20;

pub fn resolve_121_key(payload: &[u8], filename: &str) -> u8 {
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
    found_key.unwrap_or_else(|| key_121_from_filename(filename))
}

#[allow(dead_code)]
pub fn decrypt_121(payload: &[u8], filename: &str) -> Vec<u8> {
    let key = resolve_121_key(payload, filename);
    let mut out = payload.to_vec();
    xor_121_mut(&mut out, key);
    out
}

pub fn encrypt_121(plaintext: &[u8], filename: &str) -> Vec<u8> {
    let key = key_121_from_filename(filename);
    encrypt_with_header(HEADER_121, plaintext, |slice| xor_121_mut(slice, key))
}

#[allow(dead_code)]
pub fn decrypt_211(payload: &[u8]) -> Vec<u8> {
    let mut out = payload.to_vec();
    xor_repeating_8byte_mut(&mut out, XOR_KEY_211);
    out
}

pub fn encrypt_211(plaintext: &[u8]) -> Vec<u8> {
    encrypt_with_header(HEADER_211, plaintext, |slice| {
        xor_repeating_8byte_mut(slice, XOR_KEY_211)
    })
}

#[allow(dead_code)]
pub fn decrypt_212(payload: &[u8]) -> Vec<u8> {
    let mut out = payload.to_vec();
    xor_repeating_8byte_mut(&mut out, XOR_KEY_212);
    out
}

pub fn encrypt_212(plaintext: &[u8]) -> Vec<u8> {
    encrypt_with_header(HEADER_212, plaintext, |slice| {
        xor_repeating_8byte_mut(slice, XOR_KEY_212)
    })
}

fn rsa_modpow(
    block: &[u8; RSA_BLOCK_SIZE],
    modulus: &BigUint,
    exponent: &BigUint,
) -> [u8; RSA_BLOCK_SIZE] {
    let base = BigUint::from_bytes_be(block);
    let result = base.modpow(exponent, modulus);
    let res_bytes = result.to_bytes_be();
    let mut out = [0u8; RSA_BLOCK_SIZE];
    if res_bytes.len() <= RSA_BLOCK_SIZE {
        let offset = RSA_BLOCK_SIZE - res_bytes.len();
        out[offset..].copy_from_slice(&res_bytes);
    }
    out
}

fn align_413_chunk_size(size: usize) -> usize {
    (size + 3) & !3
}

fn decoded_413_chunk_payload(block: &[u8; RSA_BLOCK_SIZE], chunk_size: usize) -> Option<&[u8]> {
    if chunk_size == 0 || chunk_size > RSA_CHUNK_PAYLOAD_CAPACITY {
        return None;
    }
    let aligned_size = align_413_chunk_size(chunk_size);
    let start = RSA_BLOCK_SIZE.checked_sub(aligned_size)?;
    Some(&block[start..start + chunk_size])
}

/// Maximum initial buffer pre-allocation to prevent out-of-memory panics
/// on corrupted 32-bit `expected_size` headers (particularly on x86-32 targets).
const MAX_INITIAL_DECOMPRESS_CAPACITY: usize = 32 * 1024 * 1024;

fn decompress_413_payload(reconstructed_zlib: &[u8]) -> Option<Vec<u8>> {
    if reconstructed_zlib.len() <= 4 {
        return None;
    }
    let expected_size = u32::from_le_bytes(reconstructed_zlib[..4].try_into().ok()?) as usize;
    let mut zlib_decoder = ZlibDecoder::new(&reconstructed_zlib[4..]);
    let mut decompressed = Vec::with_capacity(expected_size.min(MAX_INITIAL_DECOMPRESS_CAPACITY));
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
) -> Option<Vec<u8>> {
    let mut reconstructed_zlib = Vec::with_capacity(block_count * RSA_CHUNK_PAYLOAD_CAPACITY);
    for idx in 0..block_count {
        let chunk = payload.get(idx * RSA_BLOCK_SIZE..(idx + 1) * RSA_BLOCK_SIZE)?;
        let block_arr: &[u8; RSA_BLOCK_SIZE] = chunk.try_into().ok()?;
        let decrypted_block = rsa_modpow(block_arr, modulus, exponent);
        let chunk_size = u32::from_be_bytes([
            decrypted_block[0],
            decrypted_block[1],
            decrypted_block[2],
            decrypted_block[3],
        ]) as usize;
        let is_last = idx == block_count - 1;
        if (!is_last && chunk_size != RSA_CHUNK_PAYLOAD_CAPACITY)
            || chunk_size > RSA_CHUNK_PAYLOAD_CAPACITY
        {
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

const BLOWFISH_FALLBACK_KEY_1: [u8; 8] = [0x59, 0x3B, 0x5D, 0x2C, 0x47, 0x74, 0x3D, 0x31]; // "Y;],Gt=1"

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

pub fn decrypt_413(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.is_empty() {
        return Err(AppError::InvalidHeader);
    }
    if payload.len() >= RSA_BLOCK_SIZE {
        let block_count = payload.len() / RSA_BLOCK_SIZE;
        for (exponent, modulus) in [
            (&PRIVATE_EXPONENT_411, &MODULUS_L2ENCDEC),
            (&PRIVATE_EXPONENT_413, &MODULUS_413),
        ] {
            if let Some(decompressed) = try_rsa_key(payload, block_count, exponent, modulus) {
                return Ok(decompressed);
            }
        }
    }
    if let Some(decompressed) = try_blowfish_key(payload, &BLOWFISH_FALLBACK_KEY_1) {
        return Ok(decompressed);
    }
    if let Some(decompressed) = try_blowfish_key(payload, obfstr!("Lineage2").as_bytes()) {
        return Ok(decompressed);
    }
    Err(AppError::DecompressionFailed)
}

pub fn encrypt_413(plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut stream = Vec::with_capacity(4 + (plaintext.len() / 2).max(1024));
    stream.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    let mut encoder = ZlibEncoder::new(stream, Compression::default());
    encoder.write_all(plaintext)?;
    let stream = encoder.finish()?;
    let chunk_count = stream.len().div_ceil(RSA_CHUNK_PAYLOAD_CAPACITY);
    let total_size = HEADER_413.len() + RSA_BLOCK_SIZE * chunk_count + RSA_FILE_TRAILER_SIZE;
    let mut out = vec![0u8; total_size];
    out[..HEADER_413.len()].copy_from_slice(HEADER_413);
    for (i, chunk) in stream.chunks(RSA_CHUNK_PAYLOAD_CAPACITY).enumerate() {
        let mut block = [0u8; RSA_BLOCK_SIZE];
        let size = chunk.len();
        if i == chunk_count - 1 {
            let aligned = align_413_chunk_size(size);
            let start = RSA_BLOCK_SIZE.checked_sub(aligned).unwrap();
            block[start..start + size].copy_from_slice(chunk);
        } else {
            block[4..4 + size].copy_from_slice(chunk);
        }
        block[..4].copy_from_slice(&(size as u32).to_be_bytes());
        let encrypted = rsa_modpow(&block, &MODULUS_L2ENCDEC, &PUBLIC_EXPONENT_L2ENCDEC);
        out[HEADER_413.len() + i * RSA_BLOCK_SIZE..HEADER_413.len() + (i + 1) * RSA_BLOCK_SIZE]
            .copy_from_slice(&encrypted);
    }
    // The 20-byte trailer consists of 12 bytes of padding, a 4-byte CRC32 of the
    // preceding stream written at (total_size - 8 .. total_size - 4), and 4 trailing zeroes.
    let crc = crc32fast::hash(&out[..total_size - RSA_FILE_TRAILER_SIZE]);
    out[total_size - 8..total_size - 4].copy_from_slice(&crc.to_le_bytes());
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_413_roundtrip() {
        let plain = b"Test payload for ver413 roundtrip verification. ".repeat(20);
        let encrypted = encrypt_413(&plain).expect("encryption failed");
        assert!(encrypted.starts_with(HEADER_413));
        let decrypted = decrypt_413(&encrypted[HEADER_413.len()..]).expect("decryption failed");
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn encrypt_120_known_keys() {
        let encrypted = encrypt_120(&[0u8; 27]);
        assert!(encrypted.starts_with(HEADER_120));
        let payload = &encrypted[HEADER_120.len()..];
        let expected: Vec<u8> = (230..=255u32).map(|v| v as u8).chain([0x01]).collect();
        assert_eq!(
            payload,
            expected.as_slice(),
            "key schedule must match expected ver120 transformation"
        );
        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let enc = encrypt_120(plaintext);
        assert!(enc.starts_with(HEADER_120));
        assert_eq!(decrypt_120(&enc[HEADER_120.len()..]).as_slice(), plaintext);
    }

    #[test]
    fn decrypt_121_magic_vtx_and_bm() {
        for (magic, filename) in [
            (MAGIC_121_VTX.as_slice(), "texture.utx"),
            (b"BM".as_slice(), "bitmap.bmp"),
        ] {
            let mut plain = magic.to_vec();
            plain.extend_from_slice(b"sample_data");
            let enc = encrypt_121(&plain, filename);
            assert!(enc.starts_with(HEADER_121));
            assert_eq!(
                decrypt_121(&enc[HEADER_121.len()..], filename).as_slice(),
                plain.as_slice()
            );
        }
    }

    #[test]
    fn decrypt_121_bm_false_positive_prevention() {
        let payload = vec![0x10, 0x1F, 0x00, 0x00, 0xAA, 0xBB];
        let dec_non_bmp = decrypt_121(&payload, "codec.utx");
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

        let decrypted = decrypt_413(&encrypted).expect("Blowfish 413 fallback failed");
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn decrypt_121_fallback_uses_filename_key() {
        let plain = b"HelloWorld-no-magic-head";
        let enc = encrypt_121(plain, "OggS.tar");
        assert_eq!(
            decrypt_121(&enc[HEADER_121.len()..], "OggS.tar").as_slice(),
            plain
        );
    }

    #[test]
    fn decrypt_121_key_zero_is_not_fallback() {
        let payload = b"OggS-zero-key";
        let dec = decrypt_121(payload, "OggS.tar");
        assert_eq!(dec.as_slice(), payload);
    }

    #[test]
    fn encrypt_121_known_vector() {
        let enc = encrypt_121(b"OggS", "OggS.tar");
        assert_eq!(&enc[..HEADER_121.len()], HEADER_121);
        assert_eq!(&enc[HEADER_121.len()..], &[0x6A, 0x42, 0x42, 0x76]);
    }

    #[test]
    fn encrypt_211_212_roundtrip() {
        let plain = b"some 211/212 test payload, not a real format, just a round-trip: 0123456789";
        let enc211 = encrypt_211(plain);
        assert!(enc211.starts_with(HEADER_211));
        assert_eq!(decrypt_211(&enc211[HEADER_211.len()..]).as_slice(), plain);
        let enc212 = encrypt_212(plain);
        assert!(enc212.starts_with(HEADER_212));
        assert_eq!(decrypt_212(&enc212[HEADER_212.len()..]).as_slice(), plain);
    }

    #[test]
    fn encrypt_111_roundtrip() {
        let plain = b"111 payload round-trip";
        let enc = encrypt_111(plain);
        assert!(enc.starts_with(HEADER_111));
        assert_eq!(decrypt_111(&enc[HEADER_111.len()..]).as_slice(), plain);
    }
}
