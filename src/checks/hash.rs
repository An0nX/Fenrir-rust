// fenrir-rust/src/checks/hash.rs

use crate::config::Config;
use crate::errors::{FenrirError, Result}; // Исправлен порядок
use crate::ioc::IocCollection;
// Возвращаем импорты макросов
use crate::{log_debug, log_warn};
use hex;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

const HASH_BUFFER_SIZE: usize = 8192;

// --- Manual Hash Implementations ---
// NOTE: These are NOT recommended for production use. Use vetted crypto libraries.
#[allow(non_snake_case)] // Allow constants like H0, T, K
mod md5_impl {
    const S: [[u32; 4]; 4] = [
        [7, 12, 17, 22],
        [5, 9, 14, 20],
        [4, 11, 16, 23],
        [6, 10, 15, 21],
    ];
    const T: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    const H0: u32 = 0x67452301;
    const H1: u32 = 0xefcdab89;
    const H2: u32 = 0x98badcfe;
    const H3: u32 = 0x10325476;
    pub struct Md5State {
        h: [u32; 4],
        buffer: [u8; 64],
        buffer_len: usize,
        total_len: u64,
    }
    impl Md5State {
        pub fn new() -> Self {
            Md5State {
                h: [H0, H1, H2, H3],
                buffer: [0; 64],
                buffer_len: 0,
                total_len: 0,
            }
        }
        pub fn update(&mut self, data: &[u8]) {
            self.total_len = self.total_len.wrapping_add(data.len() as u64);
            let mut data_idx = 0;
            if self.buffer_len > 0 {
                let space_left = 64 - self.buffer_len;
                let fill_len = std::cmp::min(space_left, data.len());
                self.buffer[self.buffer_len..self.buffer_len + fill_len]
                    .copy_from_slice(&data[..fill_len]);
                self.buffer_len += fill_len;
                data_idx += fill_len;
                if self.buffer_len == 64 {
                    let buffer_copy = self.buffer;
                    self.process_block(&buffer_copy);
                    self.buffer_len = 0;
                }
            }
            while data.len() - data_idx >= 64 {
                self.process_block(&data[data_idx..data_idx + 64]);
                data_idx += 64;
            }
            let remaining_len = data.len() - data_idx;
            if remaining_len > 0 {
                self.buffer[..remaining_len].copy_from_slice(&data[data_idx..]);
                self.buffer_len = remaining_len;
            }
        }
        pub fn finalize(mut self) -> [u8; 16] {
            let total_bits = self.total_len.wrapping_mul(8);
            self.buffer[self.buffer_len] = 0x80;
            self.buffer_len += 1;
            if self.buffer_len > 56 {
                for i in self.buffer_len..64 {
                    self.buffer[i] = 0;
                }
                let buffer_copy = self.buffer;
                self.process_block(&buffer_copy);
                self.buffer_len = 0;
            }
            for i in self.buffer_len..56 {
                self.buffer[i] = 0;
            }
            self.buffer[56..64].copy_from_slice(&total_bits.to_le_bytes());
            let buffer_copy = self.buffer;
            self.process_block(&buffer_copy);
            let mut result = [0u8; 16];
            result[0..4].copy_from_slice(&self.h[0].to_le_bytes());
            result[4..8].copy_from_slice(&self.h[1].to_le_bytes());
            result[8..12].copy_from_slice(&self.h[2].to_le_bytes());
            result[12..16].copy_from_slice(&self.h[3].to_le_bytes());
            result
        }
        fn process_block(&mut self, block: &[u8]) {
            assert!(block.len() == 64);
            let mut m = [0u32; 16];
            for i in 0..16 {
                m[i] = u32::from_le_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
            }
            let mut a = self.h[0];
            let mut b = self.h[1];
            let mut c = self.h[2];
            let mut d = self.h[3];
            for i in 0..64 {
                let (f, g) = match i {
                    0..=15 => (((b & c) | (!b & d)), i),
                    16..=31 => (((b & d) | (c & !d)), (5 * i + 1) % 16),
                    32..=47 => ((b ^ c ^ d), (3 * i + 5) % 16),
                    48..=63 => ((c ^ (b | !d)), (7 * i) % 16),
                    _ => unreachable!(),
                };
                let temp = d;
                d = c;
                c = b;
                let rot = S[i / 16][i % 4];
                b = b.wrapping_add(
                    a.wrapping_add(f)
                        .wrapping_add(T[i])
                        .wrapping_add(m[g])
                        .rotate_left(rot),
                );
                a = temp;
            }
            self.h[0] = self.h[0].wrapping_add(a);
            self.h[1] = self.h[1].wrapping_add(b);
            self.h[2] = self.h[2].wrapping_add(c);
            self.h[3] = self.h[3].wrapping_add(d);
        }
    }
}
#[allow(non_snake_case)]
mod sha1_impl {
    const H0: u32 = 0x67452301;
    const H1: u32 = 0xEFCDAB89;
    const H2: u32 = 0x98BADCFE;
    const H3: u32 = 0x10325476;
    const H4: u32 = 0xC3D2E1F0;
    const K: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];
    pub struct Sha1State {
        h: [u32; 5],
        buffer: [u8; 64],
        buffer_len: usize,
        total_len: u64,
    }
    impl Sha1State {
        pub fn new() -> Self {
            Sha1State {
                h: [H0, H1, H2, H3, H4],
                buffer: [0; 64],
                buffer_len: 0,
                total_len: 0,
            }
        }
        pub fn update(&mut self, data: &[u8]) {
            self.total_len = self.total_len.wrapping_add(data.len() as u64);
            let mut data_idx = 0;
            if self.buffer_len > 0 {
                let space_left = 64 - self.buffer_len;
                let fill_len = std::cmp::min(space_left, data.len());
                self.buffer[self.buffer_len..self.buffer_len + fill_len]
                    .copy_from_slice(&data[..fill_len]);
                self.buffer_len += fill_len;
                data_idx += fill_len;
                if self.buffer_len == 64 {
                    let buffer_copy = self.buffer;
                    self.process_block(&buffer_copy);
                    self.buffer_len = 0;
                }
            }
            while data.len() - data_idx >= 64 {
                self.process_block(&data[data_idx..data_idx + 64]);
                data_idx += 64;
            }
            let remaining_len = data.len() - data_idx;
            if remaining_len > 0 {
                self.buffer[..remaining_len].copy_from_slice(&data[data_idx..]);
                self.buffer_len = remaining_len;
            }
        }
        pub fn finalize(mut self) -> [u8; 20] {
            let total_bits = self.total_len.wrapping_mul(8);
            self.buffer[self.buffer_len] = 0x80;
            self.buffer_len += 1;
            if self.buffer_len > 56 {
                for i in self.buffer_len..64 {
                    self.buffer[i] = 0;
                }
                let buffer_copy = self.buffer;
                self.process_block(&buffer_copy);
                self.buffer_len = 0;
            }
            for i in self.buffer_len..56 {
                self.buffer[i] = 0;
            }
            self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
            let buffer_copy = self.buffer;
            self.process_block(&buffer_copy);
            let mut result = [0u8; 20];
            result[0..4].copy_from_slice(&self.h[0].to_be_bytes());
            result[4..8].copy_from_slice(&self.h[1].to_be_bytes());
            result[8..12].copy_from_slice(&self.h[2].to_be_bytes());
            result[12..16].copy_from_slice(&self.h[3].to_be_bytes());
            result[16..20].copy_from_slice(&self.h[4].to_be_bytes());
            result
        }
        fn process_block(&mut self, block: &[u8]) {
            assert!(block.len() == 64);
            let mut w = [0u32; 80];
            for i in 0..16 {
                w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let mut a = self.h[0];
            let mut b = self.h[1];
            let mut c = self.h[2];
            let mut d = self.h[3];
            let mut e = self.h[4];
            #[allow(clippy::needless_range_loop)]
            for i in 0..80 {
                let (f, k) = match i {
                    0..=19 => (((b & c) | (!b & d)), K[0]),
                    20..=39 => ((b ^ c ^ d), K[1]),
                    40..=59 => (((b & c) | (b & d) | (c & d)), K[2]),
                    60..=79 => ((b ^ c ^ d), K[3]),
                    _ => unreachable!(),
                };
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(w[i]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            self.h[0] = self.h[0].wrapping_add(a);
            self.h[1] = self.h[1].wrapping_add(b);
            self.h[2] = self.h[2].wrapping_add(c);
            self.h[3] = self.h[3].wrapping_add(d);
            self.h[4] = self.h[4].wrapping_add(e);
        }
    }
}
#[allow(non_snake_case)]
mod sha256_impl {
    const H: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    #[inline(always)]
    fn sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }
    #[inline(always)]
    fn sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }
    #[inline(always)]
    fn usigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }
    #[inline(always)]
    fn usigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }
    #[inline(always)]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }
    #[inline(always)]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }
    pub struct Sha256State {
        h: [u32; 8],
        buffer: [u8; 64],
        buffer_len: usize,
        total_len: u64,
    }
    impl Sha256State {
        pub fn new() -> Self {
            Sha256State {
                h: H,
                buffer: [0; 64],
                buffer_len: 0,
                total_len: 0,
            }
        }
        pub fn update(&mut self, data: &[u8]) {
            self.total_len = self.total_len.wrapping_add(data.len() as u64);
            let mut data_idx = 0;
            if self.buffer_len > 0 {
                let space_left = 64 - self.buffer_len;
                let fill_len = std::cmp::min(space_left, data.len());
                self.buffer[self.buffer_len..self.buffer_len + fill_len]
                    .copy_from_slice(&data[..fill_len]);
                self.buffer_len += fill_len;
                data_idx += fill_len;
                if self.buffer_len == 64 {
                    let buffer_copy = self.buffer;
                    self.process_block(&buffer_copy);
                    self.buffer_len = 0;
                }
            }
            while data.len() - data_idx >= 64 {
                self.process_block(&data[data_idx..data_idx + 64]);
                data_idx += 64;
            }
            let remaining_len = data.len() - data_idx;
            if remaining_len > 0 {
                self.buffer[..remaining_len].copy_from_slice(&data[data_idx..]);
                self.buffer_len = remaining_len;
            }
        }
        pub fn finalize(mut self) -> [u8; 32] {
            let total_bits = self.total_len.wrapping_mul(8);
            self.buffer[self.buffer_len] = 0x80;
            self.buffer_len += 1;
            if self.buffer_len > 56 {
                for i in self.buffer_len..64 {
                    self.buffer[i] = 0;
                }
                let buffer_copy = self.buffer;
                self.process_block(&buffer_copy);
                self.buffer_len = 0;
            }
            for i in self.buffer_len..56 {
                self.buffer[i] = 0;
            }
            self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
            let buffer_copy = self.buffer;
            self.process_block(&buffer_copy);
            let mut result = [0u8; 32];
            for i in 0..8 {
                result[i * 4..(i + 1) * 4].copy_from_slice(&self.h[i].to_be_bytes());
            }
            result
        }
        fn process_block(&mut self, block: &[u8]) {
            assert!(block.len() == 64);
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
            }
            for i in 16..64 {
                let s0 = usigma0(w[i - 15]);
                let s1 = usigma1(w[i - 2]);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let mut a = self.h[0];
            let mut b = self.h[1];
            let mut c = self.h[2];
            let mut d = self.h[3];
            let mut e = self.h[4];
            let mut f = self.h[5];
            let mut g = self.h[6];
            let mut h = self.h[7];
            for i in 0..64 {
                let s1 = sigma1(e);
                let ch_val = ch(e, f, g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch_val)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = sigma0(a);
                let maj_val = maj(a, b, c);
                let temp2 = s0.wrapping_add(maj_val);
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }
            self.h[0] = self.h[0].wrapping_add(a);
            self.h[1] = self.h[1].wrapping_add(b);
            self.h[2] = self.h[2].wrapping_add(c);
            self.h[3] = self.h[3].wrapping_add(d);
            self.h[4] = self.h[4].wrapping_add(e);
            self.h[5] = self.h[5].wrapping_add(f);
            self.h[6] = self.h[6].wrapping_add(g);
            self.h[7] = self.h[7].wrapping_add(h);
        }
    }
}

// --- Main Hash Checking Function ---

pub fn check_file_hashes(path: &Path, iocs: &IocCollection, config: &Config) -> Result<()> {
    if !config.enable_hash_check || iocs.hashes.is_empty() {
        return Ok(());
    }

    log_debug!(
        config,
        "Hashing file (using manual implementation): {}",
        path.display()
    );

    let file = File::open(path).map_err(|e| FenrirError::FileAccess {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut reader = BufReader::with_capacity(HASH_BUFFER_SIZE, file);

    let mut md5_state = md5_impl::Md5State::new();
    let mut sha1_state = sha1_impl::Sha1State::new();
    let mut sha256_state = sha256_impl::Sha256State::new();

    let mut buf = [0u8; HASH_BUFFER_SIZE];
    loop {
        let bytes_read = reader.read(&mut buf).map_err(|e| FenrirError::FileAccess {
            path: path.to_path_buf(),
            source: e,
        })?;
        if bytes_read == 0 {
            break;
        }
        let data_slice = &buf[..bytes_read];
        md5_state.update(data_slice);
        sha1_state.update(data_slice);
        sha256_state.update(data_slice);
    }

    let md5_digest = md5_state.finalize();
    let sha1_digest = sha1_state.finalize();
    let sha256_digest = sha256_state.finalize();

    let md5_hex = hex::encode(md5_digest);
    let sha1_hex = hex::encode(sha1_digest);
    let sha256_hex = hex::encode(sha256_digest);

    log_debug!(
        config,
        "Checking hashes for {}: MD5={}, SHA1={}, SHA256={}",
        path.display(),
        md5_hex,
        sha1_hex,
        sha256_hex
    );

    if let Some(description) = iocs.hashes.get(&md5_hex) {
        log_warn!(
            config,
            "[!] Hash match found FILE: {} HASH: {} (MD5) DESCRIPTION: {}",
            path.display(),
            md5_hex,
            description
        );
    }
    if let Some(description) = iocs.hashes.get(&sha1_hex) {
        log_warn!(
             config,
             "[!] Hash match found FILE: {} HASH: {} (SHA1 - WARNING: SHA1 is cryptographically weak!) DESCRIPTION: {}",
             path.display(), sha1_hex, description
         );
    }
    if let Some(description) = iocs.hashes.get(&sha256_hex) {
        log_warn!(
            config,
            "[!] Hash match found FILE: {} HASH: {} (SHA256) DESCRIPTION: {}",
            path.display(),
            sha256_hex,
            description
        );
    }

    Ok(())
}
