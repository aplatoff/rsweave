//

use num_bigint::BigUint;
use rand::thread_rng;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

pub const RSA_SIGN_ALGORITHM: &str = "rsa";
pub const RSA_PRIVATE_KEY_SIZE: usize = 4096;

pub const DEFAULT_KEY_TYPE: &str = RSA_SIGN_ALGORITHM;

pub enum KeyType {
    RSA(usize),
}

pub fn new_rsa_key(bits: usize) -> RsaPrivateKey {
    RsaPrivateKey::new(&mut thread_rng(), bits).unwrap()
}

pub trait PublicKey {
    fn to_address(&self) -> Vec<u8>;
}

impl PublicKey for RsaPublicKey {
    fn to_address(&self) -> Vec<u8> {
        let der = self.to_pkcs1_der().unwrap();
        Sha256::digest(der.as_bytes()).to_vec()
    }
}

pub fn vdf_sha(salt: BigUint, state: &[u8; 32], iterations: usize, checkpoints: usize) -> [u8; 32] {
    let mut buffer = [0u8; 64];
    let mut s = salt.clone();
    buffer[32..].copy_from_slice(state);

    for _ in 0..checkpoints {
        s += BigUint::from(1u32);
        let salt_bin = s.to_bytes_be();
        buffer[..salt_bin.len()].copy_from_slice(&salt_bin);
        for _ in 0..iterations {
            let sha = Sha256::digest(&buffer);
            buffer[32..].copy_from_slice(&sha[..32]);
        }
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&buffer[32..64]);
    result
}

pub const SALT_SIZE: usize = 32;
const VDF_SHA_HASH_SIZE: usize = 32;

fn long_add(salt_buffer: &[u8; SALT_SIZE], checkpoint_idx: usize) -> [u8; SALT_SIZE] {
    let mut acc = checkpoint_idx;
    let mut result = [0u8; SALT_SIZE];
    for i in 1..=SALT_SIZE {
        acc += salt_buffer[SALT_SIZE - i] as usize;
        result[SALT_SIZE - i] = acc as u8;
        acc >>= 8;
    }
    result
}

fn compute_hash(
    salt: &[u8; SALT_SIZE],
    input: &[u8],
    iterations: usize,
) -> [u8; VDF_SHA_HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(input);
    let mut temp = hasher.finalize_reset();
    for _ in 1..iterations {
        hasher.update(salt);
        hasher.update(&temp);
        temp = hasher.finalize_reset();
    }
    let mut result = [0u8; VDF_SHA_HASH_SIZE];
    result.copy_from_slice(&temp);
    result
}

pub fn vdf_checkpoints(
    salt: &[u8; SALT_SIZE],
    seed: &[u8; SALT_SIZE],
    checkpoint_count: usize,
    skip_checkpoint_count: usize,
    hashing_iterations: usize,
) -> Vec<[u8; VDF_SHA_HASH_SIZE]> {
    let mut out = Vec::with_capacity(checkpoint_count);
    let mut salt_buffer = *salt;
    let mut result_hash = *seed;
    for _ in 0..checkpoint_count {
        for _ in 0..=skip_checkpoint_count {
            result_hash = compute_hash(&salt_buffer, &result_hash, hashing_iterations);
            salt_buffer = long_add(&salt_buffer, 1);
        }
        out.push(result_hash);
    }
    out
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        use std::time::Instant;

        let now = Instant::now();
        let vdf = vdf_sha(BigUint::from(0u8), &[0u8; 32], 1_000_000, 15);
        let elapsed = now.elapsed();

        println!("Elapsed: {:.2?}", elapsed);
        println!("{:?}", vdf);
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn it_works_ring() {
        use std::time::Instant;

        let now = Instant::now();
        let vdf = vdf_checkpoints(&[0u8; SALT_SIZE], &[0u8; SALT_SIZE], 15, 0, 1_000_000);
        let elapsed = now.elapsed();

        println!("Elapsed: {:.2?}", elapsed);
        println!("{:?}", vdf);
        assert_eq!(2 + 2, 4);
    }
}
