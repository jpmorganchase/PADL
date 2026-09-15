use crate::field::*;
use tiny_keccak::{Hasher, Keccak};

const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;
pub const SALT_BYTES: usize = 16;

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

pub fn field_to_bytes32(v: ArkField) -> [u8; 32] {
    let mut out = [0u8; 32];
    // Big-endian in 32 bytes (same as TS fieldToBytes32)
    let bytes = to_u128(v).to_be_bytes(); // 16 bytes
    out[16..32].copy_from_slice(&bytes);
    out
}

pub fn leaf_hash_from_values(values: &[ArkField]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + values.len() * 32);
    buf.push(LEAF_TAG);
    for &v in values {
        buf.extend_from_slice(&field_to_bytes32(v));
    }
    keccak256(&buf)
}

pub fn leaf_hash_from_values_salt(values: &[ArkField], salt: &[u8]) -> [u8; 32] {
    assert_eq!(salt.len(), SALT_BYTES);
    let mut buf = Vec::with_capacity(1 + values.len() * 32 + SALT_BYTES);
    buf.push(LEAF_TAG);
    for &v in values {
        buf.extend_from_slice(&field_to_bytes32(v));
    }
    buf.extend_from_slice(salt);
    keccak256(&buf)
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = NODE_TAG;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    keccak256(&buf)
}

pub fn random_salt() -> [u8; SALT_BYTES] {
    let mut s = [0u8; SALT_BYTES];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut s);
    s
}

pub fn random_salts(n: usize) -> Vec<[u8; SALT_BYTES]> {
    (0..n).map(|_| random_salt()).collect()
}

pub fn pack_field16(v: ArkField) -> [u8; 16] {
    to_u128(v).to_be_bytes()
}

pub fn pack_cvec(c_ntts: &[Vec<ArkField>]) -> Vec<u8> {
    let m = c_ntts.len();
    let d = c_ntts[0].len();
    let mut buf = vec![0u8; m * d * 16];
    let mut off = 0;
    for cm in c_ntts {
        for &v in cm {
            buf[off..off + 16].copy_from_slice(&pack_field16(v));
            off += 16;
        }
    }
    buf
}

pub fn cvec_hash(c_ntts: &[Vec<ArkField>]) -> [u8; 32] {
    keccak256(&pack_cvec(c_ntts))
}

pub fn bytes_to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("0x");
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

pub fn u64_be(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

pub fn leading_zero_bits_bytes(b: &[u8]) -> usize {
    let mut n = 0;
    for &byte in b {
        if byte == 0 {
            n += 8;
            continue;
        }
        for i in (0..8).rev() {
            if (byte >> i) & 1 != 0 {
                return n;
            }
            n += 1;
        }
        return n;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_to_bytes32() {
        let b = field_to_bytes32(from_u128(1));
        assert_eq!(b[31], 1);
        assert_eq!(b[30], 0);
    }

    #[test]
    fn test_leaf_hash_deterministic() {
        let values = [from_u128(1), from_u128(2), from_u128(3)];
        let h1 = leaf_hash_from_values(&values);
        let h2 = leaf_hash_from_values(&values);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_node_hash() {
        let a = [0u8; 32];
        let b = [1u8; 32];
        let h = node_hash(&a, &b);
        assert_ne!(h, a);
    }
}
