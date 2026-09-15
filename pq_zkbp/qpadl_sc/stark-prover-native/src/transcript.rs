use crate::field::*;
use crate::hash::*;

pub struct FiatShamirTranscript {
    pub state: [u8; 32],
}

impl FiatShamirTranscript {
    pub fn new() -> Self {
        Self {
            state: keccak256(b"stark-fs-keccak-v1"),
        }
    }

    pub fn append(&mut self, data: &[u8]) {
        let mut buf = Vec::with_capacity(32 + data.len());
        buf.extend_from_slice(&self.state);
        buf.extend_from_slice(data);
        self.state = keccak256(&buf);
    }

    pub fn append_u64(&mut self, v: u64) {
        self.append(&v.to_be_bytes());
    }

    pub fn append_field(&mut self, v: ArkField) {
        self.append(&field_to_bytes32(v));
    }

    pub fn challenge(&mut self, modulus: u128) -> ArkField {
        let mut buf = Vec::with_capacity(32 + 9);
        buf.extend_from_slice(&self.state);
        buf.extend_from_slice(b"challenge");
        self.state = keccak256(&buf);
        // Full 256-bit → mod P using ruint U256
        let acc = ruint::aliases::U256::from_be_bytes(self.state);
        let p256 = ruint::aliases::U256::from(modulus);
        let rem = acc % p256;
        from_u128(rem.as_limbs()[0] as u128 | ((rem.as_limbs()[1] as u128) << 64))
    }

    pub fn challenge_index(&mut self, max_val: usize) -> usize {
        let mut buf = Vec::with_capacity(32 + 5);
        buf.extend_from_slice(&self.state);
        buf.extend_from_slice(b"index");
        self.state = keccak256(&buf);
        let acc = ruint::aliases::U256::from_be_bytes(self.state);
        let mv = ruint::aliases::U256::from(max_val as u128);
        let rem = acc % mv;
        rem.as_limbs()[0] as usize
    }
}

pub fn tr_append_hex32(tr: &mut FiatShamirTranscript, hex: &str) {
    assert!(hex.starts_with("0x") && hex.len() == 66);
    let mut buf = [0u8; 32];
    for i in 0..32 {
        buf[i] = u8::from_str_radix(&hex[2 + 2 * i..4 + 2 * i], 16).unwrap();
    }
    tr.append(&buf);
}

pub fn tr_append_keccak_hash(tr: &mut FiatShamirTranscript, hash: &[u8; 32]) {
    tr.append(hash);
}
