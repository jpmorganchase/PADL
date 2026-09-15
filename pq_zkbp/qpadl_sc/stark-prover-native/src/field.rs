use ark_ff::{BigInteger, Field, Fp128, MontBackend, MontConfig, PrimeField, Zero};

pub const P: u128 = 340282366920938463463374607393113505793;
pub const G_PRIM: u128 = 3;

#[derive(MontConfig)]
#[modulus = "340282366920938463463374607393113505793"]
#[generator = "3"]
pub struct FieldConfig;

pub type ArkField = Fp128<MontBackend<FieldConfig, 2>>;

#[inline(always)]
pub fn from_u128(value: u128) -> ArkField {
    ArkField::from(value)
}

#[inline(always)]
pub fn to_u128(value: ArkField) -> u128 {
    let limbs = value.into_bigint().to_bytes_le();
    let mut bytes = [0u8; 16];
    bytes[..limbs.len()].copy_from_slice(&limbs);
    u128::from_le_bytes(bytes)
}

#[inline(always)]
pub fn fadd(a: ArkField, b: ArkField) -> ArkField {
    a + b
}

#[inline(always)]
pub fn fsub(a: ArkField, b: ArkField) -> ArkField {
    a - b
}

#[inline(always)]
pub fn fmul(a: ArkField, b: ArkField) -> ArkField {
    a * b
}

pub fn fpow(base: ArkField, exp: u128) -> ArkField {
    base.pow([exp as u64, (exp >> 64) as u64])
}

#[inline(always)]
pub fn finv(value: ArkField) -> ArkField {
    value.inverse().unwrap_or_else(ArkField::zero)
}

#[inline(always)]
pub fn fmod(value: ArkField) -> ArkField {
    value
}

pub fn root_of_unity(n: u128) -> ArkField {
    assert!((P - 1) % n == 0, "n={} does not divide P-1", n);
    fpow(from_u128(G_PRIM), (P - 1) / n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_ops() {
        assert_eq!(to_u128(fmul(from_u128(7), from_u128(8))), 56);
        assert_eq!(to_u128(fmul(from_u128(P - 1), from_u128(2))), P - 2);
        assert_eq!(fmul(finv(from_u128(8)), from_u128(8)), from_u128(1));
        assert_eq!(to_u128(fsub(from_u128(0), from_u128(1))), P - 1);
        assert_eq!(to_u128(fadd(from_u128(P - 1), from_u128(3))), 2);
    }

    #[test]
    fn test_root_of_unity() {
        let omega = root_of_unity(8);
        assert_eq!(fpow(omega, 8), from_u128(1));
        assert_ne!(fpow(omega, 4), from_u128(1));
    }

    #[test]
    fn test_custom_ark_field_modulus_and_conversion() {
        assert_eq!(ArkField::MODULUS.to_string(), P.to_string());
        assert_eq!(to_u128(from_u128(P - 1)), P - 1);
        assert_eq!(to_u128(from_u128(P)), 0);
        assert_eq!(finv(from_u128(0)), from_u128(0));
    }
}
