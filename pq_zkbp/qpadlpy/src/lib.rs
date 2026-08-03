use pyo3::prelude::*;

use padl_pq::commitment::ABDLOP;
use padl_pq::matrix::Matrix;
use padl_pq::polynomial::{Poly, PolyCanon, Poly_I128, Poly_U128};
use padl_pq::common::DEGREE;

use num_traits::{One, Zero};
use std::ops::Neg;

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};

// ---- alias core proof modules + types to avoid name conflicts ----
use padl_pq::proof_of_asset::{
    ProofOfAsset as ProofOfAssetCore,
    gen_proof_of_asset as gen_proof_of_asset_core,
    verify_proof_of_asset as verify_proof_of_asset_core,
};

use padl_pq::proof_of_asset_compact::{
    ProofOfAssetCompact as ProofOfAssetCompactCore,
    gen_proof_of_asset_compact as gen_proof_of_asset_compact_core,
    verify_proof_of_asset_compact as verify_proof_of_asset_compact_core,
};

use padl_pq::proof_of_balance::{
    ProofOfBalance as ProofOfBalanceCore,
    gen_proof_of_balance as gen_proof_of_balance_core,
    verify_proof_of_balance as verify_proof_of_balance_core,
};

use padl_pq::proof_of_equivalence::{
    ProofOfEquivalence as ProofOfEquivalenceCore,
    gen_proof_of_equivalence as gen_proof_of_equivalence_core,
    verify_proof_of_equivalence as verify_proof_of_equivalence_core,
};

use padl_pq::proof_of_consistency::{
    ProofOfConsistency as ProofOfConsistencyCore,
    gen_proof_of_consistency as gen_proof_of_consistency_core,
    verify_proof_of_consistency as verify_proof_of_consistency_core,
};

use padl_pq::proof_of_opening::{
    ProofOfOpening as ProofOfOpeningCore,
    gen_proof_of_opening as gen_proof_of_opening_core,
    verify_proof_of_opening as verify_proof_of_opening_core,
};

/* ============================
   PyO3 exposed structs
============================ */

#[pyclass]
#[derive(Clone)]
pub struct SecretKey {
    // Needed by PoE (st/et are required in your gen_proof_of_equivalence signature)
    st1: Matrix<Poly>,
    st2: Matrix<Poly>,
    et1: Matrix<Poly>,
    et2: Matrix<Poly>,
}

#[pyclass]
pub struct PublicParams {
    // "bdlop": the original qpadl commitment parameters used for commit_value, PoA, PoB, etc.
    bdlop: ABDLOP,
}

#[pyclass]
pub struct PoeParams {
    // Special ABDLOP instance used by PoE protocol (ABDLOP::new_poe_abdlop()).
    abdlop: ABDLOP,
}

#[pyclass]
pub struct PoaCompactParams {
    // Separate ABDLOP instance used by ProofOfAssetCompact.
    abdlop: ABDLOP,
}

#[pyclass]
pub struct ConsistencyParams {
    // Separate ABDLOP instance used inside ProofOfConsistency.
    abdlop: ABDLOP,
}

#[pyclass]
pub struct OpeningParams {
    // Separate ABDLOP instance used for ProofOfOpening.
    abdlop: ABDLOP,
}

#[pyclass]
#[derive(Clone)]
pub struct Commitment {
    cm: Matrix<Poly>,
}

#[pyclass]
#[derive(Clone)]
pub struct ProofOfAssetPy {
    pub poa_w: Matrix<Poly>,
    pub poa_z: Matrix<Poly>,
    pub poa_u_mult: Matrix<Poly>,
    pub u_lin: Matrix<Poly>,
    pub random_phi: Poly,
    pub masked_h: Poly,
    pub challenge: Poly,
    pub cm1: Commitment, // python-friendly wrapper
}

#[pyclass]
#[derive(Clone)]
pub struct ProofOfAssetCompactPy {
    pub u0: Matrix<Poly>,
    pub u_y2: Matrix<Poly>,
    pub u_masking_g: Matrix<Poly>,
    pub u_bin: Vec<Matrix<Poly>>,
    pub u_g1: Poly,

    pub bin_challenge_mat_poly_sigma: Vec<Matrix<Poly>>,
    pub dj_vec: Vec<Poly>,
    pub dj_vec_binary: Vec<Poly>,
    pub dj_vec_compose: Vec<Poly>,
    pub challenge: Poly,

    pub z2: Poly,
    pub z1: Matrix<Poly>,
    pub z3: Matrix<Poly>,

    pub w1: Matrix<Poly>,
    pub w2: Matrix<Poly>,
    pub v: Poly,
    pub h: Poly,
}

#[pyclass]
#[derive(Clone)]
pub struct ProofOfBalancePy {
    pub w: Matrix<Poly>,
    pub u: Matrix<Poly>,
    pub z: Matrix<Poly>,
    pub challenge: Poly,
}

#[pyclass]
#[derive(Clone)]
pub struct ProofOfEquivalencePy {
    pub poe_com_diff_0: Matrix<Poly>,
    pub poe_u_pk1_pk2: Matrix<Poly>,
    pub poe_ubar_comdiff1_2: Matrix<Poly>,

    pub cm_top: Matrix<Poly>,
    pub cm_y3: Matrix<Poly>,
    pub cm_g: Matrix<Poly>,

    pub w: Matrix<Poly>,
    pub challenge: Poly,
    pub z1: Matrix<Poly>,
    pub z2: Matrix<Poly>,

    pub z3: Poly,
    pub h_poly: Poly,

    pub dj_vec: Vec<Poly>,
    pub bin_challenge_mat_poly_sigma: Vec<Matrix<Poly>>,

    pub v0_leftover_y: Matrix<Poly>,
    pub v1_leftover_y: Poly,
}

#[pyclass]
#[derive(Clone)]
pub struct ProofOfConsistencyPy {
    pub cm_proof: Matrix<Poly>,
    pub r_proof: Matrix<Poly>,

    pub w: Matrix<Poly>,
    pub y1: Matrix<Poly>,
    pub y2: Matrix<Poly>,
    pub y3: Poly,

    pub masking_g: Poly,
    pub bin_challenge_mat: Vec<Vec<Poly_U128>>,
    pub bin_challenge_mat_poly: Vec<Matrix<Poly>>,
    pub dj_vec: Vec<Poly>,
    pub dj_vec_prime: Vec<Poly>,
    pub z3: Poly,
    pub h_poly: Poly,
    pub challenge: Poly,
    pub z1: Matrix<Poly>,
    pub z2: Matrix<Poly>,
}

#[pyclass]
#[derive(Clone)]
pub struct ProofOfOpeningPy {
    pub w: Matrix<Poly>,
    pub y1: Matrix<Poly>,
    pub y2: Matrix<Poly>,
    pub challenge: Poly,
    pub z1: Matrix<Poly>,
    pub z2: Matrix<Poly>,
    pub cm_top: Matrix<Poly>,
}

/* ============================
   Conversions (core <-> py)
============================ */

pub fn poa_core_to_py(proof: ProofOfAssetCore) -> ProofOfAssetPy {
    ProofOfAssetPy {
        poa_w: proof.poa_w,
        poa_z: proof.poa_z,
        poa_u_mult: proof.poa_u_mult,
        u_lin: proof.u_lin,
        random_phi: proof.random_phi,
        masked_h: proof.masked_h,
        challenge: proof.challenge,
        cm1: Commitment { cm: proof.cm1 },
    }
}

pub fn poa_py_to_core(proof: &ProofOfAssetPy) -> ProofOfAssetCore {
    ProofOfAssetCore {
        poa_w: proof.poa_w.clone(),
        poa_z: proof.poa_z.clone(),
        poa_u_mult: proof.poa_u_mult.clone(),
        u_lin: proof.u_lin.clone(),
        random_phi: proof.random_phi.clone(),
        masked_h: proof.masked_h.clone(),
        challenge: proof.challenge.clone(),
        cm1: proof.cm1.cm.clone(),
    }
}

pub fn poa_compact_core_to_py(p: ProofOfAssetCompactCore) -> ProofOfAssetCompactPy {
    ProofOfAssetCompactPy {
        u0: p.u0,
        u_y2: p.u_y2,
        u_masking_g: p.u_masking_g,
        u_bin: p.u_bin,
        u_g1: p.u_g1,
        bin_challenge_mat_poly_sigma: p.bin_challenge_mat_poly_sigma,
        dj_vec: p.dj_vec,
        dj_vec_binary: p.dj_vec_binary,
        dj_vec_compose: p.dj_vec_compose,
        challenge: p.challenge,
        z2: p.z2,
        z1: p.z1,
        z3: p.z3,
        w1: p.w1,
        w2: p.w2,
        v: p.v,
        h: p.h,
    }
}

pub fn poa_compact_py_to_core(p: &ProofOfAssetCompactPy) -> ProofOfAssetCompactCore {
    ProofOfAssetCompactCore {
        u0: p.u0.clone(),
        u_y2: p.u_y2.clone(),
        u_masking_g: p.u_masking_g.clone(),
        u_bin: p.u_bin.clone(),
        u_g1: p.u_g1.clone(),
        bin_challenge_mat_poly_sigma: p.bin_challenge_mat_poly_sigma.clone(),
        dj_vec: p.dj_vec.clone(),
        dj_vec_binary: p.dj_vec_binary.clone(),
        dj_vec_compose: p.dj_vec_compose.clone(),
        challenge: p.challenge.clone(),
        z2: p.z2.clone(),
        z1: p.z1.clone(),
        z3: p.z3.clone(),
        w1: p.w1.clone(),
        w2: p.w2.clone(),
        v: p.v.clone(),
        h: p.h.clone(),
    }
}

fn panic_to_string(err: Box<dyn Any + Send>) -> String {
    if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

pub fn pob_core_to_py(proof: ProofOfBalanceCore) -> ProofOfBalancePy {
    ProofOfBalancePy {
        w: proof.w,
        u: proof.u,
        z: proof.z,
        challenge: proof.challenge,
    }
}

pub fn pob_py_to_core(proof: &ProofOfBalancePy) -> ProofOfBalanceCore {
    ProofOfBalanceCore {
        w: proof.w.clone(),
        u: proof.u.clone(),
        z: proof.z.clone(),
        challenge: proof.challenge.clone(),
    }
}

pub fn poe_core_to_py(p: ProofOfEquivalenceCore) -> ProofOfEquivalencePy {
    ProofOfEquivalencePy {
        poe_com_diff_0: p.poe_com_diff_0,
        poe_u_pk1_pk2: p.poe_u_pk1_pk2,
        poe_ubar_comdiff1_2: p.poe_ubar_comdiff1_2,

        cm_top: p.cm_top,
        cm_y3: p.cm_y3,
        cm_g: p.cm_g,

        w: p.w,
        challenge: p.challenge,
        z1: p.z1,
        z2: p.z2,

        z3: p.z3,
        h_poly: p.h_poly,

        dj_vec: p.dj_vec,
        bin_challenge_mat_poly_sigma: p.bin_challenge_mat_poly_sigma,

        v0_leftover_y: p.v0_leftover_y,
        v1_leftover_y: p.v1_leftover_y,
    }
}

pub fn poe_py_to_core(p: &ProofOfEquivalencePy) -> ProofOfEquivalenceCore {
    ProofOfEquivalenceCore {
        poe_com_diff_0: p.poe_com_diff_0.clone(),
        poe_u_pk1_pk2: p.poe_u_pk1_pk2.clone(),
        poe_ubar_comdiff1_2: p.poe_ubar_comdiff1_2.clone(),

        cm_top: p.cm_top.clone(),
        cm_y3: p.cm_y3.clone(),
        cm_g: p.cm_g.clone(),

        w: p.w.clone(),
        challenge: p.challenge.clone(),
        z1: p.z1.clone(),
        z2: p.z2.clone(),

        z3: p.z3.clone(),
        h_poly: p.h_poly.clone(),

        dj_vec: p.dj_vec.clone(),
        bin_challenge_mat_poly_sigma: p.bin_challenge_mat_poly_sigma.clone(),

        v0_leftover_y: p.v0_leftover_y.clone(),
        v1_leftover_y: p.v1_leftover_y.clone(),
    }
}

pub fn poc_core_to_py(p: ProofOfConsistencyCore) -> ProofOfConsistencyPy {
    ProofOfConsistencyPy {
        cm_proof: p.cm_proof,
        r_proof: p.r_proof,

        w: p.w,
        y1: p.y1,
        y2: p.y2,
        y3: p.y3,

        masking_g: p.masking_g,
        bin_challenge_mat: p.bin_challenge_mat,
        bin_challenge_mat_poly: p.bin_challenge_mat_poly,
        dj_vec: p.dj_vec,
        dj_vec_prime: p.dj_vec_prime,
        z3: p.z3,
        h_poly: p.h_poly,
        challenge: p.challenge,
        z1: p.z1,
        z2: p.z2,
    }
}

pub fn poc_py_to_core(p: &ProofOfConsistencyPy) -> ProofOfConsistencyCore {
    ProofOfConsistencyCore {
        cm_proof: p.cm_proof.clone(),
        r_proof: p.r_proof.clone(),

        w: p.w.clone(),
        y1: p.y1.clone(),
        y2: p.y2.clone(),
        y3: p.y3.clone(),

        masking_g: p.masking_g.clone(),
        bin_challenge_mat: p.bin_challenge_mat.clone(),
        bin_challenge_mat_poly: p.bin_challenge_mat_poly.clone(),
        dj_vec: p.dj_vec.clone(),
        dj_vec_prime: p.dj_vec_prime.clone(),
        z3: p.z3.clone(),
        h_poly: p.h_poly.clone(),
        challenge: p.challenge.clone(),
        z1: p.z1.clone(),
        z2: p.z2.clone(),
    }
}

pub fn poo_core_to_py(p: ProofOfOpeningCore) -> ProofOfOpeningPy {
    ProofOfOpeningPy {
        w: p.w,
        y1: p.y1,
        y2: p.y2,
        challenge: p.challenge,
        z1: p.z1,
        z2: p.z2,
        cm_top: p.cm_top,
    }
}

pub fn poo_py_to_core(p: &ProofOfOpeningPy) -> ProofOfOpeningCore {
    ProofOfOpeningCore {
        w: p.w.clone(),
        y1: p.y1.clone(),
        y2: p.y2.clone(),
        challenge: p.challenge.clone(),
        z1: p.z1.clone(),
        z2: p.z2.clone(),
        cm_top: p.cm_top.clone(),
    }
}

/* ============================
   Bytes helpers
============================ */

fn poly_from_bytes(b: &[u8]) -> PyResult<Poly> {
    if b.len() != 16 * DEGREE {
        return Err(pyo3::exceptions::PyValueError::new_err("bad poly byte length"));
    }

    let mut arr = [Poly_U128::zero(); DEGREE];

    for i in 0..DEGREE {
        let chunk: [u8; 16] = b[16 * i..16 * i + 16]
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("bad byte chunk"))?;

        let x = Poly_I128::from_le_bytes(chunk);
        arr[i] = Poly_U128::from(x);
    }

    Ok(Poly::new(arr))
}

fn poly_to_bytes(p: &Poly) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 * DEGREE);
    for c in p.into_canonical_poly().coeff.iter() {
        out.extend_from_slice(&c.to_le_bytes());
    }
    out
}

fn matrix_poly_from_bytes_column(r_bytes: &Vec<Vec<u8>>) -> PyResult<Matrix<Poly>> {
    if r_bytes.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err("r_bytes is empty"));
    }
    let mut polys = Vec::with_capacity(r_bytes.len());
    for (i, pb) in r_bytes.iter().enumerate() {
        let p = poly_from_bytes(pb).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "failed to decode r_bytes[{}]: {}",
                i, e
            ))
        })?;
        polys.push(p);
    }
    Ok(Matrix::from_vec(polys)) // column vector in your codebase
}

fn matrix_poly_to_bytes_column(m: &Matrix<Poly>) -> Vec<Vec<u8>> {
    m.to_vec().into_iter().map(|p| poly_to_bytes(&p)).collect()
}

/* ============================
   Setup / Keygen
============================ */

#[pyfunction]
fn keygen() -> PyResult<(PublicParams, SecretKey)> {
    let (bdlop, st1, st2, et1, et2) = ABDLOP::new_random_instance();
    Ok((
        PublicParams { bdlop },
        SecretKey { st1, st2, et1, et2 },
    ))
}

#[pyfunction]
fn setup() -> PyResult<PublicParams> {
    let (bdlop, _st1, _st2, _et1, _et2) = ABDLOP::new_random_instance();
    Ok(PublicParams { bdlop })
}

#[pyfunction]
fn poe_setup() -> PyResult<PoeParams> {
    let abdlop = ABDLOP::new_poe_abdlop();
    Ok(PoeParams { abdlop })
}

#[pyfunction]
fn poa_compact_setup() -> PyResult<PoaCompactParams> {
    let MAX_COEFF_BETA=64;
    let (abdlop, _st1, _st2, _et1, _et2) =
        ABDLOP::new_random_instance_custom(3 + MAX_COEFF_BETA);
    Ok(PoaCompactParams { abdlop })
}

#[pyfunction]
fn consistency_setup() -> PyResult<ConsistencyParams> {
    let (abdlop, _st1, _st2, _et1, _et2) = ABDLOP::new_random_instance();
    Ok(ConsistencyParams { abdlop })
}

#[pyfunction]
fn opening_setup() -> PyResult<OpeningParams> {
    let (abdlop, _st1, _st2, _et1, _et2) = ABDLOP::new_random_instance();
    Ok(OpeningParams { abdlop })
}

/* ============================
   Commitment
============================ */

#[pyfunction]
fn commit_value(pp: &PublicParams, value: i128) -> PyResult<(Commitment, Vec<Vec<u8>>)> {
    let m = Poly::from_i128_constant(value);
    let prepared = pp.bdlop.prepare_qpadl_message(m);
    let (cm, r) = pp.bdlop.commit(&prepared);
    let r_bytes = matrix_poly_to_bytes_column(&r);
    Ok((Commitment { cm }, r_bytes))
}

#[pyfunction]
fn commit_values(pp: &PublicParams, values: Vec<i128>) -> PyResult<(Commitment, Vec<Vec<u8>>)> {
    if values.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "values must be a non-empty list",
        ));
    }

    let m = Poly::from_i128_vec(&values);
    let prepared = pp.bdlop.prepare_qpadl_message(m);
    let (cm, r) = pp.bdlop.commit(&prepared);
    let r_bytes = matrix_poly_to_bytes_column(&r);
    Ok((Commitment { cm }, r_bytes))
}

#[pyfunction]
fn add_commitments(a: &Commitment, b: &Commitment) -> PyResult<Commitment> {
    Ok(Commitment { cm: &a.cm + &b.cm })
}

/* ============================
   Extraction (trapdoor)
============================ */

fn poly_to_signed_coeffs(p: &Poly) -> Vec<i128> {
    p.into_canonical_poly().coeff.to_vec()
}

#[pyfunction]
fn extract_const_without_r(pp: &PublicParams, sk: &SecretKey, c: &Commitment) -> PyResult<i128> {
    let m = ABDLOP::extract_without_r_message(&pp.bdlop, &sk.st1, &sk.st2, &c.cm);
    Ok(poly_to_signed_coeffs(&m)[0])
}

#[pyfunction]
fn extract_all_without_r(pp: &PublicParams, sk: &SecretKey, c: &Commitment) -> PyResult<Vec<i128>> {
    let m = ABDLOP::extract_without_r_message(&pp.bdlop, &sk.st1, &sk.st2, &c.cm);
    Ok(poly_to_signed_coeffs(&m))
}

/* ============================
   Proof of Asset
============================ */

#[pyfunction]
fn gen_proof_of_asset(
    pp: &PublicParams,
    cm: &Commitment,
    value: i128,
    r_bytes: Vec<Vec<u8>>,
) -> PyResult<ProofOfAssetPy> {
    let r = matrix_poly_from_bytes_column(&r_bytes)?;
    let m = Poly::from_i128_constant(value);
    let proof_core = gen_proof_of_asset_core(&pp.bdlop, &m, &cm.cm, &r);
    Ok(poa_core_to_py(proof_core))
}

#[pyfunction]
fn verify_proof_of_asset(pp: &PublicParams, cm: &Commitment, proof: &ProofOfAssetPy) -> PyResult<bool> {
    let proof_core = poa_py_to_core(proof);
    Ok(verify_proof_of_asset_core(&pp.bdlop, &cm.cm, &proof_core))
}

/* ============================
   Proof of Asset (Compact)
============================ */

#[pyfunction]
fn gen_proof_of_asset_compact(
    pp: &PublicParams,
    cap: &PoaCompactParams,
    cm: &Commitment,
    values: Vec<i128>,
    r_bytes: Vec<Vec<u8>>,
    is_rejection_sampling: bool,
) -> PyResult<ProofOfAssetCompactPy> {
    if values.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "values must be a non-empty list",
        ));
    }
    let r = matrix_poly_from_bytes_column(&r_bytes)?;

    let m = Poly::from_i128_vec(&values);
    let m_vec = pp.bdlop.prepare_qpadl_message(m.clone());
    let res = catch_unwind(AssertUnwindSafe(|| {
        gen_proof_of_asset_compact_core(
            &pp.bdlop,
            &cap.abdlop,
            &cm.cm,
            &r,
            &m,
            is_rejection_sampling,
        )
    }));

    let proof_core = match res {
        Ok(p) => p,
        Err(err) => {
            let msg = panic_to_string(err);
            return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "Rust panic while generating ProofOfAssetCompact: {}",
                msg
            )));
        }
    };

    Ok(poa_compact_core_to_py(proof_core))
}

#[pyfunction]
fn verify_proof_of_asset_compact(
    pp: &PublicParams,
    cap: &PoaCompactParams,
    cm: &Commitment,
    proof: &ProofOfAssetCompactPy,
) -> PyResult<bool> {
    let proof_core = poa_compact_py_to_core(proof);
    Ok(verify_proof_of_asset_compact_core(
        proof_core,
        &pp.bdlop,
        &cap.abdlop,
        &cm.cm,
    ))
}

/* ============================
   Proof of Balance
============================ */

#[pyfunction]
fn sum_commitments_py(py: Python, coms: Vec<Py<Commitment>>) -> PyResult<Commitment> {
    if coms.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err("empty commitment list"));
    }

    let first = coms[0].borrow(py);
    let mut acc = first.cm.clone();

    for c in coms.iter().skip(1) {
        let c_ref = c.borrow(py);
        acc = &acc + &c_ref.cm;
    }

    Ok(Commitment { cm: acc })
}

#[pyfunction]
fn sum_r_bytes(r_list: Vec<Vec<Vec<u8>>>) -> PyResult<Vec<Vec<u8>>> {
    if r_list.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err("empty r_list"));
    }

    let mut acc: Option<Matrix<Poly>> = None;

    for (i, r_bytes) in r_list.iter().enumerate() {
        let r = matrix_poly_from_bytes_column(r_bytes).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "failed to decode r_list[{}]: {}",
                i, e
            ))
        })?;

        acc = Some(match acc {
            None => r,
            Some(prev) => &prev + &r,
        });
    }

    Ok(matrix_poly_to_bytes_column(&acc.unwrap()))
}

#[pyfunction]
fn gen_proof_of_balance(
    py: Python,
    pp: &PublicParams,
    coms: Vec<Py<Commitment>>,
    r_sum_bytes: Vec<Vec<u8>>,
) -> PyResult<ProofOfBalancePy> {
    if coms.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err("empty commitment list"));
    }

    let com_vec: Vec<Matrix<Poly>> = coms
        .into_iter()
        .map(|c| c.borrow(py).cm.clone())
        .collect();

    let r_sum = matrix_poly_from_bytes_column(&r_sum_bytes)?;
    let proof_core = gen_proof_of_balance_core(&com_vec, &r_sum, &pp.bdlop);
    Ok(pob_core_to_py(proof_core))
}

#[pyfunction]
fn verify_proof_of_balance(
    py: Python,
    pp: &PublicParams,
    coms: Vec<Py<Commitment>>,
    proof: &ProofOfBalancePy,
) -> PyResult<bool> {
    if coms.is_empty() {
        return Ok(false);
    }

    let com_vec: Vec<Matrix<Poly>> = coms
        .into_iter()
        .map(|c| c.borrow(py).cm.clone())
        .collect();

    let proof_core = pob_py_to_core(proof);
    Ok(verify_proof_of_balance_core(&com_vec, &pp.bdlop, &proof_core))
}

/* ============================
   Proof of Equivalence
============================ */

#[pyfunction]
fn recommit_and_prove_equivalence(
    pp: &PublicParams,
    poe_pp: &PoeParams,
    sk: &SecretKey,
    cm1: &Commitment,
) -> PyResult<(Commitment, Vec<Vec<u8>>, ProofOfEquivalencePy)> {
    let bdlop = &pp.bdlop;
    let abdlop = &poe_pp.abdlop;

    let m_poly = ABDLOP::extract_without_r_message(bdlop, &sk.st1, &sk.st2, &cm1.cm);
    let m_vec = bdlop.prepare_qpadl_message(m_poly);

    let (cm2_mat, r2) = bdlop.commit(&m_vec);
    let cm2 = Commitment { cm: cm2_mat };
    let r2_bytes = matrix_poly_to_bytes_column(&r2);

    let k = bdlop.randomness_vector_dimension_k;
    let r1_dummy = Matrix::from_vec(vec![Poly::zero(); k]);
    let r2_dummy = Matrix::from_vec(vec![Poly::zero(); k]);

    let res = catch_unwind(AssertUnwindSafe(|| {
        gen_proof_of_equivalence_core(
            bdlop,
            abdlop,
            &sk.st1,
            &sk.st2,
            &sk.et1,
            &sk.et2,
            &m_vec,
            &cm1.cm,
            &cm2.cm,
            &r1_dummy,
            &r2_dummy,
        )
    }));

    let proof_core = match res {
        Ok(p) => p,
        Err(_) => {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Rust panic while generating ProofOfEquivalence (enable RUST_BACKTRACE=1 to debug).",
            ));
        }
    };

    Ok((cm2, r2_bytes, poe_core_to_py(proof_core)))
}

#[pyfunction]
fn verify_proof_of_equivalence(
    pp: &PublicParams,
    poe_pp: &PoeParams,
    cm1: &Commitment,
    cm2: &Commitment,
    proof: &ProofOfEquivalencePy,
) -> PyResult<bool> {
    let proof_core = poe_py_to_core(proof);
    Ok(verify_proof_of_equivalence_core(
        &pp.bdlop,
        &poe_pp.abdlop,
        &cm1.cm,
        &cm2.cm,
        &proof_core,
    ))
}

/* ============================
   Proof of Consistency
============================ */

#[pyfunction]
fn gen_proof_of_consistency(
    pp: &PublicParams,
    cpp: &ConsistencyParams,
    value: i128,
    r1_bytes: Vec<Vec<u8>>,
) -> PyResult<ProofOfConsistencyPy> {
    let value_poly = Poly::from_i128_constant(value);
    let r1 = matrix_poly_from_bytes_column(&r1_bytes)?;

    let res = catch_unwind(AssertUnwindSafe(|| {
        gen_proof_of_consistency_core(&pp.bdlop, &cpp.abdlop, value_poly, &r1)
    }));

    let proof_core = match res {
        Ok(p) => p,
        Err(_) => {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Rust panic while generating ProofOfConsistency (enable RUST_BACKTRACE=1 to debug).",
            ));
        }
    };

    Ok(poc_core_to_py(proof_core))
}

#[pyfunction]
fn verify_proof_of_consistency(
    pp: &PublicParams,
    cpp: &ConsistencyParams,
    cm1: &Commitment,
    proof: &ProofOfConsistencyPy,
) -> PyResult<bool> {
    let proof_core = poc_py_to_core(proof);
    Ok(verify_proof_of_consistency_core(
        &pp.bdlop,
        &cpp.abdlop,
        &cm1.cm,
        &proof_core,
    ))
}

/* ============================
   Proof of Opening
   You want a PyO3 flow similar to your test:
     - r is from bdlop.commit(...)
     - cm_abdlop,s is from abdlop.commit_full(m_vec, r)
     - proof uses (r,s,cm_abdlop)
   Since Python doesn't have m_vec, we expose a helper:
     abdlop_commit_full_value(op, value, r_bytes) -> (cm_abdlop, s_bytes)
   Then:
     gen_proof_of_opening(op, r_bytes, s_bytes, cm_abdlop) -> proof
============================ */

#[pyfunction]
fn abdlop_commit_full_value(
    op: &OpeningParams,
    value: i128,
    r_bytes: Vec<Vec<u8>>,
) -> PyResult<(Commitment, Vec<Vec<u8>>)> {
    let r = matrix_poly_from_bytes_column(&r_bytes)?;
    let m = Poly::from_i128_constant(value);

    // Use the SAME vectorization style as commit_value
    let m_vec = op.abdlop.prepare_qpadl_message(m);
    let (cm_proof, s) = op.abdlop.commit_full(&m_vec, &r);

    Ok((Commitment { cm: cm_proof }, matrix_poly_to_bytes_column(&s)))
}

#[pyfunction]
fn gen_proof_of_opening(
    op: &OpeningParams,
    r_bytes: Vec<Vec<u8>>,
    s_bytes: Vec<Vec<u8>>,
    cm_abdlop: &Commitment,
) -> PyResult<ProofOfOpeningPy> {
    let r = matrix_poly_from_bytes_column(&r_bytes)?;
    let s = matrix_poly_from_bytes_column(&s_bytes)?;

    let res = catch_unwind(AssertUnwindSafe(|| {
        gen_proof_of_opening_core(&op.abdlop, &r, &s, &cm_abdlop.cm)
    }));

    let proof_core = match res {
        Ok(p) => p,
        Err(_) => {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Rust panic while generating ProofOfOpening (enable RUST_BACKTRACE=1 to debug).",
            ));
        }
    };

    Ok(poo_core_to_py(proof_core))
}

#[pyfunction]
fn verify_proof_of_opening(op: &OpeningParams, proof: &ProofOfOpeningPy) -> PyResult<bool> {
    let proof_core = poo_py_to_core(proof);
    Ok(verify_proof_of_opening_core(&op.abdlop, &proof_core))
}

/* ============================
   Module
============================ */

#[pymodule]
fn zkqp(_py: Python, m: &PyModule) -> PyResult<()> {
    // setup / keys
    m.add_function(wrap_pyfunction!(keygen, m)?)?;
    m.add_function(wrap_pyfunction!(setup, m)?)?;
    m.add_function(wrap_pyfunction!(poe_setup, m)?)?;
    m.add_function(wrap_pyfunction!(poa_compact_setup, m)?)?;
    m.add_function(wrap_pyfunction!(consistency_setup, m)?)?;
    m.add_function(wrap_pyfunction!(opening_setup, m)?)?;

    // commitment ops
    m.add_function(wrap_pyfunction!(commit_value, m)?)?;
    m.add_function(wrap_pyfunction!(commit_values, m)?)?;
    m.add_function(wrap_pyfunction!(add_commitments, m)?)?;
    m.add_function(wrap_pyfunction!(sum_commitments_py, m)?)?;
    m.add_function(wrap_pyfunction!(sum_r_bytes, m)?)?;

    // extraction
    m.add_function(wrap_pyfunction!(extract_const_without_r, m)?)?;
    m.add_function(wrap_pyfunction!(extract_all_without_r, m)?)?;

    // proof of asset
    m.add_function(wrap_pyfunction!(gen_proof_of_asset, m)?)?;
    m.add_function(wrap_pyfunction!(verify_proof_of_asset, m)?)?;
    m.add_function(wrap_pyfunction!(gen_proof_of_asset_compact, m)?)?;
    m.add_function(wrap_pyfunction!(verify_proof_of_asset_compact, m)?)?;

    // proof of balance
    m.add_function(wrap_pyfunction!(gen_proof_of_balance, m)?)?;
    m.add_function(wrap_pyfunction!(verify_proof_of_balance, m)?)?;

    // proof of equivalence
    m.add_function(wrap_pyfunction!(recommit_and_prove_equivalence, m)?)?;
    m.add_function(wrap_pyfunction!(verify_proof_of_equivalence, m)?)?;

    // proof of consistency
    m.add_function(wrap_pyfunction!(gen_proof_of_consistency, m)?)?;
    m.add_function(wrap_pyfunction!(verify_proof_of_consistency, m)?)?;

    // proof of opening
    m.add_function(wrap_pyfunction!(abdlop_commit_full_value, m)?)?;
    m.add_function(wrap_pyfunction!(gen_proof_of_opening, m)?)?;
    m.add_function(wrap_pyfunction!(verify_proof_of_opening, m)?)?;

    // classes
    m.add_class::<PublicParams>()?;
    m.add_class::<PoeParams>()?;
    m.add_class::<PoaCompactParams>()?;
    m.add_class::<ConsistencyParams>()?;
    m.add_class::<OpeningParams>()?;
    m.add_class::<SecretKey>()?;
    m.add_class::<Commitment>()?;
    m.add_class::<ProofOfAssetPy>()?;
    m.add_class::<ProofOfAssetCompactPy>()?;
    m.add_class::<ProofOfBalancePy>()?;
    m.add_class::<ProofOfEquivalencePy>()?;
    m.add_class::<ProofOfConsistencyPy>()?;
    m.add_class::<ProofOfOpeningPy>()?;

    Ok(())
}
