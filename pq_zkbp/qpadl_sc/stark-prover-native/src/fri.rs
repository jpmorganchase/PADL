use crate::field::*;
use crate::hash::*;
use crate::merkle::*;
use crate::ntt::{eval_on_coset, intt_coset, LdeCoset};

pub fn fold4_coset(
    e0: ArkField,
    e1: ArkField,
    e2: ArkField,
    e3: ArkField,
    l: ArkField,
    beta: ArkField,
    mu: ArkField,
) -> ArkField {
    let inv4 = finv(from_u128(4));
    let a = fadd(e0, e2);
    let b = fadd(e1, e3);
    let c = fsub(e0, e2);
    let d = fmul(mu, fsub(e1, e3));
    let g0 = fmul(fadd(a, b), inv4);
    let g2 = fmul(fsub(a, b), inv4);
    let g1 = fmul(fsub(c, d), inv4);
    let g3 = fmul(fadd(c, d), inv4);
    let inv_l = finv(l);
    let t1 = fmul(beta, inv_l);
    let t2 = fmul(t1, t1);
    let t3 = fmul(t2, t1);
    fadd(fadd(g0, fmul(t1, g1)), fadd(fmul(t2, g2), fmul(t3, g3)))
}

pub fn fri_fold_arity4(
    evals: &[ArkField],
    domain: &[ArkField],
    beta: ArkField,
    mu: ArkField,
) -> (Vec<ArkField>, Vec<ArkField>) {
    let n = domain.len();
    let q = n / 4;
    let mut new_evals = Vec::with_capacity(q);
    let mut new_domain = Vec::with_capacity(q);
    for i in 0..q {
        let l = domain[i];
        new_evals.push(fold4_coset(
            evals[i],
            evals[i + q],
            evals[i + 2 * q],
            evals[i + 3 * q],
            l,
            beta,
            mu,
        ));
        new_domain.push(fpow(l, 4));
    }
    (new_evals, new_domain)
}

pub struct FriLayer {
    pub evals: Vec<ArkField>,
    pub domain: Vec<ArkField>,
}

pub struct FriCommitResult {
    pub layers: Vec<FriLayer>,
    pub trees: Vec<BatchedMerkleTree>,
    pub caps: Vec<Vec<[u8; 32]>>,
    pub salts: Vec<Vec<[u8; SALT_BYTES]>>,
    pub betas: Vec<ArkField>,
    pub final_poly: Vec<ArkField>,
}

pub fn fri_commit(
    h_batch_evals: Vec<ArkField>,
    lde: &LdeCoset,
    n: usize,
    cap_height: usize,
    final_poly_bound: usize,
    fri_arity: usize,
    tr: &mut crate::transcript::FiatShamirTranscript,
) -> FriCommitResult {
    assert_eq!(fri_arity, 4);
    let mu4 = fpow(lde.lde_omega, (lde.lde_size / fri_arity) as u128);
    let cap_r0 = layer_cap_height(cap_height, lde.lde_size);

    let mut layers = vec![FriLayer {
        evals: h_batch_evals.clone(),
        domain: lde.domain.clone(),
    }];
    let mut trees = Vec::new();
    let mut caps = Vec::new();
    let mut salts_all = Vec::new();
    let mut betas = Vec::new();

    let layer0_salts = random_salts(lde.lde_size);
    let leaves0: Vec<[u8; 32]> = h_batch_evals
        .iter()
        .enumerate()
        .map(|(i, &v)| leaf_hash_from_values_salt(&[v], &layer0_salts[i]))
        .collect();
    let tree0 = BatchedMerkleTree::new(leaves0, cap_r0);
    let cap0 = tree0.cap();
    for hc in &cap0 {
        tr.append(hc);
    }
    trees.push(tree0);
    caps.push(cap0);
    salts_all.push(layer0_salts);

    let mut cur_evals = h_batch_evals;
    let mut cur_domain = lde.domain.clone();
    let mut cur_bound = n;
    let mut final_poly = Vec::new();

    loop {
        let beta = tr.challenge(P);
        betas.push(beta);
        let (new_evals, new_domain) = fri_fold_arity4(&cur_evals, &cur_domain, beta, mu4);
        cur_evals = new_evals;
        cur_domain = new_domain;
        cur_bound /= fri_arity;

        if cur_bound > final_poly_bound {
            layers.push(FriLayer {
                evals: cur_evals.clone(),
                domain: cur_domain.clone(),
            });
            let cap = layer_cap_height(cap_height, cur_evals.len());
            let layer_salts = random_salts(cur_evals.len());
            let leaves: Vec<[u8; 32]> = cur_evals
                .iter()
                .enumerate()
                .map(|(i, &v)| leaf_hash_from_values_salt(&[v], &layer_salts[i]))
                .collect();
            let tree = BatchedMerkleTree::new(leaves, cap);
            let tree_cap = tree.cap();
            for hc in &tree_cap {
                tr.append(hc);
            }
            trees.push(tree);
            caps.push(tree_cap);
            salts_all.push(layer_salts);
        } else {
            let final_lde = LdeCoset {
                lde_omega: fmul(cur_domain[1], finv(cur_domain[0])),
                coset_gen: cur_domain[0],
                lde_size: cur_evals.len(),
                domain: cur_domain.clone(),
            };
            let final_coeffs = intt_coset(&cur_evals, &final_lde);
            for j in cur_bound..final_coeffs.len() {
                assert_eq!(
                    final_coeffs[j],
                    from_u128(0),
                    "FRI final poly degree overflow at {}",
                    j
                );
            }
            final_poly = final_coeffs[..cur_bound].to_vec();
            break;
        }
    }

    for &c in &final_poly {
        tr.append_field(c);
    }

    FriCommitResult {
        layers,
        trees,
        caps,
        salts: salts_all,
        betas,
        final_poly,
    }
}
