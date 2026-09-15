use crate::hash::*;

pub struct BatchedMerkleTree {
    pub n: usize,
    pub depth: usize,
    pub cap_height: usize,
    pub levels: Vec<Vec<[u8; 32]>>,
}

impl BatchedMerkleTree {
    pub fn new(leaf_hashes: Vec<[u8; 32]>, cap_height: usize) -> Self {
        let n = leaf_hashes.len();
        assert!(n > 0 && n.is_power_of_two());
        let depth = n.trailing_zeros() as usize;
        assert!(cap_height <= depth);
        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaf_hashes];
        for _ in 0..(depth - cap_height) {
            let prev = levels.last().unwrap();
            let mut cur = Vec::with_capacity(prev.len() / 2);
            for i in (0..prev.len()).step_by(2) {
                cur.push(node_hash(&prev[i], &prev[i + 1]));
            }
            levels.push(cur);
        }
        Self {
            n,
            depth,
            cap_height,
            levels,
        }
    }

    pub fn cap(&self) -> Vec<[u8; 32]> {
        self.levels.last().unwrap().clone()
    }

    pub fn open_batch(&self, indices: &[usize]) -> Vec<[u8; 32]> {
        let mut proof = Vec::new();
        let mut cur: Vec<usize> = {
            let mut s: Vec<usize> = indices.to_vec();
            s.sort_unstable();
            s.dedup();
            s
        };
        for k in 0..(self.depth - self.cap_height) {
            let level = &self.levels[k];
            let cur_set: std::collections::HashSet<usize> = cur.iter().copied().collect();
            let mut next = Vec::new();
            let mut seen = std::collections::HashSet::new();
            for &idx in &cur {
                if seen.contains(&idx) {
                    continue;
                }
                let sib = idx ^ 1;
                seen.insert(idx);
                seen.insert(sib);
                if !cur_set.contains(&sib) {
                    proof.push(level[sib]);
                }
                next.push(idx >> 1);
            }
            cur = next;
            cur.sort_unstable();
            cur.dedup();
        }
        proof
    }
}

pub fn layer_cap_height(cfg_cap: usize, layer_size: usize) -> usize {
    let depth = layer_size.trailing_zeros() as usize;
    cfg_cap.min(depth)
}
