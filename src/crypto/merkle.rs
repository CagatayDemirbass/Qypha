use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A Merkle tree for verifying integrity of chunked data.
///
/// Each leaf is the SHA-256 hash of a data chunk.
/// Internal nodes are SHA-256(left || right).
/// The root hash provides a single tamper-proof fingerprint of all chunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// Root hash of the tree
    pub root_hash: [u8; 32],
    /// All leaf hashes (for proof generation)
    pub leaves: Vec<[u8; 32]>,
    /// Total number of leaves (chunks)
    pub leaf_count: usize,
    /// All nodes stored in a flat array (level-order).
    /// nodes[0] = root, children of i at 2i+1 and 2i+2.
    /// We store only the hashes.
    nodes: Vec<[u8; 32]>,
}

/// Direction in a Merkle proof path
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProofDirection {
    Left,
    Right,
}

/// A Merkle proof that a specific chunk belongs to the tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub chunk_index: usize,
    pub chunk_hash: [u8; 32],
    /// Sibling hashes from leaf to root
    pub siblings: Vec<(ProofDirection, [u8; 32])>,
    pub root_hash: [u8; 32],
}

impl MerkleTree {
    fn build_levels_from_leaves(leaf_hashes: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
        assert!(
            !leaf_hashes.is_empty(),
            "Cannot build Merkle tree from empty hashes"
        );

        let mut current_level: Vec<[u8; 32]> = leaf_hashes.to_vec();
        if current_level.len() % 2 != 0 {
            current_level.push(*current_level.last().unwrap());
        }

        let mut all_levels: Vec<Vec<[u8; 32]>> = vec![current_level.clone()];
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for pair in current_level.chunks(2) {
                let hash = hash_pair(&pair[0], &pair[1]);
                next_level.push(hash);
            }
            if next_level.len() > 1 && next_level.len() % 2 != 0 {
                next_level.push(*next_level.last().unwrap());
            }
            all_levels.push(next_level.clone());
            current_level = next_level;
        }

        all_levels
    }

    /// Build a Merkle tree from data chunks.
    ///
    /// Each chunk is hashed with SHA-256 to form a leaf.
    /// If the number of leaves is odd, the last leaf is duplicated.
    pub fn build(chunks: &[&[u8]]) -> Self {
        assert!(
            !chunks.is_empty(),
            "Cannot build Merkle tree from empty data"
        );

        let leaves: Vec<[u8; 32]> = chunks
            .iter()
            .map(|chunk| {
                let mut hasher = Sha256::new();
                hasher.update(chunk);
                hasher.finalize().into()
            })
            .collect();

        Self::build_from_hashes(&leaves)
    }

    /// Build a Merkle tree from pre-computed leaf hashes.
    pub fn build_from_hashes(leaf_hashes: &[[u8; 32]]) -> Self {
        let leaf_count = leaf_hashes.len();
        let all_levels = Self::build_levels_from_leaves(leaf_hashes);
        let root_hash = all_levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("Merkle tree must contain a root");

        // Flatten into level-order array (root first)
        let mut nodes = Vec::new();
        for level in all_levels.iter().rev() {
            nodes.extend_from_slice(level);
        }

        Self {
            root_hash,
            leaves: leaf_hashes.to_vec(),
            leaf_count,
            nodes,
        }
    }

    /// Generate a proof that chunk at `chunk_index` is part of this tree.
    pub fn generate_proof(&self, chunk_index: usize) -> MerkleProof {
        let levels = Self::build_levels_from_leaves(&self.leaves);
        self.generate_proof_from_levels(chunk_index, &levels)
    }

    /// Generate proofs for every original leaf while reusing the same level structure.
    pub fn generate_all_proofs(&self) -> Vec<MerkleProof> {
        let levels = Self::build_levels_from_leaves(&self.leaves);
        (0..self.leaf_count)
            .map(|chunk_index| self.generate_proof_from_levels(chunk_index, &levels))
            .collect()
    }

    fn generate_proof_from_levels(
        &self,
        chunk_index: usize,
        levels: &[Vec<[u8; 32]>],
    ) -> MerkleProof {
        assert!(chunk_index < self.leaf_count, "Chunk index out of range");

        let mut siblings = Vec::new();

        let mut idx = chunk_index;
        for current_level in levels {
            if current_level.len() <= 1 {
                break;
            }

            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling_hash = current_level[sibling_idx.min(current_level.len() - 1)];
            let direction = if idx % 2 == 0 {
                ProofDirection::Right
            } else {
                ProofDirection::Left
            };

            siblings.push((direction, sibling_hash));
            idx /= 2;
        }

        MerkleProof {
            chunk_index,
            chunk_hash: self.leaves[chunk_index],
            siblings,
            root_hash: self.root_hash,
        }
    }

    /// Verify that all chunks match the expected root hash.
    pub fn verify_root(chunks: &[&[u8]], expected_root: &[u8; 32]) -> bool {
        if chunks.is_empty() {
            return false;
        }
        let tree = Self::build(chunks);
        tree.root_hash == *expected_root
    }
}

impl MerkleProof {
    /// Verify this proof: recompute the root from chunk data and siblings.
    pub fn verify(&self, chunk_data: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(chunk_data);
        let computed_hash: [u8; 32] = hasher.finalize().into();

        if computed_hash != self.chunk_hash {
            return false;
        }

        self.verify_hash()
    }

    /// Verify this proof using the pre-computed chunk hash (no raw data needed).
    pub fn verify_hash(&self) -> bool {
        let mut current = self.chunk_hash;

        for (direction, sibling) in &self.siblings {
            current = match direction {
                ProofDirection::Left => hash_pair(sibling, &current),
                ProofDirection::Right => hash_pair(&current, sibling),
            };
        }

        current == self.root_hash
    }
}

/// Hash two child nodes to produce a parent node
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_chunk() {
        let data = b"hello world";
        let tree = MerkleTree::build(&[data.as_ref()]);
        assert_eq!(tree.leaf_count, 1);

        let proof = tree.generate_proof(0);
        assert!(proof.verify(data));
    }

    #[test]
    fn test_two_chunks() {
        let c1 = b"chunk one";
        let c2 = b"chunk two";
        let tree = MerkleTree::build(&[c1.as_ref(), c2.as_ref()]);
        assert_eq!(tree.leaf_count, 2);

        let proof0 = tree.generate_proof(0);
        assert!(proof0.verify(c1));

        let proof1 = tree.generate_proof(1);
        assert!(proof1.verify(c2));
    }

    #[test]
    fn test_odd_chunk_count() {
        let chunks: Vec<Vec<u8>> = (0..7)
            .map(|i| format!("chunk_{}", i).into_bytes())
            .collect();
        let refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let tree = MerkleTree::build(&refs);
        assert_eq!(tree.leaf_count, 7);

        for i in 0..7 {
            let proof = tree.generate_proof(i);
            assert!(proof.verify(&chunks[i]), "Proof failed for chunk {}", i);
        }
    }

    #[test]
    fn test_even_chunk_count() {
        let chunks: Vec<Vec<u8>> = (0..16)
            .map(|i| format!("data_{}", i).into_bytes())
            .collect();
        let refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let tree = MerkleTree::build(&refs);
        assert_eq!(tree.leaf_count, 16);

        for i in 0..16 {
            let proof = tree.generate_proof(i);
            assert!(proof.verify(&chunks[i]), "Proof failed for chunk {}", i);
        }
    }

    #[test]
    fn test_tamper_detection() {
        let c1 = b"original data";
        let c2 = b"more data";
        let tree = MerkleTree::build(&[c1.as_ref(), c2.as_ref()]);

        let proof = tree.generate_proof(0);
        // Verify with tampered data
        assert!(!proof.verify(b"tampered data"));
    }

    #[test]
    fn test_verify_root() {
        let c1 = b"a";
        let c2 = b"b";
        let c3 = b"c";
        let tree = MerkleTree::build(&[c1.as_ref(), c2.as_ref(), c3.as_ref()]);

        assert!(MerkleTree::verify_root(
            &[c1.as_ref(), c2.as_ref(), c3.as_ref()],
            &tree.root_hash
        ));

        // Tampered chunk
        assert!(!MerkleTree::verify_root(
            &[c1.as_ref(), b"X".as_ref(), c3.as_ref()],
            &tree.root_hash
        ));
    }

    #[test]
    fn test_deterministic() {
        let c1 = b"data1";
        let c2 = b"data2";
        let tree1 = MerkleTree::build(&[c1.as_ref(), c2.as_ref()]);
        let tree2 = MerkleTree::build(&[c1.as_ref(), c2.as_ref()]);
        assert_eq!(tree1.root_hash, tree2.root_hash);
    }

    #[test]
    fn test_large_tree() {
        let chunks: Vec<Vec<u8>> = (0..1000)
            .map(|i| format!("chunk_number_{:04}", i).into_bytes())
            .collect();
        let refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let tree = MerkleTree::build(&refs);
        assert_eq!(tree.leaf_count, 1000);

        // Spot-check a few proofs
        for &i in &[0, 1, 499, 500, 999] {
            let proof = tree.generate_proof(i);
            assert!(proof.verify(&chunks[i]), "Proof failed for chunk {}", i);
        }
    }

    #[test]
    fn test_proof_serialization() {
        let c1 = b"test";
        let tree = MerkleTree::build(&[c1.as_ref()]);
        let proof = tree.generate_proof(0);

        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: MerkleProof = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.chunk_hash, proof.chunk_hash);
        assert_eq!(deserialized.root_hash, proof.root_hash);
        assert!(deserialized.verify(c1));
    }
}
