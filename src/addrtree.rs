//! Memory address tree: a 256-way radix tree over the 8 bytes of a 64-bit
//! address, used to count how many times each address (or address prefix)
//! occurs.
//!
//! This is binbloom's central statistical structure. Every address is stored as
//! a path of 8 nodes (one per byte, most-significant first). A leaf accumulates
//! a `votes` counter each time its full address is registered again, which lets
//! us answer "how many values start with this prefix?" in O(depth) without
//! scanning a list.
//!
//! The C implementation uses raw pointers; here children are owned `Box`es so
//! the whole tree is freed automatically and there is no `unsafe`.

/// Number of bytes (tree levels) in a full 64-bit address.
const ADDRESS_BYTES: usize = 8;

/// A single node of the address tree.
pub struct Node {
    votes: i32,
    leaf: bool,
    children: [Option<Box<Node>>; 256],
}

impl Node {
    fn new() -> Self {
        Node {
            votes: 1,
            leaf: true,
            children: std::array::from_fn(|_| None),
        }
    }

    /// Vote count carried by this node (meaningful for leaves).
    pub fn votes(&self) -> i32 {
        self.votes
    }

    /// Whether this node has no children.
    pub fn is_leaf(&self) -> bool {
        self.leaf
    }

    /// Borrow the child reached through byte `index`, if any.
    pub fn child(&self, index: usize) -> Option<&Node> {
        self.children[index].as_deref()
    }

    /// Maximum vote found among the leaves of the subtree rooted here.
    pub fn max_vote(&self) -> i32 {
        if self.leaf {
            return self.votes;
        }
        let mut max = 0;
        for child in self.children.iter().flatten() {
            let n = child.max_vote();
            if n > max {
                max = n;
            }
        }
        max
    }

    /// Number of leaves in the subtree rooted here.
    pub fn count_nodes(&self) -> usize {
        if self.leaf {
            return 1;
        }
        let mut nodes = 0;
        for child in self.children.iter().flatten() {
            nodes += child.count_nodes();
        }
        nodes
    }

    /// Remove every leaf whose vote count is strictly below `threshold`, then
    /// prune branches that become empty. A node that loses all its children
    /// turns back into a (zero-vote) leaf, exactly like the C version.
    fn filter(&mut self, threshold: i32) {
        if self.leaf {
            return;
        }

        for slot in self.children.iter_mut() {
            let drop = match slot {
                None => false,
                Some(child) if child.leaf => child.votes < threshold,
                Some(child) => {
                    child.filter(threshold);
                    // A child that collapsed into a leaf is removed regardless
                    // of its (now zero) vote count.
                    child.leaf
                }
            };
            if drop {
                *slot = None;
            }
        }

        if self.children.iter().all(Option::is_none) {
            self.leaf = true;
            self.votes = 0;
        }
    }

    /// Walk the subtree, pushing `(reconstructed_address, votes)` for each leaf.
    fn collect_leaves(&self, base: u64, out: &mut Vec<(u64, i32)>) {
        if self.leaf {
            out.push((base, self.votes));
            return;
        }
        for (k, child) in self.children.iter().enumerate() {
            if let Some(child) = child {
                child.collect_leaves((base << 8) | k as u64, out);
            }
        }
    }
}

/// A complete address tree with a tracked node count.
pub struct AddrTree {
    root: Box<Node>,
    nb_nodes: u64,
}

impl Default for AddrTree {
    fn default() -> Self {
        Self::new()
    }
}

impl AddrTree {
    /// Create an empty tree (a single root leaf).
    pub fn new() -> Self {
        AddrTree {
            root: Box::new(Node::new()),
            nb_nodes: 0,
        }
    }

    /// Borrow the root node, for callers that need to navigate manually
    /// (e.g. endianness detection).
    pub fn root(&self) -> &Node {
        &self.root
    }

    /// Register an address, creating its path if necessary and incrementing the
    /// leaf's vote count on repeat registrations.
    pub fn register_address(&mut self, address: u64) {
        let mut created = 0u64;
        let mut node = self.root.as_mut();

        for level in (0..ADDRESS_BYTES).rev() {
            let byte = ((address >> (level * 8)) & 0xff) as usize;
            if node.children[byte].is_none() {
                node.leaf = false;
                node.children[byte] = Some(Box::new(Node::new()));
                created += 1;
                node = node.children[byte].as_mut().expect("just inserted");
            } else {
                node = node.children[byte].as_mut().expect("checked is_some");
                if node.leaf {
                    node.votes += 1;
                }
            }
        }

        self.nb_nodes += created;
    }

    /// Maximum vote over all leaves.
    pub fn max_vote(&self) -> i32 {
        self.root.max_vote()
    }

    /// Number of leaves currently in the tree.
    pub fn count_nodes(&self) -> usize {
        self.root.count_nodes()
    }

    /// Approximate memory footprint, mirroring binbloom's `nb_nodes * sizeof`.
    pub fn memsize(&self) -> u64 {
        self.nb_nodes * std::mem::size_of::<Node>() as u64
    }

    /// Number of nodes ever allocated (the C `nb_nodes` field).
    pub fn nb_nodes(&self) -> u64 {
        self.nb_nodes
    }

    /// Drop every leaf below `threshold` votes and prune empty branches.
    pub fn filter(&mut self, threshold: i32) {
        self.root.filter(threshold);
    }

    /// Collect every `(address, votes)` leaf pair.
    pub fn leaves(&self) -> Vec<(u64, i32)> {
        let mut out = Vec::new();
        self.root.collect_leaves(0, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_address_one_leaf() {
        let mut t = AddrTree::new();
        t.register_address(0x1234_5678);
        let leaves = t.leaves();
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], (0x1234_5678, 1));
        assert_eq!(t.count_nodes(), 1);
        assert_eq!(t.max_vote(), 1);
        // 8 levels created for one fresh address.
        assert_eq!(t.nb_nodes(), 8);
    }

    #[test]
    fn repeated_address_accumulates_votes() {
        let mut t = AddrTree::new();
        for _ in 0..5 {
            t.register_address(0xdead_beef);
        }
        let leaves = t.leaves();
        assert_eq!(leaves, vec![(0xdead_beef, 5)]);
        assert_eq!(t.max_vote(), 5);
        // Still a single path: no new nodes after the first registration.
        assert_eq!(t.nb_nodes(), 8);
    }

    #[test]
    fn distinct_addresses_distinct_leaves() {
        let mut t = AddrTree::new();
        t.register_address(0x1000);
        t.register_address(0x2000);
        t.register_address(0x1000);
        let mut leaves = t.leaves();
        leaves.sort();
        assert_eq!(leaves, vec![(0x1000, 2), (0x2000, 1)]);
        assert_eq!(t.count_nodes(), 2);
        assert_eq!(t.max_vote(), 2);
    }

    #[test]
    fn shared_prefix_branches_late() {
        let mut t = AddrTree::new();
        // Same first 7 bytes, differ in the last.
        t.register_address(0xaabb_ccdd_eeff_0011);
        t.register_address(0xaabb_ccdd_eeff_0022);
        assert_eq!(t.count_nodes(), 2);
        // 8 nodes for the first, 1 extra leaf for the divergent last byte.
        assert_eq!(t.nb_nodes(), 9);
    }

    #[test]
    fn filter_removes_low_votes() {
        let mut t = AddrTree::new();
        t.register_address(0x10); // votes 1
        for _ in 0..4 {
            t.register_address(0x20); // votes 4
        }
        t.filter(2);
        let leaves = t.leaves();
        assert_eq!(leaves, vec![(0x20, 4)]);
        assert_eq!(t.count_nodes(), 1);
    }

    #[test]
    fn filter_can_empty_tree() {
        let mut t = AddrTree::new();
        t.register_address(0x10);
        t.register_address(0x20);
        t.filter(100);
        // Everything pruned: root collapses to a single zero-vote leaf.
        let leaves = t.leaves();
        assert_eq!(leaves, vec![(0, 0)]);
        assert_eq!(t.max_vote(), 0);
    }

    #[test]
    fn navigate_children_for_endianness() {
        let mut t = AddrTree::new();
        // High 4 bytes zero (32-bit value stored in 64-bit slot).
        t.register_address(0x0000_0000_1122_3344);
        // Descend four zero bytes from the root, as endianness detection does.
        let mut node = t.root();
        for _ in 0..4 {
            node = node.child(0).expect("zero-byte path exists");
        }
        // Next byte should be 0x11.
        assert!(node.child(0x11).is_some());
    }
}
