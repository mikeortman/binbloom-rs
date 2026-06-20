//! Shannon entropy of a byte buffer, normalised to `[0, 1]`.
//!
//! Mirrors binbloom's `entropy()` helper (Shannon entropy in bits per byte,
//! divided by 8 so a uniform distribution over 256 symbols maps to 1.0).

/// Stateless entropy calculator.
pub struct Entropy;

impl Entropy {
    /// Normalised Shannon entropy of `data` in the range `[0.0, 1.0]`.
    ///
    /// An empty slice yields `0.0` (the C code would divide by zero here).
    pub fn shannon(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }

        let size = data.len() as f64;
        let mut h = 0.0;
        for &c in counts.iter() {
            if c > 0 {
                let p = c as f64 / size;
                h -= p * p.log2();
            }
        }

        h / 8.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(Entropy::shannon(&[]), 0.0);
    }

    #[test]
    fn uniform_single_symbol_is_zero() {
        // All identical bytes: zero entropy.
        assert_eq!(Entropy::shannon(&[0x41; 1024]), 0.0);
    }

    #[test]
    fn full_byte_range_is_one() {
        // Every byte value exactly once -> maximal entropy (8 bits/byte -> 1.0).
        let data: Vec<u8> = (0..=255u8).collect();
        let h = Entropy::shannon(&data);
        assert!((h - 1.0).abs() < 1e-9, "entropy was {h}");
    }

    #[test]
    fn two_symbols_half_each_is_one_eighth() {
        // Two equally likely symbols -> 1 bit/byte -> 1/8 normalised.
        let mut data = vec![0u8; 512];
        data.extend(std::iter::repeat(1u8).take(512));
        let h = Entropy::shannon(&data);
        assert!((h - 0.125).abs() < 1e-9, "entropy was {h}");
    }

    #[test]
    fn low_entropy_below_uninit_threshold() {
        // Mostly zeros with a sprinkle of noise stays well under 0.05.
        let mut data = vec![0u8; 1024];
        data[0] = 1;
        data[1] = 2;
        assert!(Entropy::shannon(&data) < 0.05);
    }
}
