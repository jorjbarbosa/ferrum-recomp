// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! A small seeded generator, so that a seed and a count always give the same program.

/// SplitMix64 (Steele, Lea and Flood, 2014): 64 bits of state and a fixed output function.
///
/// Every draw is integer arithmetic, so the sequence is the same on every host.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// A generator whose sequence depends only on `seed`.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number in `0..n`. `n` must not be zero.
    pub fn below(&mut self, n: u32) -> u32 {
        assert!(n > 0, "below(0) has no value to return");
        // The high 32 bits scaled to `0..n`, which keeps the bias below 2^-32 per value.
        let high = self.next_u64() >> 32;
        // `high * n` is below 2^64, and the shift brings it below `n`.
        ((high * u64::from(n)) >> 32) as u32
    }

    /// A number in `low..=high`.
    pub fn between(&mut self, low: u32, high: u32) -> u32 {
        low + self.below(high - low + 1)
    }

    /// True with a chance of `per_mille` in 1000.
    pub fn chance(&mut self, per_mille: u32) -> bool {
        self.below(1000) < per_mille
    }

    /// One of the values, each with its weight.
    pub fn pick<T: Copy>(&mut self, weighted: &[(u32, T)]) -> T {
        let total: u32 = weighted.iter().map(|&(weight, _)| weight).sum();
        let mut draw = self.below(total);
        for &(weight, value) in weighted {
            if draw < weight {
                return value;
            }
            draw -= weight;
        }
        unreachable!("the draw is below the sum of the weights")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sequence_is_splitmix64() {
        // The first outputs for seed 0 of the published algorithm.
        let mut rng = Rng::new(0);
        assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
    }

    #[test]
    fn draws_stay_in_their_ranges_and_reach_both_ends() {
        let mut rng = Rng::new(7);
        let mut seen = [false; 5];
        for _ in 0..1000 {
            let value = rng.between(3, 7);
            assert!((3..=7).contains(&value));
            seen[(value - 3) as usize] = true;
        }
        assert!(seen.iter().all(|&s| s));
        let picks = (0..1000)
            .filter(|_| rng.pick(&[(1, false), (3, true)]))
            .count();
        assert!((650..850).contains(&picks), "{picks}");
    }
}
