// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jorge Barbosa

//! The time base that `mftb` reads.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Frequency of the Xbox 360 time base, in ticks per second.
pub const TIME_BASE_HZ: u64 = 50_000_000;

/// A source for the 64-bit time base register.
///
/// Every thread has to read the same clock, so a [`crate::PpcContext`] holds one through an
/// `Arc`. A port can supply its own, to slow time down for example, and tests a fixed one.
pub trait TimeBase: Send + Sync {
    /// Returns the time base: ticks of [`TIME_BASE_HZ`] since some fixed point.
    fn read(&self) -> u64;
}

/// The default time base: ticks since the moment it was created, measured with [`Instant`].
#[derive(Debug, Clone, Copy)]
pub struct HostTimeBase {
    epoch: Instant,
}

impl HostTimeBase {
    /// Starts a time base at zero now.
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }
}

impl Default for HostTimeBase {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeBase for HostTimeBase {
    fn read(&self) -> u64 {
        ticks(self.epoch.elapsed())
    }
}

/// Returns the [`HostTimeBase`] of the process, created on first use, which every
/// [`crate::PpcContext::new`] shares.
pub fn host_time_base() -> Arc<dyn TimeBase> {
    static SHARED: OnceLock<Arc<HostTimeBase>> = OnceLock::new();
    let shared = SHARED.get_or_init(|| Arc::new(HostTimeBase::new()));
    Arc::clone(shared) as Arc<dyn TimeBase>
}

/// Converts a duration into time base ticks, saturating after some 11,000 years.
fn ticks(elapsed: Duration) -> u64 {
    const NANOS_PER_TICK: u128 = 1_000_000_000 / TIME_BASE_HZ as u128;
    u64::try_from(elapsed.as_nanos() / NANOS_PER_TICK).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tick_is_20_nanoseconds() {
        assert_eq!(ticks(Duration::from_secs(1)), TIME_BASE_HZ);
        assert_eq!(ticks(Duration::from_nanos(19)), 0);
        assert_eq!(ticks(Duration::from_nanos(20)), 1);
        assert_eq!(ticks(Duration::from_nanos(39)), 1);
        assert_eq!(ticks(Duration::MAX), u64::MAX);
    }

    #[test]
    fn the_host_time_base_never_goes_back() {
        let clock = host_time_base();
        let mut last = clock.read();
        for _ in 0..1000 {
            let now = clock.read();
            assert!(now >= last);
            last = now;
        }
    }

    #[test]
    fn the_process_has_one_host_time_base() {
        let a = host_time_base();
        let b = host_time_base();
        assert!(std::ptr::addr_eq(Arc::as_ptr(&a), Arc::as_ptr(&b)));
    }
}
