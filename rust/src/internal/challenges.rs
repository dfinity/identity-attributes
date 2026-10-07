use std::collections::BTreeMap;

/// The most nonces held at once; issuing past it evicts the oldest.
pub(crate) const MAX_TOTAL: usize = 4096;

/// How long a nonce stays redeemable: the bundle freshness window, past which
/// it could not be redeemed anyway.
pub(crate) const EXPIRY_NS: u64 = 5 * 60 * 1_000_000_000;

/// Single-use nonces this canister issued, with the time each was issued.
///
/// Nonces come from the canister, never the frontend: a frontend nonce gives
/// the canister no way to tell a fresh sign-in from a replayed bundle. They
/// are not keyed by principal, because the start call is anonymous and the
/// finish call is not; the bundle signature binds it to the finishing caller.
#[derive(Default)]
pub(crate) struct Challenges(BTreeMap<Vec<u8>, u64>);

impl Challenges {
    /// Adds `nonce`, after dropping expired ones and, at capacity, the oldest.
    pub(crate) fn issue(&mut self, nonce: Vec<u8>, now: u64) {
        self.prune(now);
        if self.0.len() >= MAX_TOTAL {
            let oldest = self
                .0
                .iter()
                .min_by_key(|(_, issued_at)| **issued_at)
                .map(|(nonce, _)| nonce.clone());
            if let Some(oldest) = oldest {
                self.0.remove(&oldest);
            }
        }
        self.0.insert(nonce, now);
    }

    /// Removes `nonce`, after dropping expired ones. `false` when it was never
    /// issued, already consumed, or expired.
    pub(crate) fn consume(&mut self, nonce: &[u8], now: u64) -> bool {
        self.prune(now);
        self.0.remove(nonce).is_some()
    }

    fn prune(&mut self, now: u64) {
        self.0
            .retain(|_, issued_at| now.saturating_sub(*issued_at) <= EXPIRY_NS);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000_000_000;

    #[test]
    fn a_nonce_is_consumed_once() {
        let mut challenges = Challenges::default();
        assert!(!challenges.consume(b"alpha", NOW));

        challenges.issue(b"n1".to_vec(), NOW);
        challenges.issue(b"n2".to_vec(), NOW);
        assert!(!challenges.consume(b"missing", NOW));
        assert_eq!(challenges.len(), 2);

        assert!(challenges.consume(b"n1", NOW));
        assert_eq!(challenges.len(), 1);
        assert!(!challenges.consume(b"n1", NOW));
    }

    #[test]
    fn an_expired_nonce_is_pruned_on_the_next_call() {
        let mut challenges = Challenges::default();
        challenges.issue(b"old".to_vec(), NOW - 10 * 60 * 1_000_000_000);
        challenges.issue(b"fresh".to_vec(), NOW);
        assert!(challenges.consume(b"fresh", NOW));
        assert_eq!(challenges.len(), 0);
    }

    #[test]
    fn a_nonce_is_redeemable_up_to_the_expiry() {
        let mut challenges = Challenges::default();
        challenges.issue(b"edge".to_vec(), NOW);
        assert!(challenges.consume(b"edge", NOW + EXPIRY_NS));

        challenges.issue(b"late".to_vec(), NOW);
        assert!(!challenges.consume(b"late", NOW + EXPIRY_NS + 1));
    }

    #[test]
    fn issuing_at_capacity_evicts_the_oldest() {
        let mut challenges = Challenges::default();
        for i in 0..MAX_TOTAL as u64 {
            challenges.issue(i.to_be_bytes().to_vec(), NOW + i);
        }
        assert_eq!(challenges.len(), MAX_TOTAL);

        challenges.issue(b"newest".to_vec(), NOW + MAX_TOTAL as u64);
        assert_eq!(challenges.len(), MAX_TOTAL);
        assert!(!challenges.consume(&0u64.to_be_bytes(), NOW + MAX_TOTAL as u64));
        assert!(challenges.consume(&1u64.to_be_bytes(), NOW + MAX_TOTAL as u64));
        assert!(challenges.consume(b"newest", NOW + MAX_TOTAL as u64));
    }
}
