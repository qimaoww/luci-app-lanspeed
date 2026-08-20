//! Base-snapshot contract carried with an NSS FastRate window.
//!
//! Fast counters are keyed by MAC and direction, but a MAC alone is not
//! sufficient to carry a completed window across a concurrently published
//! runtime snapshot.  This compact contract binds each sampled MAC to the
//! daemon identity and Access Edge attachment generation that were current
//! when the worker was scheduled.

use std::collections::{BTreeMap, BTreeSet};

/// Keep an identity-bound FastRate baseline across at most this many base
/// publications that omitted the client.  The normal collection cadence is
/// one second, so this covers a short FDB/identity miss without turning the
/// worker contract into an unbounded departed-client cache.
const FAST_RATE_CONTRACT_MISSING_GRACE_GENERATIONS: u64 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FastRateClientContract {
    pub mac: [u8; 6],
    pub identity_key: String,
    pub attachment_generation: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastRateBaseContract {
    pub base_generation: u64,
    clients: BTreeMap<[u8; 6], FastRateClientContract>,
    last_present_generation: BTreeMap<[u8; 6], u64>,
    /// A duplicate MAC in the source snapshot is deliberately fail-closed.
    /// Keeping this marker lets a short-lived contract merge drop an old
    /// binding instead of silently retaining an ambiguous attribution.
    ambiguous_macs: BTreeSet<[u8; 6]>,
}

impl FastRateBaseContract {
    pub(crate) fn new(
        base_generation: u64,
        clients: impl IntoIterator<Item = FastRateClientContract>,
    ) -> Self {
        let mut unique = BTreeMap::<[u8; 6], Option<FastRateClientContract>>::new();
        let mut ambiguous_macs = BTreeSet::new();
        for client in clients {
            unique
                .entry(client.mac)
                .and_modify(|current| {
                    if current.as_ref() != Some(&client) {
                        *current = None;
                        ambiguous_macs.insert(client.mac);
                    }
                })
                .or_insert(Some(client));
        }
        let clients = unique
            .into_iter()
            .filter_map(|(mac, client)| client.map(|client| (mac, client)))
            .collect::<BTreeMap<_, _>>();
        let last_present_generation = clients
            .keys()
            .copied()
            .map(|mac| (mac, base_generation))
            .collect();
        Self {
            base_generation,
            clients,
            last_present_generation,
            ambiguous_macs,
        }
    }

    /// Carry bindings through a transient base snapshot that omitted a
    /// client.  The current snapshot always wins for a MAC; an explicitly
    /// ambiguous MAC is removed so a duplicate cannot inherit an old rate.
    /// The generation is retargeted to the current base snapshot while the
    /// identity and attachment generation remain immutable evidence.
    pub(crate) fn retain_missing_from(&self, current: &Self) -> Self {
        let mut clients = self.clients.clone();
        let mut last_present_generation = self.last_present_generation.clone();
        clients.retain(|mac, _| {
            last_present_generation
                .get(mac)
                .is_some_and(|last_present| {
                    current.base_generation.saturating_sub(*last_present)
                        <= FAST_RATE_CONTRACT_MISSING_GRACE_GENERATIONS
                })
        });
        last_present_generation.retain(|mac, _| clients.contains_key(mac));
        for mac in &current.ambiguous_macs {
            clients.remove(mac);
            last_present_generation.remove(mac);
        }
        for (mac, client) in &current.clients {
            clients.insert(*mac, client.clone());
            last_present_generation.insert(
                *mac,
                current
                    .last_present_generation
                    .get(mac)
                    .copied()
                    .unwrap_or(current.base_generation),
            );
        }
        Self {
            base_generation: current.base_generation,
            clients,
            last_present_generation,
            ambiguous_macs: current.ambiguous_macs.clone(),
        }
    }

    pub(crate) fn client_matches(
        &self,
        mac: [u8; 6],
        identity_key: &str,
        attachment_generation: u64,
    ) -> bool {
        self.clients.get(&mac).is_some_and(|client| {
            client.identity_key == identity_key
                && client.attachment_generation == attachment_generation
        })
    }

    pub(crate) fn client(&self, mac: [u8; 6]) -> Option<&FastRateClientContract> {
        self.clients.get(&mac)
    }

    pub(crate) fn client_macs(&self) -> impl Iterator<Item = [u8; 6]> + '_ {
        self.clients.keys().copied()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.clients.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{FastRateBaseContract, FastRateClientContract};

    fn client(mac: [u8; 6], identity: &str, generation: u64) -> FastRateClientContract {
        FastRateClientContract {
            mac,
            identity_key: identity.into(),
            attachment_generation: generation,
        }
    }

    #[test]
    fn matches_identity_and_attachment_generation_not_only_mac() {
        let mac = [2, 0, 0, 0, 0, 1];
        let contract = FastRateBaseContract::new(7, [client(mac, "client@lan", 11)]);
        assert!(contract.client_matches(mac, "client@lan", 11));
        assert!(!contract.client_matches(mac, "replacement@lan", 11));
        assert!(!contract.client_matches(mac, "client@lan", 12));
    }

    #[test]
    fn excludes_an_ambiguous_mac_contract() {
        let mac = [2, 0, 0, 0, 0, 1];
        let contract = FastRateBaseContract::new(
            7,
            [client(mac, "first@lan", 1), client(mac, "second@lan", 1)],
        );
        assert_eq!(contract.len(), 0);
        assert!(!contract.client_matches(mac, "first@lan", 1));
    }

    #[test]
    fn retains_a_missing_client_but_replaces_changed_attachment() {
        let desktop = [2, 0, 0, 0, 0, 1];
        let phone = [2, 0, 0, 0, 0, 2];
        let previous = FastRateBaseContract::new(
            7,
            [
                client(desktop, "desktop@lan", 11),
                client(phone, "phone@lan", 3),
            ],
        );
        let current = FastRateBaseContract::new(8, [client(desktop, "desktop@lan", 12)]);
        let merged = previous.retain_missing_from(&current);
        assert_eq!(merged.base_generation, 8);
        assert!(merged.client_matches(desktop, "desktop@lan", 12));
        assert!(merged.client_matches(phone, "phone@lan", 3));
    }

    #[test]
    fn ambiguous_current_mac_drops_the_retained_binding() {
        let mac = [2, 0, 0, 0, 0, 1];
        let previous = FastRateBaseContract::new(7, [client(mac, "old@lan", 1)]);
        let current = FastRateBaseContract::new(
            8,
            [client(mac, "first@lan", 1), client(mac, "second@lan", 1)],
        );
        let merged = previous.retain_missing_from(&current);
        assert_eq!(merged.len(), 0);
    }

    #[test]
    fn missing_binding_expires_after_the_bounded_base_generation_grace() {
        let mac = [2, 0, 0, 0, 0, 1];
        let previous = FastRateBaseContract::new(7, [client(mac, "client@lan", 1)]);
        let within_grace = previous.retain_missing_from(&FastRateBaseContract::new(10, []));
        assert!(within_grace.client_matches(mac, "client@lan", 1));
        let expired = within_grace.retain_missing_from(&FastRateBaseContract::new(11, []));
        assert_eq!(expired.len(), 0);
    }
}
