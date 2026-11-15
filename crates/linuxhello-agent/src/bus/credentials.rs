//! Cache of caller credentials by unique bus name.
//!
//! Collaborators: `crate::api::Caller`.

use crate::api::Caller;
use std::collections::HashMap;

/// Caller credentials by unique bus name; a unique name is never reused during the life of a bus.
/// Until eviction on `NameOwnerChanged` is wired, the cache has no size limit: it must not be used in `AgentService` before that slice.
#[derive(Debug, Default)]
pub struct CallerCache {
    /// The mapping from unique bus names to their cached credentials.
    entries: HashMap<String, Caller>,
}

impl CallerCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// The caller stored for `unique_name`, or `None` when there is no entry.
    pub fn get(&self, unique_name: &str) -> Option<Caller> {
        self.entries.get(unique_name).copied()
    }

    /// Stores `caller` for `unique_name`, replacing any entry.
    pub fn insert(&mut self, unique_name: &str, caller: Caller) {
        self.entries.insert(unique_name.to_string(), caller);
    }

    /// Drops the entry of `unique_name`; nothing happens when there is none.
    pub fn evict(&mut self, unique_name: &str) {
        self.entries.remove(unique_name);
    }

    /// Drops every entry.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Helper to simulate the interface lookup logic.
    fn through(cache: &mut CallerCache, name: &str, lookups: &Cell<u32>, answer: Caller) -> Caller {
        if let Some(cached) = cache.get(name) {
            cached
        } else {
            lookups.set(lookups.get() + 1);
            cache.insert(name, answer);
            answer
        }
    }

    #[test]
    fn credentials_are_looked_up_once_per_connection() {
        let mut cache = CallerCache::new();
        let lookups = Cell::new(0);
        let answer = Caller { uid: Some(1000) };

        // First three calls for ":1.3" should only trigger 1 lookup.
        through(&mut cache, ":1.3", &lookups, answer);
        through(&mut cache, ":1.3", &lookups, answer);
        through(&mut cache, ":1.3", &lookups, answer);
        assert_eq!(lookups.get(), 1);

        // A new connection ":1.4" should trigger a second lookup.
        through(&mut cache, ":1.4", &lookups, Caller { uid: Some(1001) });
        assert_eq!(lookups.get(), 2);
    }

    #[test]
    fn a_caller_without_credentials_is_cached_as_refused() {
        let mut cache = CallerCache::new();
        let lookups = Cell::new(0);
        let refused = Caller { uid: None };

        // Insert a refused caller.
        cache.insert(":1.3", refused);

        // get(":1.3") should return the cached None, not trigger a lookup.
        // We use a manual get here to verify the cache state.
        assert_eq!(cache.get(":1.3"), Some(Caller { uid: None }));

        // A completely new name should still return None (no entry).
        assert_eq!(cache.get(":1.9"), None);
        assert_eq!(lookups.get(), 0);
    }

    #[test]
    fn cached_credentials_are_dropped_when_the_peer_leaves() {
        let mut cache = CallerCache::new();
        let lookups = Cell::new(0);

        through(&mut cache, ":1.3", &lookups, Caller { uid: Some(1000) });
        through(&mut cache, ":1.4", &lookups, Caller { uid: Some(1001) });
        assert_eq!(lookups.get(), 2);

        // Evict ":1.3".
        cache.evict(":1.3");
        assert_eq!(cache.get(":1.3"), None);
        // ":1.4" should still be there.
        assert_eq!(cache.get(":1.4"), Some(Caller { uid: Some(1001) }));

        // Re-lookup ":1.3" should increment lookups.
        through(&mut cache, ":1.3", &lookups, Caller { uid: Some(1000) });
        assert_eq!(lookups.get(), 3);

        // Evicting twice should not panic.
        cache.evict(":1.4");
        cache.evict(":1.4");
    }

    #[test]
    fn clear_drops_every_entry() {
        let mut cache = CallerCache::new();
        cache.insert(":1.1", Caller { uid: Some(1) });
        cache.insert(":1.2", Caller { uid: Some(2) });

        cache.clear();

        assert_eq!(cache.get(":1.1"), None);
        assert_eq!(cache.get(":1.2"), None);
    }
}
