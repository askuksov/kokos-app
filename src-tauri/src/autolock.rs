use std::time::Duration;

/// Decide whether the vault should auto-lock now. Pure so it is unit-testable
/// without a running app: the background watcher computes the three
/// inputs each tick and calls this. `minutes == 0` means auto-lock disabled.
pub fn should_lock(vault_open: bool, elapsed: Duration, minutes: u32) -> bool {
    vault_open && minutes > 0 && elapsed >= Duration::from_secs(minutes as u64 * 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test] fn locks_after_timeout_when_open() {
        assert!(should_lock(true, Duration::from_secs(16 * 60), 15));
    }
    #[test] fn not_before_timeout() {
        assert!(!should_lock(true, Duration::from_secs(14 * 60), 15));
    }
    #[test] fn never_when_disabled() { assert!(!should_lock(true, Duration::from_secs(999 * 60), 0)); }
    #[test] fn never_when_closed() { assert!(!should_lock(false, Duration::from_secs(999 * 60), 15)); }
}
