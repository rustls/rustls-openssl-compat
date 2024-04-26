use std::time::SystemTime;

#[derive(Debug, Clone, Copy)]
pub struct ExpiryTime(pub u64);

impl ExpiryTime {
    fn calculate(now: TimeBase, life_time_secs: u64) -> ExpiryTime {
        ExpiryTime(now.0.saturating_add(life_time_secs))
    }

    pub fn in_past(&self, time: TimeBase) -> bool {
        self.0 < time.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TimeBase(u64);

impl TimeBase {
    pub fn now() -> Self {
        Self(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|n| n.as_secs())
                .unwrap_or_default(),
        )
    }
}
