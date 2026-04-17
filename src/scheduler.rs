use crate::config::ScheduleConfig;
use crate::history::Store;
use std::collections::VecDeque;

pub struct ScanRequest {
    pub target_name: String,
    pub profile_name: String,
}

struct ScheduleEntry {
    config: ScheduleConfig,
    next_run: i64,
}

pub struct Scheduler {
    entries: Vec<ScheduleEntry>,
    queue: VecDeque<ScanRequest>,
}

impl Scheduler {
    pub fn new(schedules: &[ScheduleConfig], store: &Store) -> Self {
        let now = crate::history::now_secs();
        let entries = schedules
            .iter()
            .filter(|s| s.enabled)
            .map(|s| {
                let last_run = store
                    .latest_scan_for(&s.target, &s.profile)
                    .unwrap_or(None);
                let next_run = match last_run {
                    Some(t) => t + s.interval_secs as i64,
                    None => now,
                };
                ScheduleEntry {
                    config: s.clone(),
                    next_run,
                }
            })
            .collect();
        Self {
            entries,
            queue: VecDeque::new(),
        }
    }

    pub fn tick(&mut self, now: i64) -> Option<ScanRequest> {
        if let Some(req) = self.queue.pop_front() {
            return Some(req);
        }
        for entry in &mut self.entries {
            if now >= entry.next_run {
                entry.next_run = now + entry.config.interval_secs as i64;
                return Some(ScanRequest {
                    target_name: entry.config.target.clone(),
                    profile_name: entry.config.profile.clone(),
                });
            }
        }
        None
    }

    pub fn notify_complete(&mut self, target: &str, profile: &str, now: i64) {
        for entry in &mut self.entries {
            if entry.config.target == target && entry.config.profile == profile {
                entry.next_run = now + entry.config.interval_secs as i64;
            }
        }
    }

    pub fn next_due(&self) -> Option<(i64, &str, &str)> {
        self.entries
            .iter()
            .min_by_key(|e| e.next_run)
            .map(|e| (e.next_run, e.config.target.as_str(), e.config.profile.as_str()))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history;

    fn tmp_store() -> Store {
        let dir = std::env::temp_dir().join(format!("netscan-sched-{}", history::short_id()));
        std::fs::create_dir_all(&dir).unwrap();
        Store::open(&dir.join("h.db")).unwrap()
    }

    #[test]
    fn fires_immediately_when_never_run() {
        let store = tmp_store();
        let schedules = vec![ScheduleConfig {
            target: "home-lan".into(),
            profile: "quick".into(),
            interval_secs: 3600,
            enabled: true,
        }];
        let mut sched = Scheduler::new(&schedules, &store);
        let now = history::now_secs();
        let req = sched.tick(now);
        assert!(req.is_some());
        let req = req.unwrap();
        assert_eq!(req.target_name, "home-lan");
        assert_eq!(req.profile_name, "quick");
    }

    #[test]
    fn does_not_fire_before_interval() {
        let store = tmp_store();
        let schedules = vec![ScheduleConfig {
            target: "home-lan".into(),
            profile: "quick".into(),
            interval_secs: 3600,
            enabled: true,
        }];
        let mut sched = Scheduler::new(&schedules, &store);
        let now = history::now_secs();
        let _ = sched.tick(now);
        sched.notify_complete("home-lan", "quick", now);
        assert!(sched.tick(now + 100).is_none());
    }

    #[test]
    fn fires_after_interval() {
        let store = tmp_store();
        let schedules = vec![ScheduleConfig {
            target: "home-lan".into(),
            profile: "quick".into(),
            interval_secs: 3600,
            enabled: true,
        }];
        let mut sched = Scheduler::new(&schedules, &store);
        let now = history::now_secs();
        let _ = sched.tick(now);
        sched.notify_complete("home-lan", "quick", now);
        let req = sched.tick(now + 3601);
        assert!(req.is_some());
    }

    #[test]
    fn disabled_schedules_ignored() {
        let store = tmp_store();
        let schedules = vec![ScheduleConfig {
            target: "home-lan".into(),
            profile: "quick".into(),
            interval_secs: 3600,
            enabled: false,
        }];
        let sched = Scheduler::new(&schedules, &store);
        assert!(sched.is_empty());
    }
}
