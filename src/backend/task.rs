use once_cell::sync::Lazy;

/// Task queue
pub static TASK: Lazy<RwLock<Option<Sender<Option<WriteSegment>>>>> =
    Lazy::new(|| RwLock::new(None));
