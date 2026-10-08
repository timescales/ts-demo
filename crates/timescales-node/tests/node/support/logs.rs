//! A `tracing` subscriber that keeps every formatted event and span field,
//! for `no_secrets_in_logs`. It is the global default, so it sees every
//! thread: the test's own, the blocking pool (relay close, header assembly,
//! relay restore) and the store's threads. The other tests of this binary
//! run at the same time and are captured too. Their nodes hold the same
//! deterministic keys, so a secret any of them logs is a finding as well.

use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

#[derive(Clone, Default)]
pub struct Captured(pub Arc<Mutex<String>>);

impl Captured {
    pub fn text(&self) -> String {
        self.0.lock().clone()
    }
}

struct Fields<'a>(&'a mut String);

impl Visit for Fields<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn core::fmt::Debug) {
        let _ = write!(self.0, " {}={:?}", field.name(), value);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let _ = write!(self.0, " {}={}", field.name(), value);
    }
}

/// Captures everything at every level from every thread.
pub struct Capture {
    out: Captured,
    next: AtomicU64,
}

/// Installs the global capture. `None` if a global subscriber is already
/// set.
pub fn capture_all() -> Option<Captured> {
    let out = Captured::default();
    let capture = Capture {
        out: out.clone(),
        next: AtomicU64::new(1),
    };
    tracing::subscriber::set_global_default(capture).ok()?;
    Some(out)
}

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, span: &Attributes<'_>) -> Id {
        let id = Id::from_u64(self.next.fetch_add(1, Ordering::Relaxed));
        let mut line = format!("span {}", span.metadata().name());
        span.record(&mut Fields(&mut line));
        line.push('\n');
        self.out.0.lock().push_str(&line);
        id
    }

    fn record(&self, _: &Id, values: &Record<'_>) {
        let mut line = String::from("record");
        values.record(&mut Fields(&mut line));
        line.push('\n');
        self.out.0.lock().push_str(&line);
    }

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut line = format!("{} {}", event.metadata().level(), event.metadata().target());
        event.record(&mut Fields(&mut line));
        let _ = write!(
            line,
            " thread={}",
            std::thread::current().name().unwrap_or("unnamed")
        );
        line.push('\n');
        self.out.0.lock().push_str(&line);
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}
