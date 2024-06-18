use super::*;

/// Create utility to start and await cancellation
pub fn cancellation() -> (CancellationRoot, PassiveCancellationToken) {
    let (tx, rx) = oneshot::channel();
    let notify = Notify::new();
    let guard = Arc::new(CancellationGuard {
        notify,
        channel: Some(tx),
    });
    let weak_guard = Arc::downgrade(&guard);

    (
        CancellationRoot {
            channel: Some(rx),
            active_unit: Some(ActiveCancellationToken { guard }),
        },
        PassiveCancellationToken { guard: weak_guard },
    )
}

pub struct CancellationRoot {
    channel: Option<oneshot::Receiver<()>>,
    active_unit: Option<ActiveCancellationToken>,
}

impl CancellationRoot {
    /// Start send cancellation signal and wait for all instances of [`ActiveCancellationToken`] to go out of scope
    pub async fn cancel(&mut self) {
        // Send cancellation signal and drop original active token
        if let Some(unit) = self.active_unit.take() {
            unit.guard.notify.notify_waiters();
        }
        // Await graceful cancellation
        if let Some(channel) = self.channel.take() {
            channel.await.ok();
        }
    }
}

pub struct CancellationGuard {
    notify: Notify,
    channel: Option<oneshot::Sender<()>>,
}

impl Drop for CancellationGuard {
    fn drop(&mut self) {
        self.channel.take().map(|c| c.send(()));
    }
}

pub struct ActiveCancellationToken {
    guard: Arc<CancellationGuard>,
}

impl ActiveCancellationToken {
    pub fn get_passive(&self) -> PassiveCancellationToken {
        PassiveCancellationToken {
            guard: Arc::downgrade(&self.guard),
        }
    }
    pub async fn cancelled(&self) {
        self.guard.notify.notified().await
    }
}

impl Clone for ActiveCancellationToken {
    fn clone(&self) -> Self {
        Self {
            guard: self.guard.clone(),
        }
    }
}

pub struct PassiveCancellationToken {
    guard: Weak<CancellationGuard>,
}

impl PassiveCancellationToken {
    pub fn get_active(&self) -> Option<ActiveCancellationToken> {
        self.guard
            .upgrade()
            .map(|guard| ActiveCancellationToken { guard })
    }
    pub async fn cancelled(&self) {
        if let Some(unit) = self.get_active() {
            unit.guard.notify.notified().await
        }
    }
}

impl Clone for PassiveCancellationToken {
    fn clone(&self) -> Self {
        Self {
            guard: self.guard.clone(),
        }
    }
}
