use super::*;

/// Create utility to start and await cancellation
pub fn cancellation() -> (CancellationRoot, CancellationUnit) {
    let (tx, rx) = oneshot::channel();
    let token = CancellationToken::new();

    (
        CancellationRoot {
            channel: Some(rx),
            token: token.clone(),
        },
        CancellationUnit {
            unit: Arc::new((token, CancellationGuard { channel: Some(tx) })),
        },
    )
}

pub struct CancellationRoot {
    channel: Option<oneshot::Receiver<()>>,
    token: CancellationToken,
}

impl CancellationRoot {
    /// Start cancellation and await all `CancellationUnit` instances to go out of scope
    pub async fn cancel(&mut self) {
        self.token.cancel();
        if let Some(channel) = self.channel.take() {
            channel.await.ok();
        }
    }
}

pub struct CancellationUnit {
    unit: Arc<(CancellationToken, CancellationGuard)>,
}

impl Deref for CancellationUnit {
    type Target = CancellationToken;

    fn deref(&self) -> &Self::Target {
        &self.unit.0
    }
}

impl Clone for CancellationUnit {
    fn clone(&self) -> Self {
        Self {
            unit: self.unit.clone(),
        }
    }
}

pub struct CancellationGuard {
    channel: Option<oneshot::Sender<()>>,
}

impl Drop for CancellationGuard {
    fn drop(&mut self) {
        self.channel.take().map(|c| c.send(()));
    }
}
