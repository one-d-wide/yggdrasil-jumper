use super::*;

/// Call `tokio::spawn(f)` for given async closure `f`
/// when `DeferGuard` goes out of scope.
#[must_use]
pub fn defer_async<F>(f: F) -> DeferGuard<impl FnOnce(), ()>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    defer(move || {
        spawn(f);
    })
}

/// Execute provided closure `f`
/// when `DeferGuard` goes out of scope.
#[must_use]
pub fn defer<F, T>(f: F) -> DeferGuard<F, T>
where
    F: FnOnce() -> T,
{
    DeferGuard { f: Some(f) }
}

pub struct DeferGuard<F, T>
where
    F: FnOnce() -> T,
{
    f: Option<F>,
}

impl<F, T> DeferGuard<F, T>
where
    F: FnOnce() -> T,
{
    pub fn forget(&mut self) {
        self.f.take();
    }
}

impl<F, T> Drop for DeferGuard<F, T>
where
    F: FnOnce() -> T,
{
    fn drop(&mut self) {
        self.f.take().map(|f| f());
    }
}
