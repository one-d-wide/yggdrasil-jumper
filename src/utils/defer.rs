use super::*;

/// Execute provided closure when [`DeferGuard`] goes out of scope.
#[must_use]
pub fn defer<F>(closure: F) -> DeferGuard<F>
where
    F: FnOnce(),
{
    DeferGuard {
        closure: Some(closure),
    }
}

pub struct DeferGuard<F>
where
    F: FnOnce(),
{
    closure: Option<F>,
}

impl<F> DeferGuard<F>
where
    F: FnOnce(),
{
    pub fn forget(&mut self) {
        self.closure.take();
    }
}

impl<F> Drop for DeferGuard<F>
where
    F: FnOnce(),
{
    fn drop(&mut self) {
        if let Some(closure) = self.closure.take() {
            closure()
        }
    }
}

/// Execute provided function `func` with argument `arg` when [`DeferArgGuard`] goes out of scope.
/// Value `arg` can be accessed via [`Deref`] and [`DerefMut`] traits.
#[must_use]
pub fn defer_arg<T>(arg: T, func: fn(T)) -> DeferArgGuard<T> {
    DeferArgGuard {
        active: true,
        arg: Some(arg),
        func,
    }
}

pub struct DeferArgGuard<T> {
    active: bool,
    arg: Option<T>,
    func: fn(T),
}

impl<T> DeferArgGuard<T> {
    pub fn forget(&mut self) {
        self.active = false;
    }
}

impl<T> Deref for DeferArgGuard<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.arg.as_ref().unwrap()
    }
}

impl<T> DerefMut for DeferArgGuard<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.arg.as_mut().unwrap()
    }
}

impl<T> Drop for DeferArgGuard<T> {
    fn drop(&mut self) {
        if let Some(arg) = self.active.then_some(self.arg.take().unwrap()) {
            (self.func)(arg);
        }
    }
}

/// Call [`tokio::spawn`] with future `fut` as an argument when [`DeferGuard`] goes out of scope.
#[must_use]
pub fn defer_async<Fut>(fut: Fut) -> DeferGuard<impl FnOnce()>
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    defer(|| {
        spawn(fut);
    })
}
