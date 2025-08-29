#[macro_export]
macro_rules! map_event {
    ($level:expr, $($field:expr),+) => {
        |error| ::tracing::event!($level, "{}: {}", format_args!($($field),+), error)
    };
}

#[macro_export]
macro_rules! map_error {
    ($($field:expr),+) => { $crate::map_event!(::tracing::Level::ERROR, $($field),+) };
}

#[macro_export]
macro_rules! map_warn {
    ($($field:expr),+) => { $crate::map_event!(::tracing::Level::WARN, $($field),+) };
}

#[macro_export]
macro_rules! map_info {
    ($($field:expr),+) => { $crate::map_event!(::tracing::Level::INFO, $($field),+) };
}

#[macro_export]
macro_rules! map_debug {
    ($($field:expr),+) => { $crate::map_event!(::tracing::Level::DEBUG, $($field),+) };
}

#[macro_export]
macro_rules! map_trace {
    ($($field:expr),+) => { $crate::map_event!(::tracing::Level::TRACE, $($field),+) };
}
