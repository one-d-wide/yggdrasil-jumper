#[macro_export]
macro_rules! map_event {
    ($level:expr, $($field:expr),+) => {
        |error| event!($level, "{}: {}", format_args!($($field),+), error)
    };
}

#[macro_export]
macro_rules! map_error {
    ($($field:expr),+) => { map_event!(Level::ERROR, $($field),+) };
}
#[macro_export]
macro_rules! map_warn {
    ($($field:expr),+) => { map_event!(Level::WARN, $($field),+) };
}
#[macro_export]
macro_rules! map_info {
    ($($field:expr),+) => { map_event!(Level::INFO, $($field),+) };
}
#[macro_export]
macro_rules! map_debug {
    ($($field:expr),+) => { map_event!(Level::DEBUG, $($field),+) };
}
#[macro_export]
macro_rules! map_trace {
    ($($field:expr),+) => { map_event!(Level::TRACE, $($field),+) };
}
