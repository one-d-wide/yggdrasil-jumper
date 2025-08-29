use std::{future::Future, io::ErrorKind, time::Duration};

use crate::IoResult;

/// Same as [`tokio::time::timeout`], but flattens the result type
pub async fn timeout<T>(
    duration: Duration,
    future: impl Future<Output = IoResult<T>>,
) -> IoResult<T> {
    match tokio::time::timeout(duration, future).await {
        Ok(res) => res,
        Err(_) => Err(ErrorKind::TimedOut.into()),
    }
}

/// Exponential timeout of base 2.
///
/// Upholds property, that max total time equals retry time (t) * cycle count (n):
///     total_time = t * n = t1 + t2 + ... + t_n = t0 * (1 + 2 + 4 + ... + 2^(n-1))
pub struct Timeout {
    /// t_0 = t * n / (2^n - 1)
    t0: Duration,
    /// n - i
    cycles_left: u32,
    /// t_i = t_0 * 2^i
    next_scale: Option<f32>,
}

impl Timeout {
    pub fn new_exponential(retry_time: Duration, cycle_count: u32) -> Self {
        Timeout {
            t0: retry_time
                .checked_mul(cycle_count)
                .unwrap()
                .div_f64(2f64.powf(cycle_count as f64) - 1f64),
            cycles_left: cycle_count,
            next_scale: Some(1f32),
        }
    }

    pub fn new_linear(retry_time: Duration, cycle_count: u32) -> Self {
        Timeout {
            t0: retry_time,
            cycles_left: cycle_count,
            next_scale: None,
        }
    }

    pub fn new(retry_time: Duration, cycle_count: u32, is_exponential: bool) -> Self {
        if is_exponential {
            Self::new_exponential(retry_time, cycle_count)
        } else {
            Self::new_linear(retry_time, cycle_count)
        }
    }
}

impl std::iter::Iterator for Timeout {
    type Item = Duration;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cycles_left == 0 {
            return None;
        }
        self.cycles_left -= 1;
        match &mut self.next_scale {
            Some(scale) => {
                let res = self.t0.mul_f32(*scale);
                *scale *= 2f32;
                Some(res)
            }
            None => Some(self.t0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout() {
        fn collect(a: u64, b: u32, c: bool) -> Vec<u64> {
            Timeout::new(Duration::from_millis(a), b, c)
                .map(|t| t.as_millis() as u64)
                .collect()
        }
        let exp = |a, b| collect(a, b, true);
        let lin = |a, b| collect(a, b, false);

        assert_eq!(exp(1500, 4), vec![400, 800, 1600, 3200]);
        assert_eq!(exp(500, 100).len(), 100);

        assert_eq!(lin(1500, 4), vec![1500, 1500, 1500, 1500]);
        assert_eq!(lin(500, 1000).len(), 1000);
    }
}
