use core::time::Duration;
use std::thread::sleep;

/// Retries the supplied function until it returns `Ok` or the supplied maximum
/// retry limit is reached.
///
/// # Examples
///
/// ```rust
/// use std::{fs, io};
/// use ue_rs::retry_loop;
/// use std::sync::atomic::{AtomicUsize, Ordering};
/// use std::path::Path;
///
/// fn read_possibly_extant_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
///     let file_path = Path::new(path.as_ref());
///
///     if file_path.exists() {
///         fs::read_to_string(file_path)
///     } else {
///         Err(io::Error::new(io::ErrorKind::NotFound, io::Error::last_os_error()))
///     }
/// }
///
/// let result = retry_loop(|| read_possibly_extant_file("might_exist.txt"), 3);
/// ```
pub fn retry_loop<F, T, E>(mut func: F, max_tries: u32) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
{
    const RETRY_INTERVAL: Duration = Duration::from_millis(1000);

    for _ in 0..max_tries - 1 {
        match func() {
            Ok(ret) => return Ok(ret),
            Err(_) => sleep(RETRY_INTERVAL),
        }
    }

    func()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use super::*;

    #[test]
    fn test_success_first_try() {
        let res: Result<(), ()> = retry_loop(|| Ok(()), 3);
        assert_eq!(res, Ok(()));
    }

    #[test]
    fn test_fail_first_try() {
        let res: Result<i32, ()> = retry_loop(|| Err(()), 3);
        assert_eq!(res, Err(()));
    }

    #[test]
    fn test_success_after_some_retries() {
        let attempts = Cell::new(0);

        let mut func = || {
            let current: u8 = attempts.get();
            attempts.set(current.wrapping_add(1));
            if current < 2 {
                Err(())
            } else {
                Ok(())
            }
        };

        let res = retry_loop(&mut func, 5);
        assert_eq!(res, Ok(()));
        assert_eq!(attempts.get(), 3);
    }

    #[test]
    fn test_fail_after_max_tries() {
        let attempts = Cell::new(0);
        let mut func = || {
            attempts.set(attempts.get() + 1);
            Err(())
        };
        let res: Result<(), ()> = retry_loop(&mut func, 5);
        assert_eq!(res, Err(()));
        assert_eq!(attempts.get(), 5);
    }
}
