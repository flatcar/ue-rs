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
const RETRY_INTERVAL_MSEC: u64 = 1000;

pub fn retry_loop<F, T, E>(mut func: F, max_tries: u32) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
{
    let mut tries = 0;

    loop {
        match func() {
            ok @ Ok(_) => return ok,
            err @ Err(_) => {
                tries += 1;

                if tries >= max_tries {
                    return err;
                }
                sleep(Duration::from_millis(RETRY_INTERVAL_MSEC));
            }
        }
    }
}
