use core::time::Duration;
use std::thread::sleep;

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
