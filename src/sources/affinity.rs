//! Thread CPU-affinity helper.
//!
//! After kernel-side timestamping ([`crate::sources::kernel_ts`]) removes the
//! scheduler-jitter component of the measurement, the *residual* variance is
//! dominated by userland wakeup time — itself sensitive to scheduler
//! migrations and CPU sibling contention. Pinning a latency-critical source
//! thread to a single core (ideally one excluded via `isolcpus` at boot) cuts
//! that residual.
//!
//! Linux only — on other platforms `pin_current_thread` is a no-op so call
//! sites stay simple.

use std::io;

#[cfg(target_os = "linux")]
pub fn pin_current_thread(cpu: usize) -> io::Result<()> {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        let r = libc::pthread_setaffinity_np(
            libc::pthread_self(),
            std::mem::size_of::<libc::cpu_set_t>(),
            &set,
        );
        if r != 0 {
            return Err(io::Error::from_raw_os_error(r));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn pin_current_thread(_cpu: usize) -> io::Result<()> {
    Ok(())
}
