//! Kernel-side packet timestamping helpers.
//!
//! Removes scheduler-jitter from per-source latency measurements by reading
//! the kernel's per-packet receive timestamp (via `SO_TIMESTAMPNS` + `recvmsg`
//! `SCM_TIMESTAMPNS` ancillary data) instead of taking `Instant::now()` after
//! the recv syscall returns.
//!
//! Linux only. On other platforms the public API still exists but
//! `enable_kernel_timestamps` is a no-op and `recv_with_timestamp` is omitted
//! (call sites are gated to Linux).
//!
//! Kernel software timestamps are in `CLOCK_REALTIME`; the registry's hot-path
//! arithmetic is in `Instant` (`CLOCK_MONOTONIC`). We bridge the two with a
//! [`ClockAnchor`] captured at startup — both clocks are read in tight
//! sequence, and subsequent kernel timestamps are converted relative to that
//! anchor. Drift between the two clocks during a benchmark run is dominated by
//! NTP adjustments and is negligible (sub-microsecond) on a sane host over
//! minutes-to-hours runs.

use std::time::{Duration, Instant};

/// Anchor pair used to convert kernel `CLOCK_REALTIME` timestamps into
/// `Instant`s comparable with `Instant::now()` elsewhere in the program.
#[derive(Clone, Copy, Debug)]
pub struct ClockAnchor {
    pub instant: Instant,
    /// Only read on Linux when converting kernel `SCM_TIMESTAMPNS` cmsg data.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub realtime_ns: i128,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl ClockAnchor {
    /// Capture both clocks back-to-back. The order is realtime → monotonic so
    /// that a kernel timestamp taken slightly before this call still yields a
    /// non-negative delta when typical NIC reception latencies are involved.
    pub fn capture() -> Self {
        let realtime_ns = realtime_ns_now();
        let instant = Instant::now();
        Self { instant, realtime_ns }
    }

    /// Convert a kernel `CLOCK_REALTIME` timestamp (nanoseconds since the unix
    /// epoch) into an `Instant` consistent with this anchor.
    pub fn instant_from_realtime_ns(&self, ts_ns: i128) -> Instant {
        let delta = ts_ns - self.realtime_ns;
        if delta >= 0 {
            self.instant + Duration::from_nanos(delta as u64)
        } else {
            self.instant
                .checked_sub(Duration::from_nanos((-delta) as u64))
                .unwrap_or(self.instant)
        }
    }
}

/// Read `CLOCK_REALTIME` as nanoseconds since the unix epoch.
#[cfg(unix)]
pub fn realtime_ns_now() -> i128 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let _ = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

#[cfg(not(unix))]
pub fn realtime_ns_now() -> i128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    d.as_nanos() as i128
}

// ────────────────────────────────────────────────────────────────────────────
// Linux-only socket plumbing
// ────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::ClockAnchor;
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::unix::io::RawFd;
    use std::time::Instant;

    /// Size of the per-message ancillary buffer for cmsg parsing.
    /// 128 bytes comfortably fits a `SCM_TIMESTAMPNS` cmsg (~32 bytes).
    const CMSG_BUF_SIZE: usize = 128;

    /// Enable nanosecond-precision software receive timestamps on `fd`.
    /// Subsequent `recv_with_timestamp` calls will read the per-packet
    /// timestamp from the ancillary data.
    pub fn enable_kernel_timestamps(fd: RawFd) -> io::Result<()> {
        let enable: libc::c_int = 1;
        let r = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPNS,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Receive a single datagram, returning (bytes, instant). The returned
    /// instant is the kernel reception time converted via `anchor`. If the
    /// kernel didn't attach a timestamp (rare — typically a misconfigured
    /// socket), falls back to `Instant::now()` so the caller never silently
    /// loses a packet.
    pub fn recv_with_timestamp(
        fd: RawFd,
        buf: &mut [u8],
        anchor: &ClockAnchor,
    ) -> io::Result<(usize, Instant)> {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut cmsg_buf: [MaybeUninit<u8>; 128] =
            unsafe { MaybeUninit::uninit().assume_init() };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len();

        let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ts_kernel: Option<libc::timespec> = None;
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                let h = &*cmsg;
                if h.cmsg_level == libc::SOL_SOCKET
                    && h.cmsg_type == libc::SCM_TIMESTAMPNS
                {
                    let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::timespec;
                    ts_kernel = Some(std::ptr::read_unaligned(data_ptr));
                    break;
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }

        let instant = match ts_kernel {
            Some(ts) => {
                let ts_ns = ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128;
                anchor.instant_from_realtime_ns(ts_ns)
            }
            None => Instant::now(),
        };
        Ok((n as usize, instant))
    }

    /// Pre-allocated state for `recvmmsg`-based batched reception.
    ///
    /// Owns one frame buffer + iovec + cmsg buffer + mmsghdr per slot. The
    /// header / iovec / cmsg pointers are wired up once at construction and
    /// remain valid as long as `BatchRecv` is not moved (the constituent
    /// `Vec` storage is heap-allocated and stable under struct moves).
    pub struct BatchRecv {
        bufs: Vec<Vec<u8>>,
        iovecs: Vec<libc::iovec>,
        cmsg_bufs: Vec<[u8; CMSG_BUF_SIZE]>,
        msgs: Vec<libc::mmsghdr>,
    }

    impl BatchRecv {
        pub fn new(batch_size: usize, buf_size: usize) -> Self {
            assert!(batch_size > 0);
            let mut bufs: Vec<Vec<u8>> = (0..batch_size).map(|_| vec![0u8; buf_size]).collect();
            let mut cmsg_bufs: Vec<[u8; CMSG_BUF_SIZE]> =
                (0..batch_size).map(|_| [0u8; CMSG_BUF_SIZE]).collect();
            let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(batch_size);
            let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(batch_size);

            for i in 0..batch_size {
                let iov = libc::iovec {
                    iov_base: bufs[i].as_mut_ptr() as *mut libc::c_void,
                    iov_len: buf_size,
                };
                iovecs.push(iov);
            }
            for i in 0..batch_size {
                let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
                hdr.msg_iov = &mut iovecs[i];
                hdr.msg_iovlen = 1;
                hdr.msg_control = cmsg_bufs[i].as_mut_ptr() as *mut libc::c_void;
                hdr.msg_controllen = CMSG_BUF_SIZE;
                msgs.push(libc::mmsghdr { msg_hdr: hdr, msg_len: 0 });
            }
            BatchRecv { bufs, iovecs, cmsg_bufs, msgs }
        }

        /// Receive up to `capacity` messages. Returns the count actually
        /// received. With `MSG_WAITFORONE` the call blocks until at least one
        /// message arrives or the socket's `SO_RCVTIMEO` expires; subsequent
        /// messages are taken non-blocking if already queued.
        ///
        /// On `WouldBlock` / `TimedOut`, returns `Ok(0)` so the caller can
        /// poll cancellation without burning errors.
        pub fn recvmmsg(&mut self, fd: RawFd) -> io::Result<usize> {
            // Reset controllen for each iteration — recvmmsg overwrites it.
            for (i, hdr) in self.msgs.iter_mut().enumerate() {
                hdr.msg_hdr.msg_controllen = CMSG_BUF_SIZE;
                hdr.msg_hdr.msg_control = self.cmsg_bufs[i].as_mut_ptr() as *mut libc::c_void;
                hdr.msg_len = 0;
            }
            let vlen = self.msgs.len() as libc::c_uint;
            let n = unsafe {
                libc::recvmmsg(
                    fd,
                    self.msgs.as_mut_ptr(),
                    vlen,
                    libc::MSG_WAITFORONE,
                    std::ptr::null_mut(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut
                {
                    return Ok(0);
                }
                return Err(err);
            }
            Ok(n as usize)
        }

        /// Bytes of frame `i` from the most recent batch.
        pub fn frame(&self, i: usize) -> &[u8] {
            let len = self.msgs[i].msg_len as usize;
            &self.bufs[i][..len]
        }

        /// Kernel timestamp of frame `i`, converted via `anchor`. Falls back
        /// to `Instant::now()` if the cmsg is missing (rare).
        pub fn timestamp(&self, i: usize, anchor: &ClockAnchor) -> Instant {
            let hdr = &self.msgs[i].msg_hdr;
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(hdr);
                while !cmsg.is_null() {
                    let h = &*cmsg;
                    if h.cmsg_level == libc::SOL_SOCKET
                        && h.cmsg_type == libc::SCM_TIMESTAMPNS
                    {
                        let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::timespec;
                        let ts = std::ptr::read_unaligned(data_ptr);
                        let ns = ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128;
                        return anchor.instant_from_realtime_ns(ns);
                    }
                    cmsg = libc::CMSG_NXTHDR(hdr, cmsg);
                }
            }
            Instant::now()
        }
    }
}
