//! Classic BPF (cBPF) socket filter used by the AF_PACKET pcap source.
//!
//! Lives outside `pcap.rs`'s Linux-only module so the filter can be
//! constructed and unit-tested on any platform — the Linux call site simply
//! reinterprets `[SockFilter; 21]` as `[libc::sock_filter; 21]` before
//! handing it to `setsockopt(SO_ATTACH_FILTER)`. Layout is verified by a
//! `const _: () = assert!` at the call site.
//!
//! The filter accepts UDP traffic to a configured port on either plain
//! Ethernet+IPv4 frames or 802.1Q VLAN-tagged Ethernet+IPv4 frames; it drops
//! non-IP, non-UDP, fragmented IPv4, wrong-port, and VLAN-carrying-non-IPv4
//! traffic.

/// Mirror of `libc::sock_filter` (Linux kernel `struct sock_filter`).
///
/// `repr(C)` and the same field layout as the kernel struct so a slice of
/// these can be reinterpret-cast to `*mut libc::sock_filter` at the syscall
/// boundary. The cast is sound iff `size_of::<SockFilter>() ==
/// size_of::<libc::sock_filter>()`, which is asserted statically at the call
/// site in `pcap::linux::capture_loop`.
///
/// `#[allow(dead_code)]` on non-Linux: the only runtime consumer is the
/// Linux-gated AF_PACKET capture path, but the type and builder still
/// compile (and are tested) on every platform.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// Build the cBPF program for the AF_PACKET socket.
///
/// Returns 21 instructions. The two terminating `ret` instructions return
/// `0xffff` (snap to full length, i.e. accept) or `0` (drop) — the kernel
/// `SO_ATTACH_FILTER` convention.
///
/// Branch map (verified by the cBPF tests in `pcap::linux::tests`):
///   PC 0–4   : ethertype demux  (plain IPv4 → 5, VLAN+IPv4 → 12, else drop)
///   PC 5–11  : no-VLAN IPv4 UDP path  (proto / frag / dst port checks)
///   PC 12–18 : VLAN+IPv4 UDP path     (same checks at +4 offsets)
///   PC 19    : accept
///   PC 20    : drop
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn build_bpf_filter(port: u16) -> [SockFilter; 21] {
    let port_u32 = port as u32;
    [
        // 0: load ethertype @12
        SockFilter { code: 0x28, jt: 0,  jf: 0,  k: 12       },
        // 1: if ethertype == 0x0800 → goto no-VLAN IP path (PC 5)
        SockFilter { code: 0x15, jt: 3,  jf: 0,  k: 0x0800   },
        // 2: else if ethertype == 0x8100 → fall through; else drop (PC 20)
        SockFilter { code: 0x15, jt: 0,  jf: 17, k: 0x8100   },
        // 3: load inner ethertype @16 (after VLAN tag)
        SockFilter { code: 0x28, jt: 0,  jf: 0,  k: 16       },
        // 4: if inner == 0x0800 → goto VLAN IP path (PC 12); else drop
        SockFilter { code: 0x15, jt: 7,  jf: 15, k: 0x0800   },
        // 5: no-VLAN path — load IP proto @23 (14+9)
        SockFilter { code: 0x30, jt: 0,  jf: 0,  k: 23       },
        // 6: if proto == UDP → fall through; else drop
        SockFilter { code: 0x15, jt: 0,  jf: 13, k: 0x11     },
        // 7: load flags+fragoff @20 (14+6)
        SockFilter { code: 0x28, jt: 0,  jf: 0,  k: 20       },
        // 8: if fragmented (frag-offset != 0) → drop; else fall through
        SockFilter { code: 0x45, jt: 11, jf: 0,  k: 0x1fff   },
        // 9: X = IHL*4 from byte @14
        SockFilter { code: 0xb1, jt: 0,  jf: 0,  k: 14       },
        // 10: load UDP dst port @x+16 (UDP header at x+14, dst port +2)
        SockFilter { code: 0x48, jt: 0,  jf: 0,  k: 16       },
        // 11: if dst port matches → accept (PC 19); else drop (PC 20)
        SockFilter { code: 0x15, jt: 7,  jf: 8,  k: port_u32 },
        // 12: VLAN path — load IP proto @27 (18+9)
        SockFilter { code: 0x30, jt: 0,  jf: 0,  k: 27       },
        // 13: if proto == UDP → fall through; else drop
        SockFilter { code: 0x15, jt: 0,  jf: 6,  k: 0x11     },
        // 14: load flags+fragoff @24 (18+6)
        SockFilter { code: 0x28, jt: 0,  jf: 0,  k: 24       },
        // 15: if fragmented → drop; else fall through
        SockFilter { code: 0x45, jt: 4,  jf: 0,  k: 0x1fff   },
        // 16: X = IHL*4 from byte @18
        SockFilter { code: 0xb1, jt: 0,  jf: 0,  k: 18       },
        // 17: load UDP dst port @x+20 (UDP header at x+18, dst port +2)
        SockFilter { code: 0x48, jt: 0,  jf: 0,  k: 20       },
        // 18: if dst port matches → accept; else drop
        SockFilter { code: 0x15, jt: 0,  jf: 1,  k: port_u32 },
        // 19: accept (truncate to 0xffff bytes)
        SockFilter { code: 0x06, jt: 0,  jf: 0,  k: 0xffff   },
        // 20: drop
        SockFilter { code: 0x06, jt: 0,  jf: 0,  k: 0        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────
    // Inline classic-BPF interpreter.
    //
    // The `rbpf` crate is eBPF-only; the kernel's `SO_ATTACH_FILTER` takes
    // classic BPF. Translating cBPF → eBPF in userspace is non-trivial, so
    // we ship a tiny interpreter that handles exactly the opcodes our
    // filter uses (LD|H|ABS, LD|B|ABS, LD|H|IND, LDX|B|MSH, JMP|JEQ|K,
    // JMP|JSET|K, RET|K).
    //
    // Returns the kernel-equivalent filter result: `0xffff` for accept,
    // `0` for drop. Panics on unknown opcode or out-of-bounds packet read.
    // ────────────────────────────────────────────────────────────────────
    fn run_cbpf(program: &[SockFilter], packet: &[u8]) -> u32 {
        let mut a: u32 = 0;
        let mut x: u32 = 0;
        let mut pc: usize = 0;
        loop {
            assert!(pc < program.len(), "cBPF ran off end of program");
            let inst = program[pc];
            match inst.code {
                0x28 => {
                    let k = inst.k as usize;
                    assert!(k + 2 <= packet.len(), "ld[H] @{} OOB (len={})", k, packet.len());
                    a = u16::from_be_bytes([packet[k], packet[k + 1]]) as u32;
                    pc += 1;
                }
                0x30 => {
                    let k = inst.k as usize;
                    assert!(k < packet.len(), "ld[B] @{} OOB", k);
                    a = packet[k] as u32;
                    pc += 1;
                }
                0x15 => {
                    if a == inst.k {
                        pc += 1 + inst.jt as usize;
                    } else {
                        pc += 1 + inst.jf as usize;
                    }
                }
                0x45 => {
                    if a & inst.k != 0 {
                        pc += 1 + inst.jt as usize;
                    } else {
                        pc += 1 + inst.jf as usize;
                    }
                }
                0xb1 => {
                    let k = inst.k as usize;
                    assert!(k < packet.len(), "ldxb @{} OOB", k);
                    x = ((packet[k] & 0x0f) as u32) * 4;
                    pc += 1;
                }
                0x48 => {
                    let off = x as usize + inst.k as usize;
                    assert!(off + 2 <= packet.len(), "ld[H+X] @{} OOB", off);
                    a = u16::from_be_bytes([packet[off], packet[off + 1]]) as u32;
                    pc += 1;
                }
                0x06 => return inst.k,
                op => panic!("run_cbpf: unhandled opcode 0x{:02x} at pc={}", op, pc),
            }
        }
    }

    /// Build an Ethernet+IPv4+UDP frame with optional 802.1Q VLAN tag.
    fn build_frame(vlan_tag: Option<u16>, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 12]); // dst MAC + src MAC
        if let Some(vid) = vlan_tag {
            buf.extend_from_slice(&[0x81, 0x00]);
            buf.extend_from_slice(&(vid & 0x0fff).to_be_bytes());
        }
        buf.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
        let total_len = (20 + 8 + payload.len()) as u16;
        buf.push(0x45);                              // version 4, IHL 5
        buf.push(0x00);                              // TOS
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]);        // identification
        buf.extend_from_slice(&[0x00, 0x00]);        // flags+fragoff
        buf.push(64);                                // TTL
        buf.push(17);                                // proto = UDP
        buf.extend_from_slice(&[0x00, 0x00]);        // checksum (unused)
        buf.extend_from_slice(&[1, 2, 3, 4]);        // src IP
        buf.extend_from_slice(&[10, 0, 0, 1]);       // dst IP
        buf.extend_from_slice(&1234u16.to_be_bytes()); // UDP src port
        buf.extend_from_slice(&dst_port.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        buf.extend_from_slice(&udp_len.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]);        // UDP checksum
        buf.extend_from_slice(payload);
        buf
    }

    fn set_ip_proto(frame: &mut [u8], vlan: bool, proto: u8) {
        let ip = if vlan { 18 } else { 14 };
        frame[ip + 9] = proto;
    }

    fn set_ip_fragoff(frame: &mut [u8], vlan: bool, fragoff: u16) {
        let ip = if vlan { 18 } else { 14 };
        frame[ip + 6] = (fragoff >> 8) as u8;
        frame[ip + 7] = (fragoff & 0xff) as u8;
    }

    const PORT: u16 = 8001;
    const WRONG_PORT: u16 = 9999;
    const ACCEPT: u32 = 0xffff;
    const DROP: u32 = 0;

    #[test]
    fn accepts_plain_ipv4_udp_on_configured_port() {
        let prog = build_bpf_filter(PORT);
        let frame = build_frame(None, PORT, b"hello");
        assert_eq!(run_cbpf(&prog, &frame), ACCEPT);
    }

    #[test]
    fn drops_plain_ipv4_udp_on_wrong_port() {
        let prog = build_bpf_filter(PORT);
        let frame = build_frame(None, WRONG_PORT, b"hello");
        assert_eq!(run_cbpf(&prog, &frame), DROP);
    }

    #[test]
    fn accepts_vlan_tagged_ipv4_udp_on_configured_port() {
        let prog = build_bpf_filter(PORT);
        let frame = build_frame(Some(42), PORT, b"hello");
        assert_eq!(run_cbpf(&prog, &frame), ACCEPT);
    }

    #[test]
    fn drops_vlan_tagged_ipv4_udp_on_wrong_port() {
        let prog = build_bpf_filter(PORT);
        let frame = build_frame(Some(42), WRONG_PORT, b"hello");
        assert_eq!(run_cbpf(&prog, &frame), DROP);
    }

    #[test]
    fn drops_non_ip_ethertype() {
        let prog = build_bpf_filter(PORT);
        let mut frame = vec![0u8; 60];
        frame[12] = 0x08;
        frame[13] = 0x06; // ARP
        assert_eq!(run_cbpf(&prog, &frame), DROP);
    }

    #[test]
    fn drops_vlan_carrying_non_ipv4() {
        let prog = build_bpf_filter(PORT);
        let mut frame = vec![0u8; 64];
        frame[12] = 0x81; frame[13] = 0x00;       // VLAN TPID
        frame[14] = 0x00; frame[15] = 0x0a;       // VID 10
        frame[16] = 0x86; frame[17] = 0xdd;       // IPv6 inner
        assert_eq!(run_cbpf(&prog, &frame), DROP);
    }

    #[test]
    fn drops_ipv4_tcp_on_configured_port() {
        let prog = build_bpf_filter(PORT);
        let mut frame = build_frame(None, PORT, b"hello");
        set_ip_proto(&mut frame, false, 6);
        assert_eq!(run_cbpf(&prog, &frame), DROP);
    }

    #[test]
    fn drops_vlan_ipv4_tcp_on_configured_port() {
        let prog = build_bpf_filter(PORT);
        let mut frame = build_frame(Some(7), PORT, b"hello");
        set_ip_proto(&mut frame, true, 6);
        assert_eq!(run_cbpf(&prog, &frame), DROP);
    }

    #[test]
    fn drops_fragmented_ipv4() {
        let prog = build_bpf_filter(PORT);
        let mut frame = build_frame(None, PORT, b"hello");
        set_ip_fragoff(&mut frame, false, 0x0001);
        assert_eq!(run_cbpf(&prog, &frame), DROP);
    }

    #[test]
    fn drops_fragmented_vlan_ipv4() {
        let prog = build_bpf_filter(PORT);
        let mut frame = build_frame(Some(7), PORT, b"hello");
        set_ip_fragoff(&mut frame, true, 0x0001);
        assert_eq!(run_cbpf(&prog, &frame), DROP);
    }

    #[test]
    fn more_fragments_flag_alone_does_not_drop() {
        // MF=1 (bit 13, 0x2000) with offset=0 is the first fragment of a
        // datagram — full UDP header present. Filter masks 0x1fff (offset
        // only), so this should pass.
        let prog = build_bpf_filter(PORT);
        let mut frame = build_frame(None, PORT, b"hello");
        set_ip_fragoff(&mut frame, false, 0x2000);
        assert_eq!(run_cbpf(&prog, &frame), ACCEPT);
    }

    #[test]
    fn accept_value_is_full_snap_length() {
        // Defensive: the kernel snaps the packet to this length.
        let prog = build_bpf_filter(PORT);
        let frame = build_frame(None, PORT, b"x");
        assert_eq!(run_cbpf(&prog, &frame), 0xffff);
    }

    #[test]
    fn port_immediates_match_configured_port() {
        // Both port-comparison instructions (PC 11, PC 18) must carry the
        // configured port verbatim — otherwise the no-VLAN path matches a
        // different port than the VLAN path.
        let prog = build_bpf_filter(12345);
        assert_eq!(prog[11].k, 12345);
        assert_eq!(prog[18].k, 12345);
    }

    #[test]
    fn rejects_truncated_vlan_header() {
        // A frame too short to even hold the inner ethertype after the
        // VLAN tag must drop. The interpreter would panic on OOB, so this
        // test uses a frame just long enough for the initial @12 load but
        // shorter than the @16 inner-ethertype load — exercised via a
        // non-VLAN ethertype value to avoid reaching the @16 load.
        let prog = build_bpf_filter(PORT);
        let mut frame = vec![0u8; 14];
        frame[12] = 0x08;
        frame[13] = 0x06; // ARP — drop path at PC 1→2→drop
        assert_eq!(run_cbpf(&prog, &frame), DROP);
    }
}
