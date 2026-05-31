# ADR-011: OpenBSD-Inspired Security Hardening

**Status:** Accepted  
**Date:** 2026-05-31  
**Author:** SORABBYNGO Engineering  

---

## Context

SORABBYNGO OS runs on clinical hardware (novela-os), consumer devices
(byngo-os), edge nodes (edge-os), and security workstations (sentinel-os).
All surfaces are targets for adversarial attack — particularly novela-os
which handles patient data, and sentinel-os which runs in hostile
environments.

OpenBSD has a 30-year track record of proactive security hardening. Their
kernel security model (W^X, pledge, unveil, pf default-deny, per-process
canaries, randomised malloc) has proven effective at reducing exploit
surface. We port the most impactful primitives to our Linux 6.19.10 base.

## Decision

Apply 9 kernel patches to `sorabbyngo-patches`, implementing:

| Patch | Feature | OpenBSD Reference |
|---|---|---|
| 0001 | Strict W^X enforcement | sys/uvm/uvm_mmap.c |
| 0002 | Pledge syscall promise sets | sys/kern/kern_pledge.c |
| 0003 | Unveil filesystem restriction | sys/kern/kern_unveil.c |
| 0004 | Enhanced kASLR entropy | locore.S TSC jitter |
| 0005 | Slab guard + UAF detection | malloc(3) hardening |
| 0006 | pf-inspired default-deny network | sys/net/pf.c |
| 0007 | Per-task stack canary reseeding | per-process canary |
| 0008 | TCP stack hardening | tcp_input.c |
| 0009 | NodeID hardening (__ro_after_init) | (security fix) |

## Integration Points

**Byngox agents** call `sorabbyngo_pledge(PLEDGE_STDIO | PLEDGE_INET)`
at startup, then `sorabbyngo_unveil("/opt/sorabbyngo/byngox", "rwx")`
before entering their main loop.

**Chameha** pledges `PLEDGE_STDIO | PLEDGE_RPATH | PLEDGE_TTY` and
unveils only its config and runtime dirs.

**CML service** pledges `PLEDGE_STDIO | PLEDGE_WPATH` (write to audit
log only) and unveils `/var/log/sorabbyngo/cml` and `/proc/sorabbyngo`.

**Byngonet** benefits from the pf-inspired network policy — NodeID-
verified peers are auto-allowed; all others are default-deny.

**Novela-OS clinical surfaces** enable all hardening features. The PREEMPT_RT
real-time patches remain compatible with all security features.

## Consequences

**Positive:**
- W^X closes the most common code-injection path
- Pledge significantly reduces syscall attack surface per process
- Unveil makes filesystem enumeration by exploited processes impossible
- Default-deny network policy matches clinical security requirements
- Per-task canary prevents cross-process canary reuse attacks
- NodeID fix prevents module-level identity spoofing

**Negative / Mitigations:**
- Slab guard pages add ~2-3% memory overhead → acceptable on all targets
- Pledge requires each Byngox agent to declare its promise set → done at
  agent init() time, no runtime overhead
- Default-deny network requires explicit allow rules for new services →
  managed via /proc/sorabbyngo/net_policy, documented in deployment guide

## Rejected Alternatives

**Port OpenBSD's relayd:** Too complex for our use case. Cyberwall already
handles application-layer filtering.

**Use gVisor/seccomp-bpf only:** seccomp-bpf alone lacks the filesystem
restriction that unveil provides. We need both layers.
