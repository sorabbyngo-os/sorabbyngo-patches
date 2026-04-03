# linux-sorabbyngo
> **Sorabbyngo AI OS Kernel** — Africa's sovereign AI operating system kernel, built on Linux 6.19.10

## What is Sorabbyngo AI OS?
Sorabbyngo AI OS is an **Africa-first AI operating system** — a custom Linux kernel stack designed to run AI workloads natively, with built-in mesh networking, hardware identity, and swarm reasoning.

**The mission:** Sovereign digital infrastructure built from the ground up for African deployment conditions — low connectivity, distributed nodes, and adversarial environments.

## Architecture

```
┌─────────────────────────────────────────┐
│           Sorabbyngo AI OS              │
├─────────────────────────────────────────┤
│  Swarm Reasoning Layer (userspace)      │
├─────────────────────────────────────────┤
│  Byngonet — Mesh Identity Networking    │
├─────────────────────────────────────────┤
│  NodeID — Hardware Cryptographic ID     │
├─────────────────────────────────────────┤
│  Linux 6.19.10 (kernel base)            │
└─────────────────────────────────────────┘
```

## Custom Kernel Drivers

### NodeID — Hardware Cryptographic Identity
Every Sorabbyngo node gets a unique, tamper-resistant identity derived from hardware. Established at kernel level before any userspace software runs. Exposed at `/proc/sorabbyngo/nodeid`.

### Byngonet — Identity-Aware Mesh Networking v0.2
Links network identity to NodeID at the kernel level. Every peer is cryptographically verified before traffic is accepted. Stats exposed at `/proc/byngonet_stats`. Netfilter packet tagging coming in v0.3.

## Kernel Base

| Property | Value |
|---|---|
| Base kernel | Linux 6.19.10 |
| Architecture | x86_64 |
| Branch | main |
| Compiler | GCC 12 |
| Maintained by | Sorabbyngo Company |

## Build Instructions

```bash
cp /boot/config-$(uname -r) .config
make olddefconfig LOCALVERSION=""
./scripts/kconfig/merge_config.sh .config sorabbyngo.config
make -j$(nproc) LOCALVERSION=""
sudo make modules_install LOCALVERSION=""
sudo cp arch/x86/boot/bzImage /boot/vmlinuz-6.19.10-sorabbyngo
sudo update-initramfs -c -k 6.19.10-sorabbyngo
sudo update-grub
```

## License
GPL-2.0 — same as the Linux kernel base.

## About
**Sorabbyngo Company** — Kisii, Kenya
*Building Africa's sovereign digital infrastructure — from the kernel up.*
© 2026 Sorabbyngo Company. All rights reserved.
