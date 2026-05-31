# SORABBYNGO Kernel Security Patches

OpenBSD-inspired security hardening for Linux 6.19.10.

## Applying the patches

```bash
# Clone Linux 6.19.10 source
git clone --depth=1 --branch v6.19.10 \
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git

cd linux

# Apply Sorabbyngo base drivers first
git apply ../sorabbyngo-patches/drivers/sorabbyngo/nodeid.c      # via Makefile
git apply ../sorabbyngo-patches/drivers/sorabbyngo/byngonet/*.c

# Apply OpenBSD security patches in order
for patch in ../sorabbyngo-patches/security/00*.patch; do
    git apply "$patch" && echo "OK: $patch" || echo "FAIL: $patch"
done

# Merge kernel config
cp /boot/config-$(uname -r) .config
make olddefconfig LOCALVERSION=""
./scripts/kconfig/merge_config.sh .config \
    ../sorabbyngo-patches/sorabbyngo.config

# Build
make -j$(nproc) LOCALVERSION="-sorabbyngo"
sudo make modules_install LOCALVERSION="-sorabbyngo"
sudo cp arch/x86/boot/bzImage \
    /boot/vmlinuz-6.19.10-sorabbyngo
sudo update-initramfs -c -k 6.19.10-sorabbyngo
sudo update-grub
```

## Patch summary

| # | Patch | What it does |
|---|---|---|
| 0001 | W^X strict enforcement | Rejects W+X mappings — closes code injection path |
| 0002 | Pledge promise sets | Per-process syscall surface reduction |
| 0003 | Unveil path restriction | Per-process filesystem visibility restriction |
| 0004 | kASLR entropy boost | TSC jitter + extended mmap/stack ASLR bits |
| 0005 | Slab guard + UAF detection | Guard pages + 0xDF free-poison pattern |
| 0006 | Default-deny net policy | pf-inspired netfilter with NodeID allowlist |
| 0007 | Per-task stack canary | NodeID-mixed canary, reseeded at fork/exec |
| 0008 | TCP hardening | SipHash ISN, timestamp randomisation, RST rate limit |
| 0009 | NodeID hardening | __ro_after_init, accessor API, rate-limited proc |

## Using pledge in userspace (Byngox example)

```c
#include <sys/prctl.h>
#include <linux/sorabbyngo_pledge.h>

/* At agent startup, before entering main loop */
prctl(PR_SET_SORABBYNGO_PLEDGE,
      PLEDGE_STDIO | PLEDGE_INET | PLEDGE_RPATH, 0, 0, 0);

/* Lock filesystem visibility */
sorabbyngo_unveil("/opt/sorabbyngo/byngox", "rwx");
sorabbyngo_unveil("/proc/sorabbyngo", "r");
sorabbyngo_unveil(NULL, NULL);  /* lock — no more unveil calls */
```

## sysctl tunables

```
net.sorabbyngo.default_policy    0=allow 1=deny (default: 1)
net.sorabbyngo.syn_rate_limit    new SYNs/sec per source (default: 50)
net.sorabbyngo.antispoof         reverse-path filtering 0/1 (default: 1)
vm.sorabbyngo.slab_guard_interval  guard page interval (default: 64)
```

## Architecture decision

See `docs-ADR-011-openbsd-security-hardening.md`
