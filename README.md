# gunyah_host_mod

Host-side out-of-tree kernel modules for DroidVM (crosvm + Qualcomm Gunyah),
grouped by module type, then by GKI version. `build.sh` builds each into
`dist/<kmi>/<module>.ko`; `6_build_apk_prepare.sh` stages them into
`usr/lib/modules/<kmi>/`, and the app's Kernel Module tab lists every `.ko`
found in the KMI dir matching the running kernel.

## gunyah_host_share — SHARE_BLOB / GuestAccept

Runtime `/dev/gunyah_share` that lets crosvm SHARE a host-visible virtio-gpu
blob to a running protected guest as an RM memparcel (the guest accepts it via
its own HVC). No kernel patch: resolves the unexported RM helpers via kallsyms
and reads the private structs by BTF-verified offset.

- **GKI6.6/** — `gunyah_share_66.c` for the **upstream** `gunyah_*` gunyah
  driver; built for **6.6** and **6.12** (v5: liveness-GC auto-reclaim + bounded
  share retry).
- **GKI6.1/** — `gunyah_share_mod.c` for the **downstream** `gh_*` gunyah driver
  (6.1). This is the original module `gunyah_share_66` was adapted from; it
  vendors the private `struct gh_vm` layout inline, so it needs no driver source.

## gunyah_kvcalloc — large-guest OOM fix (6.1)

- **GKI6.1/** — reproduces the in-tree fix (commit `b6ff6203e4bc`) that makes
  Gunyah's `gh_vm_mem_alloc()` use `kvcalloc()`/`kvfree()` instead of
  `kcalloc()`/`kfree()`, so a >2 GB guest's pinned-page pointer array doesn't
  fail a high-order `kmalloc` under fragmentation (VM setup `-ENOMEM`). kprobe
  full-function hijack of the two paired functions; downstream `gh_*` /
  `struct gh_vm`, whose layout it vendors inline (same as host-share), so it
  needs no gunyah driver source.

## gh_unmovable — non-movable pinnable memory for small GPU blobs (all KMIs)

`/dev/gh_unmovable` exposing one ioctl, `GH_UNMOVABLE_MAKE(memfd)`, that drops
`__GFP_MOVABLE` from a memfd's page-cache gfp mask
(`mapping_set_gfp_mask(GFP_HIGHUSER)`). gfxstream calls it on a **small**
(non-folio-backed) host-visible blob's memfd right after `memfd_create`, so the
pages udmabuf later faults in are born in an **UNMOVABLE** pageblock. Without
it, a small blob's shmem lands in a MOVABLE/CMA pageblock (the reserve lends
idle memory to CMA for apps), and `gunyah_share`'s
`pin_user_pages_fast(FOLL_LONGTERM)` then fails `-ENOMEM` trying to migrate it
out of CMA → the SHARE dies and the guest's blob mmap returns
`VK_ERROR_OUT_OF_DEVICE_MEMORY` (vkmark / mc broke this way until the reserve's
CMA was manually reclaimed first). Large blobs are unaffected — they sit in
isolated 2 MB reserve folios. KMI-agnostic: one source (`gh_unmovable/GKI6.6/`)
builds for 6.1 / 6.6 / 6.12 via a `struct fd` compat shim.

## udmabuf — /dev/udmabuf fallback (all KMIs)

Out-of-tree copy of the upstream udmabuf driver for host kernels shipped with
`CONFIG_UDMABUF` unset. Every GKI `gki_defconfig` since 6.1 enables it, but
vendor kernel_platform builds (e.g. QCOM 6.1) may not — and gfxstream's
host-visible blob path imports blob memfds as dma-bufs through `/dev/udmabuf`,
so those hosts need this module. Init **no-ops when `/dev/udmabuf` already
exists** (`misc_register` returns `-EEXIST` against the in-tree driver's
device; the module stays loaded but registers nothing), so autostart is safe
on every device. One portable source (`udmabuf/udmabuf.c`) builds for
6.1 / 6.6 / 6.12; the per-KMI module name (`udmabuf_gki_6.1` …) keeps
`/sys/module` from clashing with a built-in `udmabuf`.

Differences from upstream: hugetlb memfds are rejected (`memfd_fcntl()` is not
exported to modules, so seals are read via `SHMEM_I()`), the `size_limit_mb`
page-limit arithmetic is done in u64 (upstream's int math overflows at
>= 4096 MB), and the default cap is 4096 MB instead of 64 MB. The app daemon
still applies its configured cap at VM start via
`/sys/module/udmabuf*/parameters/size_limit_mb` (glob covers both the in-tree
name and this module's).

So a 6.1 device shows **four** modules in the Kernel Module tab (host-share +
kvcalloc + gh_unmovable + udmabuf); 6.6 / 6.12 show **three** (host-share +
gh_unmovable + udmabuf).
