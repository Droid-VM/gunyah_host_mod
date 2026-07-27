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

## udmabuf — provide or repair `/dev/udmabuf` (all KMIs)

gfxstream's host-visible blob path imports blob memfds as dma-bufs through
`/dev/udmabuf`, and host kernels break that in two different ways. One module
covers both: it picks a mode at insmod and logs which (also readable at
`/sys/module/udmabuf_gki_*/parameters/mode`).

| mode | when | what it does |
| --- | --- | --- |
| `native` | no built-in provider (`CONFIG_UDMABUF` unset — some vendor kernel_platform builds, e.g. QCOM 6.1) | registers `/dev/udmabuf` itself |
| `hijack` | built-in present but **unfixed**: its page-pointer array comes from `kmalloc_array` | kprobe redirects `udmabuf_create()` to ours |
| `noop` | built-in present and already fixed (or ≥ 6.10 folio driver, or not safely hookable) | loads and does nothing |

The unfixed built-in is the bug CVE-2024-56544 fixed upstream: a 128 MiB
dma-buf needs 32768 page pointers = a contiguous **order-6** (256 KiB)
allocation, which fails on a fragmented phone even with gigabytes free. Ours
uses `kvmalloc`, which falls back to vmalloc. **GKI 6.6 is unfixed** (checked
against 6.6.118: `kmalloc_array` at `drivers/dma-buf/udmabuf.c`), so this
module is doing real work on current devices, not just old ones.

Mode selection is deliberately one-directional — it adds a capability or
repairs one, and never takes a working `/dev/udmabuf` away:

- The built-in is found via kallsyms (`udmabuf_create` / `udmabuf_ops`), and
  `misc_register` returning `-EEXIST` is a second net under it.
- "Already fixed?" is answered by decoding the arm64 `BL` instructions inside
  the built-in `udmabuf_create` and looking for a call to `kvmalloc_node`. The
  log line names the allocator it *did* find (`… calls __kmalloc, no kvmalloc`),
  so the scan proves itself rather than just asserting a verdict.
- Anything inconclusive falls to `noop`, except an unreadable allocator call,
  which reports unfixed: hooking an already-fixed kernel costs nothing (the
  replacement does the same work), skipping a broken one costs the user the bug.
- `force_mode=native|hijack|noop` overrides the choice for testing.

**Hooking one function is enough** because the replacement returns a dma_buf
that is entirely ours — our `dma_buf_ops`, our private struct. The built-in
driver's ops never see our objects, so there is no vendored `struct udmabuf`
layout to get wrong (it differs across 6.1/6.6/6.12) and no paired
`release_udmabuf` hook: a kvmalloc'd pointer can never reach the built-in
`kfree`, because the built-in release only ever runs for buffers the built-in
create made. Buffers made before, during and after the hook each go home to
whoever made them. `DEFINE_DMA_BUF_EXPORT_INFO` sets `owner = THIS_MODULE`, so
`rmmod` is `-EAGAIN` while any of our buffers is alive.

Every kernel function outside the GKI module KMI is resolved by name at runtime
and left NULL when absent (same discipline as `gh_hugepage_reserve`'s kapi);
nothing dereferences a symbol it did not resolve. Two specific traps this
avoids: `shmem_mapping()` is a header inline comparing `&shmem_aops`, which the
KMI trim drops on real devices (insmod died with "Unknown symbol shmem_aops"
before this used the tmpfs superblock magic instead), and `memfd_fcntl()` is
not exported to modules (resolved by name, with `SHMEM_I()->seals` as fallback).

Other differences from upstream: hugetlbfs memfds are rejected (6.6 upstream
dropped them too; 6.1 loses that support here — crosvm uses shmem memfds, THP
included, so nothing in DroidVM notices), and the `size_limit_mb` page limit is
computed in u64 with a 4096 MB default, because upstream's int math overflows
at >= 4096 (16384 → 2^34 truncates to 0, rejecting everything). In `hijack`
mode **this** parameter, not the built-in's, is the one that counts. The app
daemon applies its configured cap at VM start via
`/sys/module/udmabuf*/parameters/size_limit_mb`, a glob covering both names.

One portable source (`udmabuf/udmabuf.c`) builds for 6.1 / 6.6 / 6.12; the
per-KMI module name (`udmabuf_gki_6.1` …) keeps `/sys/module` from clashing
with a built-in `udmabuf`. `stat_created` / `stat_failed` parameters count what
the module itself exported, which is how you confirm on-device that the hook is
the thing serving requests.

So a 6.1 device shows **four** modules in the Kernel Module tab (host-share +
kvcalloc + gh_unmovable + udmabuf); 6.6 / 6.12 show **three** (host-share +
gh_unmovable + udmabuf).
