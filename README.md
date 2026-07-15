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

- **GKI6.6/** — canonical, KMI-agnostic source (`gunyah_share_66.c`) for the
  **upstream** `gunyah_*` gunyah driver; built for **6.6** and **6.12**
  (v5: liveness-GC auto-reclaim + bounded share retry).
- **GKI6.1/** — placeholder for the 6.1 port against the **downstream** `gh_rm_*`
  gunyah (different symbol naming + struct offsets). Pending.

## gunyah_kvcalloc — large-guest OOM fix (6.1)

- **GKI6.1/** — reproduces the in-tree fix (commit `b6ff6203e4bc`) that makes
  Gunyah's `gh_vm_mem_alloc()` use `kvcalloc()`/`kvfree()` instead of
  `kcalloc()`/`kfree()`, so a >2 GB guest's pinned-page pointer array doesn't
  fail a high-order `kmalloc` under fragmentation (VM setup `-ENOMEM`). kprobe
  full-function hijack of the two paired functions; downstream `gh_*` /
  `struct gh_vm` (needs the private `drivers/virt/gunyah/vm_mgr.h`).

So a 6.1 device shows **both** modules in the Kernel Module tab (once the 6.1
host-share port lands); 6.6 / 6.12 show host-share only.
