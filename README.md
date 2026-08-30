# gunyah_host_mod

Host-side out-of-tree kernel modules for DroidVM (crosvm + Qualcomm Gunyah),
grouped by module type, then by GKI version. `build.sh` builds each into
`dist/<kmi>/<module>.ko`; `6_build_apk_prepare.sh` stages them into
`usr/lib/modules/<kmi>/`, and the app's Kernel Module tab lists every `.ko`
found in the KMI dir matching the running kernel.

## gunyah_kvcalloc — large-guest OOM fix (6.1)

- **GKI6.1/** — reproduces the in-tree fix (commit `b6ff6203e4bc`) that makes
  Gunyah's `gh_vm_mem_alloc()` use `kvcalloc()`/`kvfree()` instead of
  `kcalloc()`/`kfree()`, so a >2 GB guest's pinned-page pointer array doesn't
  fail a high-order `kmalloc` under fragmentation (VM setup `-ENOMEM`). kprobe
  full-function redirect of the two paired functions; downstream `gh_*` /
  `struct gh_vm`, whose layout it vendors inline (same as host-share), so it
  needs no gunyah driver source.

