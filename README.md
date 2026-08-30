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

Both copies are called `gunyah_share_mod.c`; the **directory** says which driver
a copy is written against, because that — not the file name — is what differs:

- **GKI6.6/** — for the **upstream** `gunyah_*` driver; built for **6.6** and
  **6.12** from this one source (v5: liveness-GC auto-reclaim + bounded share
  retry). 6.12 changed nothing it touches: `struct gunyah_vm` is identical
  through `vm_status`, and every 6.12 addition lands after it. Two 6.12-only
  behaviours are handled — the driver now stamps `parcel->label` from the
  userspace region label, so ours carries a namespace bit to keep the two out of
  one namespace, and the new `RESET_FAILED` VM state makes the reaper give up at
  once instead of spending its whole retry budget on a VM that will never
  release the guest's accepts.
- **GKI6.1/** — for the **downstream** `gh_*` driver (6.1). This is the original
  the 6.6 copy was adapted from; it vendors the private `struct gh_vm` layout
  inline, so it needs no driver source.

## gunyah_kvcalloc — large-guest OOM fix (6.1)

- **GKI6.1/** — reproduces the in-tree fix (commit `b6ff6203e4bc`) that makes
  Gunyah's `gh_vm_mem_alloc()` use `kvcalloc()`/`kvfree()` instead of
  `kcalloc()`/`kfree()`, so a >2 GB guest's pinned-page pointer array doesn't
  fail a high-order `kmalloc` under fragmentation (VM setup `-ENOMEM`). kprobe
  full-function redirect of the two paired functions; downstream `gh_*` /
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

## match.json — which devices a module is for

The KMI directory answers "which kernel", which is only half the question: every
module here is Gunyah/Qualcomm work that does nothing on a MediaTek or Tensor
phone. `match.json` carries a rule per module, keyed by module-name **prefix**
(same convention as `descr/`, longest match wins), and the app lists only the
modules whose rule passes:

```json
{ "version": 1,
  "modules": {
    "gunyah_host_share": { "soc_vendor": ["qualcomm"] },
    "mtk_whatever":      { "soc_vendor": ["mediatek"], "soc_model_prefix": ["MT69"] } } }
```

Fields are `soc_vendor` (`qualcomm` / `mediatek` / `google` / `samsung` /
`unisoc` / `hisilicon`), `soc_model` (exact, case-insensitive) and
`soc_model_prefix`; values within a field are alternatives, fields are ANDed, and
a rule with no fields matches **every** device — which is why `udmabuf` carries
only a `comment`: it is a generic dma-buf fix with nothing Gunyah about it, so it
is offered wherever a build for the running kernel exists. A module for a new
vendor therefore needs no app change — the rule ships next to its `.ko`. A field
the installed app does not know makes the rule **fail**, deliberately: an insmod
on the wrong device is a panic, so an app that cannot judge a rule must not list
the module anyway.

There is deliberately no kernel-version field: the `<kmi>/` directory a `.ko`
sits in already answers that, and the app only ever looks in the one matching the
running kernel.

`build.sh` fails if any `.ko` it built is not covered by a rule — an unmatched
module is not listed at all, so a missing rule would silently delete it from the
UI. `6_build_apk_prepare.sh` stages the file to `usr/lib/modules/match.json`.

The app carries its own copy of this format in `assets/match.json`, for the one
module that has no `.ko` to ride on (GH-Hugepage-Reserve) and as the answer for
prebuilts older than this file. When nothing at all matches, the app's setup
wizard skips its kernel-module page; Settings still opens the list, empty.

## descr/ — the "why is this needed" pages

`descr/<module>.html` is one self-contained page per module, explaining in plain
language what breaks without it and what it does about it. The file name is the
module-name **prefix** it applies to, so `udmabuf.html` serves
`udmabuf_gki_6.6` and its siblings.

Each page carries **all three languages** (`<div class="i18n"
data-lang="en|zh-CN|zh-TW">`) and no colours of its own. At display time the app
injects, ahead of `style.css`:

- the CSS rule selecting one language (device language, falling back to English),
- the live Material palette as CSS variables, so pages follow dark mode and
  Material You, plus `data-theme` for anything that needs to branch on it.

So the page never has to know the device's language or theme, and neither the
build nor the file tree is per-language. Rendering is a WebView with JavaScript
off and network loads blocked — the pages are static HTML with inline SVG.

A page gets a figure only where a picture explains something words struggle with
(fragmentation, contiguity) — most don't need one. A figure closes its section's
prose rather than opening the page, which puts it *inside* a language block, so
its drawing is written once per language and only the caption differs. The build
compares the copies and fails if they diverge: a diagram fixed in one language
and not the others is a bug no reader of the other two would ever think to
report. Anything the text enumerates is a real list, not numbers inside a
sentence.

`build.sh` (or `./build.sh descr` alone) stages them to `dist/descr/`, refusing
any page that is missing a language or the `<link ... style.css>` line the app
swaps for the inlined stylesheet; `6_build_apk_prepare.sh` copies them to
`usr/lib/modules/descr/`. They ride inside the prebuilt `tar.xz`, so they are
plain files rather than a JSON blob or a nested archive: **open one in a browser
to proofread it** — you get all three languages at once on the fallback palette
in `style.css`.

`style.css` lives here but renders from the app's copy
(`DroidVM/app/src/main/assets/descr/style.css`, synced by
`6_build_apk_prepare.sh`), because the app also renders one page that has no
prebuilt to ride on: GH-Hugepage-Reserve, which is a Magisk/KernelSU module
rather than one of these `.ko` files, ships its page in the APK assets.
