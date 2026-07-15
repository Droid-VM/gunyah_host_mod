#!/usr/bin/env bash
# Build DroidVM's host-side gunyah kernel modules for each supported GKI KMI via the
# ddk-min docker images. Output layout: dist/<kmi>/<module>.ko
#
#   gunyah_host_share  SHARE_BLOB / GuestAccept   -> 6.6, 6.12 (upstream gunyah_*), 6.1 (gh_*)
#   gunyah_kvcalloc    large-guest >2GB OOM fix   -> 6.1                            (downstream gh_*)
#
# Kbuild/modpost turns the '-' in the module name into '_' and keeps the '.', so the
# loaded name matches what the app's Kernel Module tab derives from the .ko filename.
# That tab lists EVERY .ko in usr/lib/modules/<kmi>/, so a KMI with two modules
# (6.1: host-share + kvcalloc) shows both; 6.6/6.12 show only host-share.
#
#   ./build.sh arm64     # all supported KMIs (modules are aarch64-only)
#
# Requires docker (the DDK images carry the kernel headers + clang per KMI).
#
# Every module vendors the gunyah private struct layout inline (or reads it by
# BTF-verified offset), so NO build needs the gunyah driver source tree -- any
# stock ddk-min image for the KMI is enough (no -I<kdir>/drivers/virt/gunyah).
set -euo pipefail
cd "$(dirname "$0")"
OUT=dist

# build_mod <kmi-tag> <ddk-image> <src-dir> <src-file> <mod-name>
build_mod() {
  local tag="$1" img="$2" srcdir="$3" srcfile="$4" mod="$5"
  echo ">>> building ${mod}.ko for ${tag}"
  mkdir -p "${OUT}/${tag}"
  docker run --rm \
    -v "${PWD}/${srcdir}:/src:ro" \
    -v "${PWD}/${OUT}/${tag}:/out" \
    -e MOD="${mod}" -e SRCFILE="${srcfile}" \
    "${img}" bash -lc '
      set -e
      K=/opt/ddk/kdir/$(ls /opt/ddk/kdir)
      export PATH=$(ls -d /opt/ddk/clang/clang-*)/bin:$PATH
      B=/tmp/build; mkdir -p "$B"
      cp "/src/${SRCFILE}" "$B/${MOD}.c"
      cp /src/*.h "$B/" 2>/dev/null || true
      printf "obj-m += %s.o\n" "$MOD" > "$B/Makefile"
      make -C "$K" -j"$(nproc)" M="$B" ARCH=arm64 LLVM=1 LLVM_IAS=1 modules
      llvm-strip -d "$B/${MOD}.ko"
      cp "$B/${MOD}.ko" "/out/${MOD}.ko"
    '
  [ -f "${OUT}/${tag}/${mod}.ko" ] || { echo "FAIL: ${tag}/${mod} produced no .ko" >&2; exit 1; }
  echo "OK: ${OUT}/${tag}/${mod}.ko ($(stat -c%s "${OUT}/${tag}/${mod}.ko") bytes)"
}

case "${1:-arm64}" in
  arm64|aarch64|all)
    # gunyah_host_share (6.6/6.12: upstream gunyah_* source; 6.1: downstream gh_* source).
    build_mod android15-6.6  ghcr.io/ylarod/ddk-min:android15-6.6  \
        gunyah_host_share/GKI6.6 gunyah_share_66.c  gunyah-host-share-gki-6.6
    build_mod android16-6.12 ghcr.io/ylarod/ddk-min:android16-6.12 \
        gunyah_host_share/GKI6.6 gunyah_share_66.c  gunyah-host-share-gki-6.12
    build_mod android15-6.1  ghcr.io/ylarod/ddk-min:android15-6.1  \
        gunyah_host_share/GKI6.1 gunyah_share_mod.c gunyah-host-share-gki-6.1
    # gunyah_kvcalloc (6.1 only, downstream gh_*).
    build_mod android15-6.1  ghcr.io/ylarod/ddk-min:android15-6.1  \
        gunyah_kvcalloc/GKI6.1 gunyah_kvcalloc_mod.c gunyah-kvcalloc-gki-6.1
    ;;
  *) echo "usage: $0 [arm64]" >&2; exit 2 ;;
esac
echo "Done. Modules in ${OUT}/"
