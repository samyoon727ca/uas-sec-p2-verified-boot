#!/usr/bin/env bash
# Build the inputs for the emulated CC boot chain (tests/ve07):
#   - U-Boot v2026.07 from the pinned tarball, in six variants:
#       hardened       qemu_arm64_defconfig + cc/uboot/p2.config + cc/uboot/qemu.config
#       stock          qemu_arm64_defconfig unchanged (control runs only)
#       ctl-bootdelay  hardened + cc/uboot/controls/bootdelay.config (control runs only)
#       ctl-noreset    hardened + cc/uboot/controls/noreset.config (control runs only)
#       tc06-version   hardened + cc/uboot/variants/version.config (TC-06 only)
#       tc06-bootargs  hardened + cc/uboot/variants/bootargs.config (TC-06 only)
#   - the pinned Ubuntu arm64 kernel and a busybox initramfs holding the
#     unseal agent (cc/initramfs/p2-unseal.c) and the TPM libraries it needs.
# Every download is checked against a pinned SHA-256, and every variant's
# .config is checked against its fragments. Output goes to $OUT.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$ROOT/build}
DL=${DL:-$ROOT/.cache/dl}
JOBS=${JOBS:-$(nproc)}
export CROSS_COMPILE=${CROSS_COMPILE:-aarch64-linux-gnu-}
mkdir -p "$OUT" "$DL"

pin() { awk -v k="$1:" '$1 == k {print $2}' "$ROOT/cc/uboot/pin.txt"; }

fetch() { # url sha256 dest
  local url=$1 sha=$2 dest=$3
  if [[ -f $dest ]] && echo "$sha  $dest" | sha256sum -c --status; then return; fi
  curl -sSfL --retry 3 -o "$dest.part" "$url"
  if ! echo "$sha  $dest.part" | sha256sum -c --status; then
    echo "SHA-256 mismatch for $url" >&2; rm -f "$dest.part"; exit 1
  fi
  mv "$dest.part" "$dest"
}

# --- U-Boot -----------------------------------------------------------------
UB_VER=$(pin version)
UB_TAR=$DL/u-boot-$UB_VER.tar.bz2
fetch "$(pin url)" "$(pin sha256)" "$UB_TAR"
SRC=$OUT/src/u-boot-$UB_VER
rm -rf "$SRC" && mkdir -p "$OUT/src" && tar -xjf "$UB_TAR" -C "$OUT/src"
export SOURCE_DATE_EPOCH=$(pin source_date_epoch)

P2=("$ROOT/cc/uboot/p2.config" "$ROOT/cc/uboot/qemu.config")
declare -A FRAGS=(
  [hardened]="${P2[*]}"
  [stock]=""
  [ctl-bootdelay]="${P2[*]} $ROOT/cc/uboot/controls/bootdelay.config"
  [ctl-noreset]="${P2[*]} $ROOT/cc/uboot/controls/noreset.config"
  [tc06-version]="${P2[*]} $ROOT/cc/uboot/variants/version.config"
  [tc06-bootargs]="${P2[*]} $ROOT/cc/uboot/variants/bootargs.config"
)
VARIANTS=(hardened stock ctl-bootdelay ctl-noreset tc06-version tc06-bootargs)
for variant in "${VARIANTS[@]}"; do
  B=$OUT/uboot-$variant
  rm -rf "$B"
  make -s -C "$SRC" O="$B" qemu_arm64_defconfig
  read -r -a frags <<< "${FRAGS[$variant]}"
  if (( ${#frags[@]} )); then
    "$SRC/scripts/kconfig/merge_config.sh" -m -O "$B" "$B/.config" "${frags[@]}" >/dev/null
    make -s -C "$SRC" O="$B" olddefconfig
    python3 "$ROOT/cc/uboot/check_config.py" "$B/.config" "${frags[@]}"
  fi
  make -s -C "$SRC" O="$B" -j"$JOBS"
  cp "$B/u-boot.bin" "$OUT/u-boot-$variant.bin"
  cp "$B/.config" "$OUT/u-boot-$variant.config"
done
cp "$OUT/uboot-hardened/tools/mkimage" "$OUT/uboot-hardened/tools/mkenvimage" "$OUT/"

# --- Guest kernel and initramfs ---------------------------------------------
GUEST=$OUT/guest && rm -rf "$GUEST" && mkdir -p "$GUEST"
while read -r file sha; do
  [[ -z $file || $file == \#* ]] && continue
  fetch "https://launchpad.net/ubuntu/+archive/primary/+files/$file" "$sha" "$DL/$file"
  dpkg-deb -x "$DL/$file" "$GUEST"
done < "$ROOT/cc/emu/guest.lock"
cp "$GUEST"/boot/vmlinuz-* "$OUT/Image.gz"

# The unseal agent, built against the pinned arm64 TPM libraries (headers from
# libtss2-dev), and every shared library it needs, found by following DT_NEEDED.
SYSLIB=$GUEST/usr/lib/aarch64-linux-gnu
"${CROSS_COMPILE}gcc" -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -ffile-prefix-map="$ROOT"=. -I"$GUEST/usr/include" -L"$SYSLIB" -Wl,-rpath-link,"$SYSLIB" \
  -o "$OUT/p2-unseal" "$ROOT/cc/initramfs/p2-unseal.c" -ltss2-esys -ltss2-mu -ltss2-rc -ltss2-tcti-device

RD=$OUT/initramfs && rm -rf "$RD" && mkdir -p "$RD"/{bin,dev,proc,run,sys,usr/bin,usr/lib/aarch64-linux-gnu}
cp "$GUEST/usr/bin/busybox" "$RD/bin/busybox"
cp "$ROOT/cc/initramfs/init" "$RD/init"
cp "$OUT/p2-unseal" "$RD/usr/bin/p2-unseal"
chmod 0755 "$RD/init" "$RD/bin/busybox" "$RD/usr/bin/p2-unseal"
ln -s usr/lib "$RD/lib"
ln -s aarch64-linux-gnu/ld-linux-aarch64.so.1 "$RD/usr/lib/ld-linux-aarch64.so.1"
needed() { "${CROSS_COMPILE}readelf" -d "$1" | sed -n 's/.*(NEEDED).*\[\(.*\)\]$/\1/p'; }
queue=("$OUT/p2-unseal")
declare -A copied=()
while (( ${#queue[@]} )); do
  for lib in $(needed "${queue[0]}"); do
    [[ -n ${copied[$lib]:-} ]] && continue
    [[ -e $SYSLIB/$lib ]] || { echo "$lib, needed by ${queue[0]##*/}, is not in guest.lock" >&2; exit 1; }
    cp -L "$SYSLIB/$lib" "$RD/usr/lib/aarch64-linux-gnu/$lib"
    copied[$lib]=1
    queue+=("$SYSLIB/$lib")
  done
  queue=("${queue[@]:1}")
done
find "$RD" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
(cd "$RD" && find . -mindepth 1 | LC_ALL=C sort | cpio -o -H newc --reproducible --owner 0:0 --quiet) \
  | gzip -9 -n > "$OUT/initramfs.cpio.gz"

# --- Record the toolchain that produced these binaries ------------------------
{
  "${CROSS_COMPILE}gcc" --version | head -1
  "${CROSS_COMPILE}ld" --version | head -1
  gcc --version | head -1
  dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' 2>/dev/null \
    | grep -E '^(gcc|cpp|g\+\+|binutils|libgcc|libc6|libstdc|gzip|cpio|device-tree-compiler|libssl|openssl)' || true
} > "$OUT/toolchain.txt"

(cd "$OUT" && sha256sum u-boot-*.bin u-boot-*.config Image.gz initramfs.cpio.gz p2-unseal mkimage mkenvimage) \
  | tee "$OUT/SHA256SUMS"
