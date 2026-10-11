#!/usr/bin/env bash
# Build the inputs for the emulated CC boot chain (tests/ve07):
#   - U-Boot v2026.07 from the pinned tarball, in four variants:
#       hardened       qemu_arm64_defconfig + cc/uboot/p2.config + cc/uboot/qemu.config
#       stock          qemu_arm64_defconfig unchanged (control runs only)
#       ctl-bootdelay  hardened + cc/uboot/controls/bootdelay.config (control runs only)
#       ctl-noreset    hardened + cc/uboot/controls/noreset.config (control runs only)
#   - the pinned Ubuntu arm64 kernel and a busybox initramfs.
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
)
VARIANTS=(hardened stock ctl-bootdelay ctl-noreset)
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

RD=$OUT/initramfs && rm -rf "$RD" && mkdir -p "$RD"/{bin,dev,proc,sys}
cp "$GUEST/usr/bin/busybox" "$RD/bin/busybox"
cp "$ROOT/cc/initramfs/init" "$RD/init"
chmod 0755 "$RD/init" "$RD/bin/busybox"
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

(cd "$OUT" && sha256sum u-boot-*.bin u-boot-*.config Image.gz initramfs.cpio.gz mkimage mkenvimage) \
  | tee "$OUT/SHA256SUMS"
