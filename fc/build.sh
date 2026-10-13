#!/usr/bin/env bash
# Build the FC's secure-boot pair at the pinned PX4 commit with a per-run key
# (TC-11; docs/04 section 4.2). Runs inside the PX4 build container pinned in
# fc/px4/pin.txt, with:
#   PX4   a PX4 checkout at the pinned commit (fc/clone-px4.sh)
#   KEYS  an empty folder for the per-run key K-FC-FW dev
#   OUT   the output folder
# Writes to OUT:
#   bootloader.bin       px4_fmu-v6x_bootloader_secureboot, K-FC-FW dev in key slot 0
#   firmware.bin         px4_fmu-v6x_secureboot, as built (unsigned)
#   firmware-signed.bin  the same, signed with K-FC-FW dev by the build (sign_firmware.py)
#   firmware.px4         the upload envelope the build wraps around the signed image
#   firmware-test-key.bin  firmware.bin signed with PX4's public test key (the wrong-key case)
#   k-fc-fw-dev.pub      the per-run public key, as the C array the boot loader build includes
#   build-info.txt       PX4 commit, toolchain and Python package versions
# The per-run private key is deleted on exit.
set -euo pipefail
: "${PX4:?}" "${KEYS:?}" "${OUT:?}"
mkdir -p "$KEYS" "$OUT"
trap 'rm -f "$KEYS"/*.json' EXIT
git config --global --add safe.directory '*'   # the checkout belongs to the runner's user, not the container's
export CI=true                                  # PX4 then updates submodules without asking
# PyNaCl for PX4's key and signing tools; the container lacks it (fc/px4/requirements-secureboot.txt).
python3 -m pip install --quiet --no-cache-dir --break-system-packages --only-binary :all: --require-hashes \
  -r "$(dirname "$0")/px4/requirements-secureboot.txt"
cd "$PX4"

python3 Tools/secure_bootloader/generate_signing_keys.py "$KEYS/k-fc-fw-dev" > /dev/null
PUBLIC_KEY0="$KEYS/k-fc-fw-dev.pub" make px4_fmu-v6x_bootloader_secureboot
BOARD_SECUREBOOT_KEY="$KEYS/k-fc-fw-dev.json" make px4_fmu-v6x_secureboot

BL=build/px4_fmu-v6x_bootloader_secureboot
FW=build/px4_fmu-v6x_secureboot
cp "$BL/px4_fmu-v6x_bootloader_secureboot.bin" "$OUT/bootloader.bin"
cp "$FW/px4_fmu-v6x_secureboot.bin" "$OUT/firmware.bin"
cp "$FW/px4_fmu-v6x_secureboot_signed.bin" "$OUT/firmware-signed.bin"
cp "$FW/px4_fmu-v6x_secureboot.px4" "$OUT/firmware.px4"
cp "$KEYS/k-fc-fw-dev.pub" "$OUT/k-fc-fw-dev.pub"
python3 Tools/secure_bootloader/sign_firmware.py --key Tools/test_keys/test_keys.json \
  "$OUT/firmware.bin" "$OUT/firmware-test-key.bin" > /dev/null

{
  echo "px4_commit: $(git rev-parse HEAD)"
  echo "px4_describe: $(git describe --tags --always)"
  echo "monocypher: $(git -C src/lib/crypto/monocypher rev-parse HEAD)"
  echo "arm-none-eabi-gcc: $(arm-none-eabi-gcc --version | head -1)"
  echo "python: $(python3 --version 2>&1)"
  echo "pynacl: $(python3 -c 'import nacl; print(nacl.__version__)')"
} > "$OUT/build-info.txt"
(cd "$OUT" && sha256sum ./*.bin ./*.px4 ./*.pub) | tee "$OUT/SHA256SUMS"
