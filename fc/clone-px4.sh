#!/usr/bin/env bash
# Clone PX4 at the tag pinned in fc/px4/pin.txt and refuse it unless the tag
# resolves to the pinned commit. Submodules are fetched by PX4's own build.
#   fc/clone-px4.sh <dir>
set -euo pipefail
PIN=$(cd "$(dirname "$0")" && pwd)/px4/pin.txt
pin() { awk -v k="$1:" '$1 == k {print $2}' "$PIN"; }
DEST=${1:?usage: fc/clone-px4.sh <dir>}
git clone --quiet --depth 1 --branch "$(pin tag)" "$(pin repo)" "$DEST"
got=$(git -C "$DEST" rev-parse HEAD)
if [[ $got != "$(pin commit)" ]]; then
  echo "PX4 $(pin tag) is $got, not the pinned $(pin commit)" >&2
  exit 1
fi
echo "PX4 $(pin tag) at $got"
