#!/usr/bin/env bash
# Install the pinned Ubuntu 24.04 host packages from the Ubuntu archive
# snapshot named in host-packages.txt, then check every installed version.
# Uses only the snapshot source, so the runner's own mirrors are not consulted.
# apt verifies the snapshot's signed Release file and each package's SHA-256.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
LIST=$HERE/host-packages.txt
TS=$(awk '$1 == "snapshot:" {print $2}' "$LIST")
[[ $TS =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || { echo "bad snapshot timestamp in $LIST" >&2; exit 1; }
mapfile -t PKGS < <(grep -Ev '^(#|snapshot:|$)' "$LIST")

SRC=$(mktemp -d)
trap 'rm -rf "$SRC"' EXIT
cat > "$SRC/p2-snapshot.sources" <<SOURCES
Types: deb
URIs: https://snapshot.ubuntu.com/ubuntu/$TS
Suites: noble noble-updates noble-security
Components: main universe
Architectures: amd64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
SOURCES
APT=(-o "Dir::Etc::SourceList=/dev/null" -o "Dir::Etc::SourceParts=$SRC" -o "APT::Get::List-Cleanup=false")
SUDO=$([[ $(id -u) -eq 0 ]] && echo "" || echo sudo)

$SUDO apt-get "${APT[@]}" update -qq
want=()
for line in "${PKGS[@]}"; do read -r name version <<< "$line"; want+=("$name=$version"); done
$SUDO env DEBIAN_FRONTEND=noninteractive apt-get "${APT[@]}" install -y -qq --no-install-recommends \
  --allow-downgrades "${want[@]}"

bad=0
for line in "${PKGS[@]}"; do
  read -r name version <<< "$line"
  got=$(dpkg-query -W -f='${Version}' "$name" 2>/dev/null || echo missing)
  if [[ $got == "$version" ]]; then echo "OK    $name $got"; else echo "DIFF  $name want $version got $got"; bad=1; fi
done
exit $bad
