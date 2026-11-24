#!/bin/bash
# shared helpers (source this file)
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
. "$ROOT/deps.env"
die() { echo "error: $*" >&2; exit 1; }
# fetch URL SHA256 DEST : download once, refuse anything whose hash does not match (empty hash = refuse, never trust blindly)
fetch() {
  local url=$1 sha=$2 dest=$3
  [ -n "$sha" ] || die "no sha256 pinned for $url - run tools/bump_clamav.sh (or fill deps.env after checking the upstream release)"
  if [ ! -f "$dest" ] || [ "$(sha256sum "$dest" | cut -d' ' -f1)" != "$sha" ]; then
    mkdir -p "$(dirname "$dest")"; curl -fsSL --retry 3 --connect-timeout 20 -o "$dest.part" "$url"; mv "$dest.part" "$dest"
  fi
  [ "$(sha256sum "$dest" | cut -d' ' -f1)" = "$sha" ] || { rm -f "$dest"; die "sha256 mismatch for $url"; }
}
# highest-numbered clamgui_vN.cpp (filename versioning)
gui_src() { ls "$ROOT"/clamgui/clamgui_v*.cpp | sed -E 's/.*clamgui_v([0-9]+)\.cpp/\1 &/' | sort -n | tail -1 | cut -d' ' -f2; }
gui_ver() { basename "$(gui_src)" .cpp | sed 's/clamgui_v//'; }
