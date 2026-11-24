#!/bin/bash
# Assemble the installer payload in build/stage from the pinned official ClamAV Windows zip + our mingw builds.
. "$(dirname "$0")/lib.sh"; v=$(gui_ver); S=$ROOT/build/stage; O=$ROOT/build/out
"$ROOT/tools/fetch_deps.sh" win
rm -rf "$S"; mkdir -p "$S/licenses"
W=$ROOT/build/deps/clamav-win; top=$(find "$W" -maxdepth 2 -name clamscan.exe -printf '%h\n' | head -1); [ -n "$top" ] || die "clamscan.exe not found in the official Windows zip"
cp -r "$top/." "$S/"
cp "$O/clamgui_v${v}_win64.exe" "$O/clamrt_win64.exe" "$S/"
mkdir -p "$S/certs"; cp -r "$ROOT/build/deps/clamav-$CLAMAV_VERSION/certs/." "$S/certs/" 2>/dev/null || echo "note: certs come from the ClamAV source tree (run fetch_deps.sh src)"
cp "$ROOT/installer/licenses/"* "$S/licenses/"
echo "ClamAV $CLAMAV_VERSION (official Windows build), ClamGUI v$v, clamrt" > "$S/licenses/COMPONENTS.txt"
ls "$S" | head -30
