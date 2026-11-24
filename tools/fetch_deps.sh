#!/bin/bash
# Download + verify + unpack the pinned upstream artifacts into build/deps.   usage: fetch_deps.sh [src|win|fltk ...]   (default: all)
. "$(dirname "$0")/lib.sh"
D=$ROOT/build/deps; mkdir -p "$D"; want=${*:-src win fltk}
for w in $want; do case $w in
  src)  fetch "$CLAMAV_SRC_URL" "$CLAMAV_SRC_SHA256" "$D/clamav-$CLAMAV_VERSION.tar.gz"; [ -d "$D/clamav-$CLAMAV_VERSION" ] || tar -xzf "$D/clamav-$CLAMAV_VERSION.tar.gz" -C "$D" ;;
  win)  fetch "$CLAMAV_WIN_URL" "$CLAMAV_WIN_SHA256" "$D/clamav-$CLAMAV_VERSION.win.x64.zip"; rm -rf "$D/clamav-win"; mkdir -p "$D/clamav-win"; unzip -q -o "$D/clamav-$CLAMAV_VERSION.win.x64.zip" -d "$D/clamav-win" ;;
  fltk) if [ ! -d "$D/fltk-$FLTK_VERSION/.git" ]; then rm -rf "$D/fltk-$FLTK_VERSION"; git clone -q "$FLTK_GIT" "$D/fltk-$FLTK_VERSION"; fi
        git -C "$D/fltk-$FLTK_VERSION" -c advice.detachedHead=false checkout -q "$FLTK_COMMIT"
        [ "$(git -C "$D/fltk-$FLTK_VERSION" rev-parse HEAD)" = "$FLTK_COMMIT" ] || die "FLTK commit mismatch" ;;
  *) die "unknown target $w" ;; esac; done
