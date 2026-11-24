#!/bin/bash
# Fails if any in-file / companion-doc reference to the ClamGUI version disagrees with the version in the source file name.
# Optional: check_versions.sh refs/tags/clamgui-v2.1.0  (the tag's major must equal the file-name version)
. "$(dirname "$0")/lib.sh"; cd "$ROOT/clamgui"; v=$(gui_ver); src=$(basename "$(gui_src)"); bad=0
n=$(ls clamgui_v*.cpp | wc -l); [ "$n" -eq 1 ] || { echo "FAIL: expected exactly one clamgui_vN.cpp, found $n (git rm the old one)"; bad=1; }
grep -q "#define CLAMGUI_VERSION \"$v\"" "$src" || { echo "FAIL: CLAMGUI_VERSION in $src is not \"$v\""; bad=1; }
[ -f "clamgui_guide_v$v.md" ] || { echo "FAIL: missing companion guide clamgui_guide_v$v.md"; bad=1; }
[ -f "e2e_clamgui_v${v}_test.sh" ] || { echo "FAIL: missing e2e_clamgui_v${v}_test.sh"; bad=1; }
for f in "$src" "e2e_clamgui_v${v}_test.sh" "$ROOT/installer/clamgui.iss"; do
  [ -f "$f" ] || continue
  # every clamgui_vN / "ClamGUI vN" token must carry the current version
  stale=$(grep -noE "clamgui_v[0-9]+|ClamGUI v[0-9]+" "$f" | grep -vE "v$v\$" || true)
  [ -z "$stale" ] || { echo "FAIL: stale version reference in $f:"; echo "$stale" | head -5; bad=1; }
done
# companion guide: the title heading must carry the current version (the body may mention older versions in its history)
head -1 "clamgui_guide_v$v.md" | grep -q "v$v" || { echo "FAIL: guide title does not say v$v"; bad=1; }
if [ -n "${1:-}" ]; then t=${1##*/}; [[ $t =~ ^clamgui-v([0-9]+)\. ]] && [ "${BASH_REMATCH[1]}" = "$v" ] || { echo "FAIL: tag $t does not match file version v$v"; bad=1; }; fi
[ $bad -eq 0 ] && echo "version check OK (ClamGUI v$v)"; exit $bad
