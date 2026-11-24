#!/bin/bash
# ClamGUI e2e suite against the freshly built ClamAV.  usage: test_clamgui_e2e.sh [none|asan|tsan]
# Needs Xvfb xdotool stalonetray imagemagick curl openssl cron (the suite skips GUI parts that lack tools).
. "$(dirname "$0")/lib.sh"; san=${1:-none}; v=$(gui_ver); CV=$ROOT/build/clamav-linux
case $san in none) bin=$ROOT/build/out/clamgui_v${v}_linux_x86_64;; *) bin=$ROOT/build/out/clamgui_v${v}_$san;; esac
[ -x "$bin" ] || die "build it first: tools/build_clamgui.sh linux $san"
export CLAMSCAN=$CV/bin/clamscan FRESHCLAM=$CV/bin/freshclam CLAMD=$CV/bin/clamd CLAMDSCAN=$CV/bin/clamdscan CERTS=$CV/certs T=${T:-/tmp/clamgui_e2e_$san}
export LSAN_OPTIONS="suppressions=$ROOT/tools/lsan.supp:print_suppressions=0"   # third-party fontconfig/X11 exit-time leaks only
bash "$ROOT/clamgui/e2e_clamgui_v${v}_test.sh" "$bin" | tee "$ROOT/build/e2e_$san.txt"; grep -q " 0 failed" "$ROOT/build/e2e_$san.txt"
