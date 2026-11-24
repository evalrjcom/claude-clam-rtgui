#!/bin/bash
# clamrt end-to-end suites against the freshly built clamd (needs build/clamav from build_clamav_linux.sh; fanotify tests need root and are skipped otherwise)
. "$(dirname "$0")/lib.sh"; CV=$ROOT/build/clamav-linux/bin
export CLAMD=$CV/clamd CERTS=$ROOT/build/clamav-linux/certs; RT=$ROOT/build/out/clamrt_linux_x86_64
cd "$ROOT/clamrt"; rc=0
for s in e2e_test.sh e2e_v3_test.sh e2e_v4_test.sh; do bash "./$s" "$RT" || rc=1; done; exit $rc
