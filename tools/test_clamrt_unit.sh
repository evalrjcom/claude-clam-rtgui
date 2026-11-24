#!/bin/bash
# clamrt unit tests (no clamd needed), with ASan+UBSan.  The fanotify/e2e tests need root + clamd: tools/test_clamrt_e2e.sh
. "$(dirname "$0")/lib.sh"; cd "$ROOT/clamrt"; O=$ROOT/build/ut; mkdir -p "$O"
gcc -std=gnu99 -g -fsanitize=address,undefined -pthread -I. test_v3.c clamrt_sha256.c -lm -o "$O/test_v3" && "$O/test_v3"
gcc -std=gnu99 -g -fsanitize=address,undefined -pthread test_plat.c -o "$O/test_plat" && "$O/test_plat"
