#!/bin/bash
# usage: build_clamrt.sh linux|win   -> build/out/clamrt_linux_x86_64 | build/out/clamrt_win64.exe
. "$(dirname "$0")/lib.sh"
t=${1:?linux|win}; B=$ROOT/build/clamrt-$t; O=$ROOT/build/out; mkdir -p "$O"; rm -rf "$B"
extra=(); [ "$t" = win ] && extra=(-DCMAKE_TOOLCHAIN_FILE="$ROOT/cmake/mingw-w64.cmake" -DCMAKE_EXE_LINKER_FLAGS="-static")
cmake -S "$ROOT/tools/clamrt_standalone" -B "$B" -DCLAMRT_SRC="$ROOT/clamrt" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-Wall -Wextra" "${extra[@]}" >/dev/null
cmake --build "$B" -j"$(nproc)"
if [ "$t" = win ]; then cp "$B/clamrt/clamrt.exe" "$O/clamrt_win64.exe"; x86_64-w64-mingw32-strip "$O/clamrt_win64.exe"
else cp "$B/clamrt/clamrt" "$O/clamrt_linux_x86_64"; strip "$O/clamrt_linux_x86_64"; fi
ls -l "$O"
