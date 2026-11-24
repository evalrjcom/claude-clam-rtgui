#!/bin/bash
# usage: build_clamgui.sh linux [none|asan|tsan] | win        -> build/out/clamgui_vN_*
. "$(dirname "$0")/lib.sh"
t=${1:?linux|win}; san=${2:-none}; src=$(gui_src); v=$(gui_ver); O=$ROOT/build/out; mkdir -p "$O"
W=(-std=gnu++17 -Wall -Wextra -Werror -Wno-missing-field-initializers)
if [ "$t" = win ]; then
  F=$ROOT/build/fltk_win; [ -f "$F/lib/libfltk.a" ] || die "run tools/build_fltk_win.sh first"
  x86_64-w64-mingw32-g++-posix "${W[@]}" -O2 -isystem "$F/include" -mwindows -static -o "$O/clamgui_v${v}_win64.exe" "$src" "$F/lib/libfltk.a" \
    -lcomctl32 -lole32 -luuid -lgdi32 -lws2_32 -lshell32 -ladvapi32 -lcomdlg32 -lwinspool
  x86_64-w64-mingw32-strip "$O/clamgui_v${v}_win64.exe"
else
  case $san in none) f=(-O2); n=clamgui_v${v}_linux_x86_64;; asan) f=(-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer); n=clamgui_v${v}_asan;; tsan) f=(-O1 -g -fsanitize=thread); n=clamgui_v${v}_tsan;; *) die "san: none|asan|tsan";; esac
  # shellcheck disable=SC2046
  g++ "${W[@]}" "${f[@]}" -o "$O/$n" "$src" $(fltk-config --cxxflags --ldstaticflags) -pthread
  [ "$san" = none ] && strip "$O/$n"
fi
ls -l "$O"
