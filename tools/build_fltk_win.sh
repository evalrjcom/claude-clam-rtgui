#!/bin/bash
# Static FLTK for the Windows cross-build -> build/fltk_win/{include,lib/libfltk.a}
. "$(dirname "$0")/lib.sh"; "$ROOT/tools/fetch_deps.sh" fltk
S=$ROOT/build/deps/fltk-$FLTK_VERSION; B=$ROOT/build/fltk-win-build; O=$ROOT/build/fltk_win; rm -rf "$B" "$O"
cmake -S "$S" -B "$B" -DCMAKE_TOOLCHAIN_FILE="$ROOT/cmake/mingw-w64.cmake" -DCMAKE_BUILD_TYPE=Release -DOPTION_BUILD_EXAMPLES=OFF -DOPTION_BUILD_TESTS=OFF \
  -DOPTION_USE_SYSTEM_LIBJPEG=OFF -DOPTION_USE_SYSTEM_LIBPNG=OFF -DOPTION_USE_SYSTEM_ZLIB=OFF -DOPTION_USE_GL=OFF -DOPTION_BUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX="$O" >/dev/null
cmake --build "$B" -j"$(nproc)" --target fltk && cmake --install "$B" >/dev/null
ls "$O/lib"
