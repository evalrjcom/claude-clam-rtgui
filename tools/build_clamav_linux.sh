#!/bin/bash
# Build the pinned ClamAV from source (Linux).  Result: build/clamav-linux/{bin,certs}.  Needs: cmake ninja-build gcc g++ pkg-config python3
# libssl-dev libjson-c-dev libbz2-dev zlib1g-dev libpcre2-dev libxml2-dev libcurl4-openssl-dev libncurses-dev libcheck-dev(optional)
. "$(dirname "$0")/lib.sh"
"$ROOT/tools/fetch_deps.sh" src
S=$ROOT/build/deps/clamav-$CLAMAV_VERSION; B=$ROOT/build/clamav-build; I=$ROOT/build/clamav-linux; rm -rf "$B" "$I"
cmake -S "$S" -B "$B" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$I" -DENABLE_TESTS=OFF -DENABLE_MILTER=OFF -DENABLE_CLAMONACC=OFF -DENABLE_EXAMPLES=OFF -DENABLE_MAN_PAGES=OFF -DENABLE_SYSTEMD=OFF >/dev/null
cmake --build "$B" -j"$(nproc)" && cmake --install "$B" >/dev/null
# the in-tree certs directory is what clamscan/freshclam need via --cvdcertsdir (ClamAV >= 1.5)
mkdir -p "$I/certs" && cp -r "$S/certs/." "$I/certs/"
mkdir -p "$I/bin" && for t in clamscan freshclam clamd clamdscan; do p=$(find "$I" -name $t -type f -perm -u+x | head -1); [ -n "$p" ] && [ "$(dirname "$p")" != "$I/bin" ] && cp "$p" "$I/bin/"; done
"$I/bin/clamscan" --version
