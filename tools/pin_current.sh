#!/bin/bash
# One-off: fill the empty sha256 values for the versions already in deps.env (run once, then commit deps.env).
. "$(dirname "$0")/lib.sh"
f=$ROOT/deps.env
for k in CLAMAV_SRC CLAMAV_WIN; do
  url=$(grep "^${k}_URL=" "$f" | cut -d= -f2-); cur=$(grep "^${k}_SHA256=" "$f" | cut -d= -f2-)
  [ -z "$cur" ] || continue
  h=$(curl -fsSL --retry 3 "$url" | sha256sum | cut -d' ' -f1); sed -i "s|^${k}_SHA256=.*|${k}_SHA256=$h|" "$f"; echo "$k -> $h"
done
