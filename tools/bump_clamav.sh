#!/bin/bash
# Pin a new ClamAV version: downloads the source tarball and the official Windows zip, computes their sha256 and rewrites deps.env.
# usage: bump_clamav.sh 1.5.5        (a human still reviews the PR: release notes, security advisories, patch compatibility)
. "$(dirname "$0")/lib.sh"
v=${1:?usage: bump_clamav.sh VERSION}; [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "bad version: $v"
base=https://github.com/Cisco-Talos/clamav/releases/download/clamav-$v
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
curl -fsSL --retry 3 -o "$T/src.tgz" "$base/clamav-$v.tar.gz"      || die "cannot download the source tarball for $v"
curl -fsSL --retry 3 -o "$T/win.zip" "$base/clamav-$v.win.x64.zip" || die "cannot download the Windows zip for $v"
s=$(sha256sum "$T/src.tgz" | cut -d' ' -f1); w=$(sha256sum "$T/win.zip" | cut -d' ' -f1)
f=$ROOT/deps.env; tmp=$(mktemp)
sed -E "s|^CLAMAV_VERSION=.*|CLAMAV_VERSION=$v|; s|^CLAMAV_SRC_URL=.*|CLAMAV_SRC_URL=$base/clamav-$v.tar.gz|; s|^CLAMAV_SRC_SHA256=.*|CLAMAV_SRC_SHA256=$s|; s|^CLAMAV_WIN_URL=.*|CLAMAV_WIN_URL=$base/clamav-$v.win.x64.zip|; s|^CLAMAV_WIN_SHA256=.*|CLAMAV_WIN_SHA256=$w|" "$f" > "$tmp" && mv "$tmp" "$f"
echo "deps.env now pins ClamAV $v"; grep '^CLAMAV' "$f"
