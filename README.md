# clam-rtgui — ClamGUI + clamrt for ClamAV

A ClamWin-style desktop front-end (**ClamGUI**) and a real-time on-access scanner (**clamrt**) for [ClamAV](https://www.clamav.net/), with a pinned-dependency CI/CD pipeline. Windows and Linux.

> **Status:** ClamGUI **v3** (audit release), clamrt **v4**, ClamAV **1.5.4**. Built and tested on Linux; the Windows build compiles but has not been run by the author. See [Verification status](#verification-status).

## Components

| Component | Where | What it is | Needs ClamAV at build time? |
|---|---|---|---|
| **ClamGUI** | `clamgui/clamgui_v3.cpp` | Single-file C++17 / FLTK 1.3 GUI. Drives the official ClamAV command-line tools; contains no scan engine. | No |
| **clamrt** | `clamrt/` | Real-time scanner: fanotify (Linux) / minifilter hooks (Windows). Talks to `clamd` over INSTREAM; does not link libclamav. | No |
| **ClamAV** | pinned in `deps.env` | Upstream engine. Linux: built from the pinned source tarball. Windows: the official Cisco zip, sha256-verified. | — |

## ClamGUI features

- **Scanning:** on-demand scan of files/folders, headless CLI mode with exit codes (0 clean / 1 infected / 2 error), optional fast engine via a managed `clamd` (`clamdscan`).
- **Automatic scans:** new USB/removable media, finished downloads, and recent-files triage ordered by file-type risk.
- **Updates and scheduling:** freshclam updates; scheduled scans and updates via cron (Linux) or Task Scheduler (Windows).
- **Quarantine vault:** private directory, SHA-256 recorded per item, integrity check on restore, restore never overwrites, read-only analysis copies, **signed evidence export** (Ed25519 via `openssl`, HMAC fallback).
- **Threat intel (opt-in):** hash-only lookups (MalwareBazaar / VirusTotal). Only the hash is sent; API keys live in a `0600` curl config, never on a command line.
- **Background protection:** tray icon, desktop notifications, `--service` supervisor for clamd + clamrt (hardened systemd unit generator on Linux, Windows service installer).
- **Fleet mode:** policy file (local path or HTTPS URL), optionally HMAC-signed, overrides a whitelist of settings; scan reports can be uploaded.
- **Integration:** Nautilus / Dolphin / Thunar context-menu entries on Linux.

### Command line

```
clamgui [PATH ...]                    open the GUI and scan PATH(s)
clamgui --scan PATH ...               headless scan
clamgui --scan-recent [DIR] [--days N]   riskiest recent files first
clamgui --scheduled-scan | --scheduled-update | --install-schedule | --remove-schedule
clamgui --quarantine-list | --restore ID [--to DIR] [--force] | --delete ID
clamgui --export-evidence FILE | --verify-export FILE
clamgui --lookup SHA256 | --sha256 FILE... | --policy-sign FILE
clamgui --service | --print-systemd-unit | --install-service | --remove-service
clamgui --install-filemanager | --remove-filemanager
clamgui --home DIR                    portable mode (also CLAMGUI_HOME=DIR)
```

### Security model

No shell is ever involved: every helper is started from an argument array (`posix_spawnp` / `CreateProcessW`). Tool output is sanitised before display, symlinks are never followed or scanned, config is written atomically with `0600`, the vault is `0700` with `0400` files, curl is run with `-q -g`, HTTPS only (plain HTTP only to loopback), and every helper call is time-bounded with process-group kill. Files whose names contain a newline cannot be put in a scan list; they are reported as *not scanned* rather than silently skipped.

## Build

Requirements: g++ ≥ 9 (C++17), FLTK 1.3 (`fltk-config`), and for Windows `x86_64-w64-mingw32-g++-posix`.

```bash
# Linux (what tools/build_clamgui.sh runs)
g++ -std=gnu++17 -O2 -Wall -Wextra -Wno-missing-field-initializers -o clamgui_v3 \
    clamgui/clamgui_v3.cpp $(fltk-config --cxxflags --ldstaticflags) -pthread
```

Or use the helper scripts:

```
tools/pin_current.sh               # fill any empty ClamAV sha256 values in deps.env (verify against upstream!)
tools/build_clamav_linux.sh        # build/clamav-linux/{bin,certs}
tools/build_clamrt.sh linux|win    # build/out/clamrt_*
tools/build_clamgui.sh linux [none|asan|tsan]
tools/build_fltk_win.sh && tools/build_clamgui.sh win
tools/stage_installer.sh           # payload for installer/clamgui.iss (Inno Setup, run on Windows)
```

## Test

```
tools/test_clamgui_e2e.sh [none|asan|tsan]   # 110 checks: CLI, odd paths, symlinks, vault, scheduler, intel mock, policy, GUI smoke (Xvfb)
tools/test_clamrt_unit.sh                    # 30 unit tests, ASan+UBSan
tools/test_clamrt_e2e.sh                     # needs root + fanotify
tools/check_versions.sh                      # filename version == every in-file/doc/installer reference
```

The e2e script expects the ClamAV tools via env vars `CLAMSCAN`, `FRESHCLAM`, `CLAMD`, `CLAMDSCAN`, `CERTS`; the tools/ wrapper sets them.

## Repository layout

```
clamgui/      ClamGUI source, e2e test, guide (versioned: clamgui_vN.*)
clamrt/       real-time scanner sources, tests, guide
tools/        build, test, pin and bump scripts
cmake/        mingw-w64 toolchain file
installer/    Inno Setup script and license texts
tests/e2e/    shared e2e helpers
.github/workflows/   ci.yml, clamav-watch.yml, release.yml
deps.env      single source of truth for upstream versions
```

## CI/CD

- `build.yml` — builds the binaries (ClamGUI + clamrt for Linux x86_64 and Windows x64) on every PR/push to `main`, uploads them as workflow artifacts with `SHA256SUMS`, runs the Windows `.exe` on a Windows runner (`--version`, `--sha256`), and on a `v*` tag attaches everything to a **draft** GitHub release. Needs no ClamAV.
- `ci.yml` — every PR: version hygiene + shellcheck, ClamAV build (cached by `deps.env`), clamrt unit/e2e, ClamGUI e2e on normal/ASan/TSan, Windows cross-build, Windows smoke test with the official ClamAV Windows tools.
- `clamav-watch.yml` — daily: new Cisco release → `tools/bump_clamav.sh` → PR for human review.
- `release.yml` — tag `v*`: re-run CI, build, sign (Azure Trusted Signing hooks), Inno installer, SHA256SUMS, provenance attestation, **draft** release including the ClamAV source tarball and our source (GPL).

A new ClamAV release is a one-line PR to `deps.env`. CI never downloads "latest": every artifact is pinned and hash-verified.

### One-time setup

1. ClamAV hashes in `deps.env` are filled in (computed from the 1.5.4 release assets — compare with Cisco's release page). FLTK is pinned to a git commit. For a new ClamAV version run `tools/bump_clamav.sh`.
2. Protect `main`: PRs only, required checks = every job in `ci.yml`.
3. Create a `release` environment with a required reviewer; add signing secrets (`SIGN_WITH=azure`, `AZURE_*`, `SIGN_*`) or swap in your own signtool step.
4. Edit `installer/clamgui.iss` (new AppId GUID, publisher, URL) and `installer/licenses/*`.

### Versioning rule

Renaming `clamgui_vN.cpp` → `clamgui_vN+1.cpp` means renaming the guide and e2e script and bumping every in-file reference (`CLAMGUI_VERSION`, header, usage text, report headers) and the companion docs. `tools/check_versions.sh` fails the PR if anything is stale.

## Verification status

Tested: ClamGUI v3 e2e **110/110** on Linux normal, ASan+UBSan and TSan builds (against ClamAV 1.5.4 built from source), mingw `-Werror` build.

Not verified — treat as unproven until you run it:
- The Windows exe has never been run (no Windows machine or Wine was available); the Windows service, tray and PowerShell-notification paths are compile-checked only.
- No access to `database.clamav.net` during development: signature updates, hash lookups and report upload were tested against a local mock only.
- Linux tray tested only with `stalonetray` under Xvfb; clamrt real-time blocking was exercised only through supervisor start-up.
- The GitHub workflows have never run on GitHub (the build chain behind `build.yml` — FLTK for Windows, ClamGUI and clamrt for both platforms — was run locally and produced all four binaries); `build_clamav_linux.sh`, `build_fltk_win.sh`, the installer, signing steps and the Windows smoke job are untested. `fetch_deps.sh` / `bump_clamav.sh` assume Cisco's current asset names (`clamav-X.Y.Z.tar.gz`, `clamav-X.Y.Z.win.x64.zip`).
- The clamrt e2e job needs root and fanotify; hosted runners may refuse it — mark it non-blocking or use a self-hosted runner.

## Documentation

- `clamgui/clamgui_guide_v3.md` — audit summary, changelog, limits, ideas.
- `clamrt/clamrt_guide_v4.md` — real-time scanner guide.

## License

ClamAV is GPLv2 (Cisco-Talos); redistributing its binaries requires shipping the license and offering the corresponding source. ClamGUI/clamrt licensing is **not yet chosen** — see `installer/licenses/LICENSE-ClamGUI.txt` and set it before publishing releases.
