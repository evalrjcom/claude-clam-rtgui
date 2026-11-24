# ClamGUI v3 — Audit Release Guide

File: `clamgui_v3.cpp` (single file, C++17 / FLTK 1.3, Linux + Windows). Every change is marked `v3 FIX` / `v3` in the source.

## 1. Audit summary
Method: g++ extended warnings, clang-tidy (bugprone, clang-analyzer, cert-err33-c), manual review of process/IO/network/vault code, ASan+UBSan+TSan runs of the e2e suite.

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | High | `run_capture` blocked forever on a hung helper (notify-send, openssl, sc.exe) — froze the UI thread | Timed pop, default 60 s, child killed, returns -2 |
| 2 | High | `Proc::kill` signalled only the direct child; a helper whose grandchild held the pipe made `~Proc` hang | Child in own process group; `kill` signals group; new `kill_hard` (SIGKILL group) on timeout |
| 3 | High (Win) | Notification text spliced into a PowerShell script; typographic quotes in a file name could break out | Text passed via environment variables, read as data |
| 4 | Medium | curl read `~/.curlrc` (hostile proxy/headers) and did URL globbing | `-q` first, `-g` added |
| 5 | Medium | Files with a newline in the name were silently omitted from recent/download scans (hiding place) | Counted and reported (CLI warning, GUI alert) |
| 6 | Medium | Uninitialised `http` in policy fetch, report upload, async pump, `--lookup` | Initialised to 0 |
| 7 | Low | systemd unit ternary had identical branches | Uses own path if under /usr or /opt, else documented install target |
| 8 | Low | `-Wall -Wextra -Werror` clean on Linux and mingw | — |

## 2. Changelog v2 → v3
- Bounded helper execution (timeout, hard kill, process groups).
- PowerShell notification injection closed.
- curl hardened (`-q`, `-g`).
- Newline-named files reported, not silently skipped.
- Uninitialised variables fixed; systemd unit path fixed.
- All version references bumped to v3; 5 new regression tests (110 total).

## 3. Tests
Normal build 110/110. ASan+UBSan 110/110 and TSan 110/110, no sanitizer reports. New tests: hung helper killed within timeout, no leftover helper, systemd unit target, newline-file warning, hostile `.curlrc` ignored.

## 4. Honest limits
- Windows exe built with mingw but never run (no Windows/Wine here); the PowerShell fix is compile-checked only.
- No network to database.clamav.net; lookups and report upload tested against a local mock only.
- Linux tray tested only with stalonetray under Xvfb.
- clamrt real-time blocking exercised only via supervisor start-up.
- CI workflows never run on GitHub.
- Not every function was exhaustively reviewed (sched_apply, Windows service installer, Thunar XML escaping got lighter review) — treat as a good audit, not a proof.

## 5. Efficiency / effectiveness suggestions
- Reuse one clamd connection (`clamdscan --stream`/INSTREAM) for the download watcher instead of spawning per batch.
- Hash cache (path+mtime+size → verdict) so recent-file scans skip unchanged clean files.
- Run lookups/notifications on a worker queue so no UI-thread blocking call remains.
- Bound the vault (age/size quota) and prune reports by size, not only count.
- Replace polling watchers with inotify / ReadDirectoryChangesW.
- Support NUL-delimited lists via a wrapper to cover newline names fully.

## 6. Innovation ideas
- Local verdict cache shared across a fleet with signed deltas.
- Behavioural triage: flag archives/scripts dropped by browsers within seconds of an Office/PDF process spawn.
- Offline YARA rule pack alongside ClamAV signatures, with rule-update signing.
- "Explain this detection" panel: file type, entropy, signature origin, lookup result.
- Ransomware canary files with tamper alerts feeding the tray.
- One-click evidence bundle (report + vault manifest + hashes) for incident response.
