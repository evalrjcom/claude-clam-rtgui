# clamrt guide v4

Real-time ClamAV front-end (Linux inotify/fanotify, Windows ReadDirectoryChangesW/ETW). v4 = audit round on v3.

## 1. Audit Summary (defects found in v3, all fixed in v4)

**Critical / high**
- **fanotify exec hang risk**: `--scan-existing` and queue-overflow rescans ran a full tree walk on the fanotify reader thread. While it ran, every `FAN_OPEN_EXEC_PERM` event on the mount blocked in the kernel. Sweeps now run on a dedicated coalescing sweep thread; the reader only answers events. *Fixed by code analysis. I could not reproduce the hang here (a 300k-file walk takes ~0.1 s), so the regression test only proves exec latency stays low during a walk.*
- **Known malware released when clamd is down**: fail-open let a previously denied binary run once clamd was unreachable. New infected-verdict table (`g_bad`, TTL <= 60 s) keeps known-bad files denied.
- **Detection storm**: N exec attempts of one infected file produced N reports/quarantine attempts. Now de-duplicated in a 5 s window (`exec_denied_total` still counts every denial).
- **Tripwire false positives**: one file rewritten many times, git-style zlib objects with no extension, and gzip files renamed `.bak` all looked like encryption. Now counts distinct paths (256-entry ring per pid) and recognises zlib/known magic.
- **Tripwire entropy sampling on the event path** moved to a sampler thread (queue 1024, retry on transient error, 200 writes/s budget).
- **Ignore lists**: `--tripwire-ignore-comm` never matched names over 15 chars (kernel truncates comm). Matching now truncates; new `--tripwire-ignore-exe` matches the resolved exe path (comm is spoofable, use exe).
- **Auto mode + tripwire suspend/kill** picked inotify, which has no pid, so the action could never fire. Auto now selects fanotify (warns and stays alert-only if unavailable).

**Medium**
- Condition variable shared between workers and sweeper (lost wakeups) -> separate cond, broadcast on shutdown.
- AF_UNIX non-blocking `connect()` returning EAGAIN (clamd backlog full) was treated as a scan error -> bounded 5 ms retry.
- Merged fanotify masks (`MODIFY|CLOSE_WRITE`) dropped the close-write half.
- Canary alert limiter was global (second process masked) -> per pid.
- inotify watch-root deletion was silent -> logs "NO LONGER WATCHED".
- `plat_suspend_pid` could stop system daemons -> protected list (systemd, sshd, dbus, dockerd, ...).
- Metrics/TUI `[IPv6]:PORT` not parsed; sends could SIGPIPE (now `MSG_NOSIGNAL`); HTTP status line checked strictly.
- Syslog/Event Log sink dropped structured fields (sha256 etc.).
- Windows: `quote_arg` overflow with backslashes before quotes; ETW pid attribution now first-opener-wins for 3 s; early-return paths free ETW/minifilter client.

## 2. Code
All source is in `clamrt_v4_src.tar.gz` (dir `clamrt-v4/`) and `clamrt_v4.patch`, with `// v4 FIX` / `v4 NEW` inline comments at each change. `clamrt_v3_to_v4.diff` is the pure v3->v4 delta.

## 3. Key changes (changelog)
- Sweep thread (async `--scan-existing`/overflow); exec scope check on the reader.
- Infected-verdict cache + 5 s report de-duplication.
- Tripwire: sampler thread, distinct-path counting, magic/zlib recognition, per-pid canary limiter, enqueue-time ignore decision.
- New option `--tripwire-ignore-exe PATH` (implies `--tripwire`); `--metrics`/`--tui` accept `[IPv6]:PORT`.
- Auto mode selects fanotify for tripwire suspend/kill.
- Hardening: protected process list, MSG_NOSIGNAL, strict HTTP parse, EAGAIN retry, cond-var fixes.
- Windows: quote_arg bound, ETW attribution, cleanup paths.
- Version bumped to 4 everywhere (header, banner, CMake, minifilter files, tests, this guide).

## 4. Test results (v4 binaries, Linux x86_64, root, private clamd)
| Suite | normal | ASan+UBSan | TSan |
|---|---|---|---|
| e2e_test.sh (v2) | 29/29 | 29/29 | 29/29 |
| e2e_v3_test.sh | 61/61 | 61/61 | 61/61 |
| e2e_v4_test.sh (new) | 24/24, 1 skip | 24/24, 1 skip | 24/24, 1 skip |
| test_plat / test_v3 (unit) | 30/30, 32/32 | | |

No sanitizer reports. Skipped: IPv6 loopback absent in the sandbox (the `[::1]` parse is therefore **untested at runtime**). CMake build inside the ClamAV 1.5.4 tree and the mingw Windows cross-build both compile cleanly.

## 5. Honest limits
- Windows build **has never been run** (compiled only). Use `--action report` first; blocking/suspend needs Administrator (Windows) or root (Linux).
- The minifilter driver (`minifilter/`) has **never been compiled** (needs the WDK).
- The fanotify hang fix is by analysis, not reproduction (see above).
- `--tripwire-ignore-comm` is spoofable; prefer `--tripwire-ignore-exe`.
- Infected cache TTL is at most 60 s; files over `--max-size` are allowed unscanned on exec.
- The metrics endpoint is unauthenticated: bind to loopback.
- Tripwire still treats real encryption tools (gpg, age, openssl) as suspicious unless ignored.

## 6. Suggestions: effectiveness and efficiency
- Use clamd IDSESSION + FILDES (pass fd) to cut per-file connects and avoid re-reading files.
- Priority queue (exec > canary > bulk) plus a global rate cap so a bulk write storm cannot starve exec checks.
- `.clamrtignore` glob files per watch root (build dirs, VM images) to remove most scan load.
- Persist the verdict cache across restarts (keyed by inode/size/mtime/ctime + DB version).
- Scan-large-binaries policy: partial scan (head/tail + section hashes) instead of allow-unscanned for execs above `--max-size`.
- Batch tripwire sampling per directory to reduce reads.

## 7. Innovation roadmap
- Hash-chained, tamper-evident audit log (and optional signed export).
- eBPF (LSM/tracepoint) pid attribution for inotify mode; lower overhead than fanotify perm events.
- YARA rules beside ClamAV signatures for behavioural/packer detection.
- Quarantine CLI (`clamrt-q list|restore|purge`) with chain-of-custody metadata.
- Windows service wrapper and a small GUI tray.
- Kubernetes DaemonSet + admission hook; S3/object-store bucket scanning.
- Canary fleets that self-rotate, with decoys placed per user profile.
