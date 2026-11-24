# clamrt minifilter (optional, UNTESTED) — v4

`clamrt_mf.sys` is the only way to **block** program execution on Windows from a ClamAV front-end: the user-mode
watcher in `clamrt.exe` sees files after they are written, a minifilter sees the moment a process asks Windows to map a
file as executable and can refuse it.

**Status: source only.** It has not been compiled (no WDK in the build environment), signed or run. `clamrt.exe`'s
side of the protocol (`--block-exec`, in `clamrt_win_ext.c`) *is* compiled but equally untested at runtime.

## Build and try it (on a disposable VM)
1. Visual Studio + WDK. New project "Filter Driver: Filesystem Mini-Filter (KMDF not needed)", replace the generated
   source with `clamrt_mf.c`, add `clamrt_mf_proto.h` (this directory), link `fltmgr.lib`, `Driver Verifier` on.
2. `bcdedit /set testsigning on`, reboot, `pnputil /add-driver clamrt_mf.inf /install` (or right-click *Install*),
   `fltmc load clamrt_mf`. Production use needs an EV code-signing certificate + Microsoft attestation signing.
3. Run `clamrt.exe --path C:\Users --action report --block-exec --exec-timeout-ms 4000` as Administrator.
   Start an EICAR/Test.Sig copy of an `.exe` from a watched folder: process creation fails with "Access is denied".
4. `fltmc unload clamrt_mf` to remove. If the client disconnects the driver fails **open** (everything runs).

## Behaviour
* hook: `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` with executable page protection (image loads and executable
  mappings), user-mode requestors only; the client's own pid is exempt
* wait: at most `--exec-timeout-ms` (100–30000) for the verdict; then fail-open, or fail-closed with `--exec-fail closed`
* port: `\ClamrtPort`, one client, SYSTEM/Administrators only
* verdicts reuse the clamd scan and the verdict cache of the user-mode client, so a re-launched clean program costs nothing

## Known limits / things to review before trusting it
* DLL loads, `CreateProcess` and `mmap(PAGE_EXECUTE*)` are covered; interpreters reading *scripts* (PowerShell,
  Python, batch) open them as ordinary data and are **not** blocked.
* No deadlock analysis for filesystems layered on network redirectors; no per-volume instance filtering
  (add `InstanceSetup` to skip network / removable volumes if needed).
* Altitude 320005 is in the Anti-Virus range for development; Microsoft assigns real altitudes.
