# clamsuite - ClamGUI + clamrt + pinned ClamAV, with CI/CD

| Component | Source | How it is built | Depends on ClamAV at build time? |
|---|---|---|---|
| **ClamGUI** (`clamgui/clamgui_vN.cpp`) | ours | g++ (Linux) / mingw-w64 cross (Windows), static FLTK | No - it only runs the ClamAV command-line tools |
| **clamrt** (`clamrt/`) | ours | CMake standalone, gcc / mingw-w64 | No - talks to clamd over INSTREAM, does not link libclamav |
| **ClamAV** | Cisco-Talos | Linux: built from the pinned source tarball. Windows: the *official* Cisco Windows zip, pinned + sha256-verified | - |

`deps.env` is the only place where upstream versions live. A new ClamAV release = one PR that changes `deps.env`.

## Everyday commands
```
tools/pin_current.sh               # once: fill the sha256 values for the versions already in deps.env (check them against upstream!)
tools/build_clamav_linux.sh        # build/clamav-linux/{bin,certs}
tools/build_clamrt.sh linux|win    # build/out/clamrt_*
tools/test_clamrt_unit.sh          # 30 unit tests, ASan+UBSan
tools/build_clamgui.sh linux [none|asan|tsan]
tools/build_fltk_win.sh && tools/build_clamgui.sh win
tools/test_clamgui_e2e.sh [none|asan|tsan]
tools/check_versions.sh            # filename version == every in-file / doc / installer reference
tools/stage_installer.sh           # payload for installer/clamgui.iss (Inno Setup, run on Windows)
```

## Workflows
* `ci.yml` - every PR: version hygiene + shellcheck, ClamAV build (cached by `deps.env`), clamrt unit/e2e, ClamGUI e2e on normal/ASan/TSan, Windows cross-build, and a **Windows smoke test that really runs the exe** with the official ClamAV Windows tools.
* `clamav-watch.yml` - daily: new Cisco release -> `tools/bump_clamav.sh` -> PR (CI runs on it; a human reviews and merges).
* `release.yml` - tag `v*`: re-runs CI, builds, signs (Azure Trusted Signing hooks; adapt for your certificate), builds the Inno installer, writes SHA256SUMS, provenance attestation, publishes a **draft** release with the ClamAV source tarball and our source (GPL).

## One-time setup checklist
1. `git init`, push to GitHub; run `tools/pin_current.sh`, verify the printed hashes against Cisco's release page, commit `deps.env`.
2. Branch protection on `main`: PRs only, required checks = every job in `ci.yml`.
3. Settings -> Environments -> create `release` (required reviewer). Add signing secrets/vars there (`SIGN_WITH=azure`, `AZURE_*`, `SIGN_*`) or swap in your own signtool step.
4. Edit `installer/clamgui.iss` (new AppId GUID, publisher, URL) and `installer/licenses/*` (your license, the GPLv2 text, contact).
5. Versioning rule: renaming `clamgui_vN.cpp` -> `clamgui_vN+1.cpp` means renaming the guide and e2e script and updating every in-file reference; `check_versions.sh` fails the PR if anything is stale.

## Not verified yet (be honest before relying on it)
* The workflows have never run on GitHub (YAML parses; scripts were run locally except the items below).
* `build_clamav_linux.sh` and `build_fltk_win.sh` were not executed here (the sandbox has no access to the download hosts; my local ClamAV and FLTK builds were made earlier by hand).
* `fetch_deps.sh`/`bump_clamav.sh` assume Cisco's current asset names (`clamav-X.Y.Z.tar.gz`, `clamav-X.Y.Z.win.x64.zip`) - check them on the release page.
* The installer script, signing steps and the Windows smoke job are untested.
* The clamrt e2e job needs root and fanotify; hosted runners may refuse fanotify inside their container setup - if so, mark that step non-blocking or use a self-hosted runner.
