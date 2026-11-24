/*
 * clamrt_win.c -- clamrt v4 Windows back-end (ReadDirectoryChangesW, user mode; ETW / minifilter helpers in clamrt_win_ext.c).
 *
 * One overlapped ReadDirectoryChangesW per watch root, all multiplexed on a
 * single thread with WaitForMultipleObjects.  Files are scanned shortly AFTER
 * they are written ("scan on write"); this is a user-mode design with no kernel
 * driver, so it cannot block the opening process (that needs a minifilter).
 *
 * Paths are UTF-8 internally and converted to wide strings (with the \\?\
 * long-path prefix) at the Win32 boundary.  Symlinks / junctions are never
 * followed.
 *
 * NOTE: this file is cross-compiled and compile-checked on Linux (mingw-w64);
 * it has not been run on a Windows machine in this build environment.
 *
 * v2 FIX / v2 NEW comments mark changes relative to v1; v3 NEW / v3 FIX relative to v2.
 */
#include "clamrt.h"

#include <shellapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_WALK_DEPTH 128
#define NOTIFY_BUF_DWORDS (16 * 1024) /* 64 KiB, DWORD aligned as the API requires */

#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK 0xA000000CL
#endif
#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003L
#endif
#ifndef FILE_ATTRIBUTE_RECALL_ON_OPEN
#define FILE_ATTRIBUTE_RECALL_ON_OPEN 0x00040000
#endif
#ifndef FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
#define FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS 0x00400000
#endif

static HANDLE g_stop_ev;

/* ---------------------------------------------------------------- conversions */
/* UTF-8 (absolute, backslash-normalised) -> wide, with \\?\ or \\?\UNC\ prefix. */
static wchar_t *u8_to_w(const char *s, int prefix_long)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    const wchar_t *pre = L"";
    size_t prelen = 0;
    wchar_t *w;

    if (n <= 0) return NULL;
    if (prefix_long) {
        if (s[0] == '\\' && s[1] == '\\' && s[2] != '?' && s[2] != '.') {
            pre = L"\\\\?\\UNC\\";
            s += 2; /* skip the leading \\ of the UNC path */
            n -= 2;
        } else if (((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) && s[1] == ':' && s[2] == '\\') {
            pre = L"\\\\?\\";
        }
        prelen = wcslen(pre);
    }
    w = malloc(((size_t)n + prelen) * sizeof(wchar_t));
    if (!w) return NULL;
    wcscpy(w, pre);
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w + prelen, n) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

static char *w_to_u8(const wchar_t *w, int wlen) /* wlen<0: NUL terminated */
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, NULL, 0, NULL, NULL);
    char *s;
    if (n <= 0) return NULL;
    s = malloc((size_t)n + 1);
    if (!s) return NULL;
    if (WideCharToMultiByte(CP_UTF8, 0, w, wlen, s, n, NULL, NULL) <= 0) {
        free(s);
        return NULL;
    }
    s[n] = '\0';
    return s;
}

/* ---------------------------------------------------------------- init / misc */
static BOOL WINAPI on_ctrl(DWORD type)
{
    (void)type;
    RT_REQUEST_STOP();
    if (g_stop_ev) SetEvent(g_stop_ev);
    return TRUE;
}

int plat_init(void)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
    g_stop_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_stop_ev) return -1;
    SetConsoleCtrlHandler(on_ctrl, TRUE);
    return 0;
}

void plat_cleanup(void)
{
    if (g_stop_ev) CloseHandle(g_stop_ev);
    WSACleanup();
}

/* v2 FIX: main()'s argv is in the ANSI code page on Windows, so a --path / --log / --quarantine-dir containing
 * non-ASCII characters was silently corrupted.  Re-read the command line as UTF-16 and convert to UTF-8. */
void plat_args(int *argc, char ***argv)
{
    int n = 0, i;
    LPWSTR *wv = CommandLineToArgvW(GetCommandLineW(), &n);
    char **nv;
    if (!wv) return;
    nv = calloc((size_t)n + 1, sizeof *nv);
    if (!nv) { LocalFree(wv); return; }
    for (i = 0; i < n; i++) {
        nv[i] = w_to_u8(wv[i], -1);
        if (!nv[i]) { LocalFree(wv); return; } /* keep the original argv on any failure */
    }
    LocalFree(wv);
    *argc = n;
    *argv = nv;
}

/* v2 NEW: Unicode-safe log open (append); SIGHUP-style reopen does not exist on Windows. */
FILE *plat_fopen_log(const char *path)
{
    wchar_t *w = u8_to_w(path, 0);
    FILE *f;
    if (!w) return NULL;
    f = _wfopen(w, L"ab");
    free(w);
    return f;
}

int plat_take_log_reopen(void) { return 0; }

uint64_t plat_now_ms(void) { return (uint64_t)GetTickCount64(); }

int plat_abspath(const char *in, char *out, size_t outsz)
{
    wchar_t *w = u8_to_w(in, 0), *full = NULL;
    DWORD n;
    char *u = NULL;
    int rc = -1;
    size_t l;

    if (!w) return -1;
    n = GetFullPathNameW(w, 0, NULL, NULL);
    if (!n) goto out;
    full = malloc((size_t)n * sizeof(wchar_t));
    if (!full || !GetFullPathNameW(w, n, full, NULL)) goto out;
    l = wcslen(full);
    while (l > 3 && full[l - 1] == L'\\') full[--l] = L'\0'; /* keep "C:\" intact */
    u = w_to_u8(full, -1);
    if (!u || strlen(u) >= outsz) goto out;
    strcpy(out, u);
    rc = 0;
out:
    free(w);
    free(full);
    free(u);
    return rc;
}

/* v2 FIX: v1 created the quarantine directory with the inherited ACL (often readable/writable by "Users").
 * It is now created with a protected DACL granting only SYSTEM and Administrators.  A pre-existing directory
 * cannot be verified cheaply, so a reminder is logged. */
int plat_prepare_dir(const char *in, char *out, size_t outsz)
{
    wchar_t *w;
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR sd = NULL;
    int ok;
    if (plat_abspath(in, out, outsz) != 0) return -1;
    w = u8_to_w(out, 1);
    if (!w) return -1;
    memset(&sa, 0, sizeof sa);
    sa.nLength = sizeof sa;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)", SDDL_REVISION_1, &sd, NULL)) {
        free(w);
        return -1;
    }
    sa.lpSecurityDescriptor = sd;
    if (CreateDirectoryW(w, &sa)) {
        ok = 1;
    } else if (GetLastError() == ERROR_ALREADY_EXISTS) {
        ok = 1;
        rt_log(RT_LOG_INFO, "quarantine dir %s already exists: make sure only SYSTEM/Administrators can access it", out);
    } else {
        ok = 0;
    }
    LocalFree(sd);
    free(w);
    return ok ? 0 : -1;
}

int plat_str_prefix(const char *s, const char *prefix)
{
    size_t pl = strlen(prefix);
    return _strnicmp(s, prefix, pl) == 0 && (s[pl] == '\0' || s[pl] == '\\' || (pl && prefix[pl - 1] == '\\'));
}

int plat_str_contains(const char *hay, const char *needle)
{
    size_t nl = strlen(needle);
    if (nl == 0) return 1;
    for (; *hay; hay++)
        if (_strnicmp(hay, needle, nl) == 0) return 1;
    return 0;
}

/* ---------------------------------------------------------------- directory walk */
enum { WALK_NONE = 0, WALK_ALL = 1, WALK_RECENT = 2 }; /* v2 NEW (mirrors the Linux back-end) */

static ULONGLONG ft_to_u64(FILETIME ft) { ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime; return u.QuadPart; }

static void walk_dir(const char *dir, int mode, ULONGLONG since, int depth)
{
    WIN32_FIND_DATAW fd;
    HANDLE h;
    char *pattern;
    wchar_t *wpat;

    if (depth > MAX_WALK_DEPTH || rt_excluded(dir)) return;
    pattern = malloc(strlen(dir) + 3);
    if (!pattern) return;
    sprintf(pattern, "%s\\*", dir);
    wpat = u8_to_w(pattern, 1);
    free(pattern);
    if (!wpat) return;
    h = FindFirstFileW(wpat, &fd);
    free(wpat);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        char *name, *full;
        if (fd.cFileName[0] == L'.' && (fd.cFileName[1] == L'\0' || (fd.cFileName[1] == L'.' && fd.cFileName[2] == L'\0'))) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            /* v2 FIX: v1 skipped EVERY reparse point.  Files compressed by "Compact OS", deduplicated files and
             * OneDrive placeholders are reparse points too, so they were never scanned.  Only directories that are
             * links are skipped here; plat_open() decides per file (symlink/junction/cloud placeholder). */
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.dwReserved0 == IO_REPARSE_TAG_SYMLINK ||
                fd.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT)
                continue;
        }
        name = w_to_u8(fd.cFileName, -1);
        if (!name) continue;
        full = malloc(strlen(dir) + strlen(name) + 2);
        if (full) {
            sprintf(full, "%s\\%s", dir, name);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (g_cfg.recursive) walk_dir(full, mode, since, depth + 1);
            } else if (mode == WALK_ALL || (mode == WALK_RECENT && (ft_to_u64(fd.ftLastWriteTime) >= since || ft_to_u64(fd.ftCreationTime) >= since)) /* v3: creation time too (copies keep an old mtime) */) {
                rt_emit(full);
            }
            free(full);
        }
        free(name);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static ULONGLONG recent_cutoff(void) /* "now - RT_OVERFLOW_RESCAN_WINDOW_S" as a FILETIME value (100 ns ticks) */
{
    FILETIME now;
    ULONGLONG back = (ULONGLONG)RT_OVERFLOW_RESCAN_WINDOW_S * 10000000ULL, n;
    GetSystemTimeAsFileTime(&now);
    n = ft_to_u64(now);
    return n > back ? n - back : 0;
}

/* ---------------------------------------------------------------- watcher */
typedef struct {
    HANDLE dir;
    OVERLAPPED ov;
    DWORD *buf;
    const char *root;
    int alive;
} wroot;

static int issue(wroot *r)
{
    DWORD filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE |
                   FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_CREATION;
    ResetEvent(r->ov.hEvent);
    return ReadDirectoryChangesW(r->dir, r->buf, NOTIFY_BUF_DWORDS * sizeof(DWORD), g_cfg.recursive ? TRUE : FALSE,
                                 filter, NULL, &r->ov, NULL)
               ? 0
               : -1;
}

static void handle_change(const wroot *r, DWORD action, const WCHAR *wname, DWORD wlen)
{
    char *name, *full;
    wchar_t *wfull;
    WIN32_FILE_ATTRIBUTE_DATA ad;

    if (action != FILE_ACTION_ADDED && action != FILE_ACTION_MODIFIED && action != FILE_ACTION_RENAMED_NEW_NAME) {
        /* v3 NEW: deletion / rename-away of a ransomware canary is an alert (the ETW pid lookup says who touched it) */
        if (g_cfg.tripwire && (action == FILE_ACTION_REMOVED || action == FILE_ACTION_RENAMED_OLD_NAME)) {
            char *n2 = w_to_u8(wname, (int)wlen), *f2;
            size_t rl = strlen(r->root);
            if (n2 && (f2 = malloc(rl + strlen(n2) + 2)) != NULL) {
                sprintf(f2, "%s%s%s", r->root, (rl && r->root[rl - 1] == '\\') ? "" : "\\", n2);
                if (rt_trip_is_canary(f2)) rt_trip_canary_event(f2, plat_etw_pid_for(f2), "deleted");
                free(f2);
            }
            free(n2);
        }
        return;
    }
    name = w_to_u8(wname, (int)wlen);
    if (!name) return;
    full = malloc(strlen(r->root) + strlen(name) + 2);
    if (!full) { free(name); return; }
    {
        size_t rl = strlen(r->root);
        sprintf(full, "%s%s%s", r->root, (rl && r->root[rl - 1] == '\\') ? "" : "\\", name);
    }
    free(name);

    wfull = u8_to_w(full, 1);
    /* v2 FIX: v1 dropped every entry with FILE_ATTRIBUTE_REPARSE_POINT here (see walk_dir); plat_open() now decides. */
    if (wfull && GetFileAttributesExW(wfull, GetFileExInfoStandard, &ad)) {
        if (ad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* a directory appearing/renamed in: files inside it produced no events of their own */
            if (g_cfg.recursive && action != FILE_ACTION_MODIFIED && !(ad.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                walk_dir(full, WALK_ALL, 0, 0);
        } else {
            rt_emit_pid(full, plat_etw_pid_for(full)); /* v3 NEW: originating process from ETW when available */
        }
    }
    free(wfull);
    free(full);
}

int plat_watch_run(void)
{
    wroot *roots = calloc((size_t)g_cfg.npaths, sizeof *roots);
    HANDLE *evs  = calloc((size_t)g_cfg.npaths + 1, sizeof *evs);
    int i, alive = 0, rc = 0;

    if (!roots || !evs) { free(roots); free(evs); return 1; }
    /* v3 NEW: mode handling.  ETW = originating PID of writes (tripwire); minifilter = blocking execution verdicts. */
    if (g_cfg.mode == RT_MODE_INOTIFY || g_cfg.mode == RT_MODE_FANOTIFY) {
        rt_log(RT_LOG_ERR, "--mode inotify/fanotify exist on Linux only");
        free(roots); free(evs); /* v4 FIX: leaked */
        return 1;
    }
    if (g_cfg.mode == RT_MODE_ETW || (g_cfg.tripwire && g_cfg.mode == RT_MODE_AUTO)) {
        if (plat_etw_start() != 0) {
            rt_log(g_cfg.mode == RT_MODE_ETW ? RT_LOG_ERR : RT_LOG_WARN,
                   "ETW file-event session could not start (needs Administrator): the tripwire cannot name the process behind a write");
            if (g_cfg.mode == RT_MODE_ETW) { free(roots); free(evs); return 1; }
        }
    }
    if (g_cfg.block_exec) {
        if (plat_mf_start() != 0) {
            rt_log(RT_LOG_ERR, "--block-exec: cannot connect to the clamrt minifilter driver (\\ClamrtPort). Install and load minifilter\\clamrt_mf.sys first");
            plat_etw_stop();
            free(roots); free(evs);
            return 1;
        }
    }
    for (i = 0; i < g_cfg.npaths; i++) {
        wchar_t *w = u8_to_w(g_cfg.paths[i], 1);
        roots[i].root = g_cfg.paths[i];
        if (!w) { rt_log(RT_LOG_ERR, "bad path: %s", g_cfg.paths[i]); continue; }
        roots[i].dir = CreateFileW(w, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                   OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
        free(w);
        if (roots[i].dir == INVALID_HANDLE_VALUE) {
            rt_log(RT_LOG_ERR, "cannot watch %s (error %lu)", g_cfg.paths[i], (unsigned long)GetLastError());
            continue;
        }
        roots[i].buf = calloc(NOTIFY_BUF_DWORDS, sizeof(DWORD));
        roots[i].ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!roots[i].buf || !roots[i].ov.hEvent || issue(&roots[i]) != 0) {
            rt_log(RT_LOG_ERR, "ReadDirectoryChangesW failed for %s (error %lu)", g_cfg.paths[i], (unsigned long)GetLastError());
            CloseHandle(roots[i].dir);
            continue;
        }
        roots[i].alive = 1;
        alive++;
        if (g_cfg.scan_existing) walk_dir(g_cfg.paths[i], WALK_ALL, 0, 0); /* watch first, then list: no gap */
    }
    if (!alive) { /* v4 FIX: stop ETW / minifilter client and free before giving up (v3 returned with both running) */
        plat_mf_stop();
        plat_etw_stop();
        free(roots); free(evs);
        return 1;
    }
    rt_log(RT_LOG_INFO, "watching %d root(s) with ReadDirectoryChangesW", alive);

    while (!RT_STOPPING() && alive) {
        DWORD w;
        int n = 0, map[RT_MAX_LIST];
        for (i = 0; i < g_cfg.npaths; i++)
            if (roots[i].alive) { evs[n] = roots[i].ov.hEvent; map[n++] = i; }
        evs[n] = g_stop_ev;
        w = WaitForMultipleObjects((DWORD)n + 1, evs, FALSE, 1000);
        if (w == WAIT_TIMEOUT) continue;
        if (w >= WAIT_OBJECT_0 + (DWORD)n) break; /* stop event (or wait failure) */
        {
            wroot *r = &roots[map[w - WAIT_OBJECT_0]];
            DWORD bytes = 0;
            int overflow = 0;
            if (!GetOverlappedResult(r->dir, &r->ov, &bytes, FALSE)) {
                DWORD e = GetLastError();
                if (e == ERROR_NOTIFY_ENUM_DIR) {
                    overflow = 1;
                } else {
                    rt_log(RT_LOG_ERR, "watch on %s ended (error %lu)", r->root, (unsigned long)e);
                    r->alive = 0;
                    alive--;
                    CloseHandle(r->dir);
                    continue;
                }
            } else if (bytes == 0) {
                overflow = 1;
            } else {
                const BYTE *p = (const BYTE *)r->buf, *end = p + bytes;
                for (;;) {
                    const FILE_NOTIFY_INFORMATION *fi = (const FILE_NOTIFY_INFORMATION *)p;
                    if (p + sizeof(FILE_NOTIFY_INFORMATION) > end ||
                        (const BYTE *)fi->FileName + fi->FileNameLength > end)
                        break; /* malformed buffer: never read out of bounds */
                    handle_change(r, fi->Action, fi->FileName, fi->FileNameLength / sizeof(WCHAR));
                    if (!fi->NextEntryOffset) break;
                    p += fi->NextEntryOffset;
                }
            }
            /* re-arm FIRST (minimises the blind window), then compensate for any lost events */
            if (issue(r) != 0) {
                rt_log(RT_LOG_ERR, "re-arming watch on %s failed (error %lu)", r->root, (unsigned long)GetLastError());
                r->alive = 0;
                alive--;
                CloseHandle(r->dir);
            } else if (overflow) {
                /* v2 FIX: v1 only logged the overflow; files changed meanwhile were silently never scanned. */
                rt_note_overflow();
                walk_dir(r->root, WALK_RECENT, recent_cutoff(), 0);
            }
        }
    }
    if (!alive && !RT_STOPPING()) rc = 1;
    for (i = 0; i < g_cfg.npaths; i++) {
        if (roots[i].alive) {
            CancelIoEx(roots[i].dir, NULL);
            CloseHandle(roots[i].dir);
        }
        if (roots[i].ov.hEvent) CloseHandle(roots[i].ov.hEvent);
        free(roots[i].buf);
    }
    free(roots);
    free(evs);
    plat_mf_stop();
    plat_etw_stop();
    return rc;
}

/* ---------------------------------------------------------------- file access */
static HANDLE open_win(const char *path, DWORD access, int follow_reparse)
{
    wchar_t *w = u8_to_w(path, 1);
    HANDLE h;
    DWORD flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN | (follow_reparse ? 0 : FILE_FLAG_OPEN_REPARSE_POINT);
    if (!w) return INVALID_HANDLE_VALUE;
    h = CreateFileW(w, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, flags, NULL);
    free(w);
    return h;
}

/* v2 NEW: true for reparse points we must not read through: symlinks, junctions, and cloud placeholders
 * (reading one would trigger a download of the whole file). */
static int reparse_is_unsafe(HANDLE h, DWORD attrs)
{
    FILE_ATTRIBUTE_TAG_INFO ti;
    DWORD tag;
    if (attrs & (FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_OFFLINE)) return 1;
    if (!(attrs & FILE_ATTRIBUTE_REPARSE_POINT)) return 0;
    if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &ti, sizeof ti)) return 1; /* unknown: be conservative */
    tag = ti.ReparseTag;
    if (tag == IO_REPARSE_TAG_SYMLINK || tag == IO_REPARSE_TAG_MOUNT_POINT) return 1;
    if ((tag & 0xFFFF0FFFu) == 0x9000001Au) return 1; /* IO_REPARSE_TAG_CLOUD_* */
    return 0; /* WOF/"Compact OS", dedup, ...: ordinary readable files */
}

int plat_open(const char *path, rt_fh *fh)
{
    BY_HANDLE_FILE_INFORMATION b0, b1;
    HANDLE h0, h;

    /* Step 1: look at the object itself (no reparse processing) to classify it. */
    h0 = open_win(path, FILE_READ_ATTRIBUTES, 0);
    if (h0 == INVALID_HANDLE_VALUE) {
        switch (GetLastError()) {
            case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND: case ERROR_INVALID_NAME: return RT_SKIP;
            case ERROR_ACCESS_DENIED: return RT_DENIED;
            default: return RT_ERR; /* e.g. ERROR_SHARING_VIOLATION: writer still has it locked */
        }
    }
    if (!GetFileInformationByHandle(h0, &b0) || (b0.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        reparse_is_unsafe(h0, b0.dwFileAttributes)) {
        CloseHandle(h0);
        return RT_SKIP;
    }

    /* Step 2 (v2 FIX): open for reading WITH normal reparse processing.  v1 read through a handle opened with
     * FILE_FLAG_OPEN_REPARSE_POINT, which bypasses filters such as WOF/dedup and returns raw (wrong) data. */
    h = open_win(path, GENERIC_READ, 1);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        CloseHandle(h0);
        switch (e) {
            case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND: case ERROR_INVALID_NAME: return RT_SKIP;
            case ERROR_ACCESS_DENIED: return RT_DENIED;
            default: return RT_ERR;
        }
    }
    /* Same object as step 1?  Detects a swap to a symlink/other file between the two opens. */
    if (!GetFileInformationByHandle(h, &b1) || b1.dwVolumeSerialNumber != b0.dwVolumeSerialNumber ||
        b1.nFileIndexHigh != b0.nFileIndexHigh || b1.nFileIndexLow != b0.nFileIndexLow) {
        CloseHandle(h);
        CloseHandle(h0);
        return RT_SKIP;
    }
    CloseHandle(h0);
    fh->h    = h;
    fh->size = ((uint64_t)b1.nFileSizeHigh << 32) | b1.nFileSizeLow;
    fh->vol  = b1.dwVolumeSerialNumber;
    fh->idhi = b1.nFileIndexHigh;
    fh->idlo = b1.nFileIndexLow;
    {   /* v3 NEW: change stamp for the verdict cache: write time AND change time (ChangeTime cannot be set by user code) */
        FILE_BASIC_INFO bi;
        ULONGLONG w = ((ULONGLONG)b1.ftLastWriteTime.dwHighDateTime << 32) | b1.ftLastWriteTime.dwLowDateTime, c = 0;
        if (GetFileInformationByHandleEx(h, FileBasicInfo, &bi, sizeof bi)) c = (ULONGLONG)bi.ChangeTime.QuadPart;
        fh->mtime = w * 1099511628211ull ^ c;
    }
    return RT_OK;
}

long plat_read(rt_fh *fh, void *buf, size_t n)
{
    DWORD got = 0;
    if (n > 0x100000) n = 0x100000;
    if (!ReadFile(fh->h, buf, (DWORD)n, &got, NULL)) return -1;
    return (long)got;
}

int plat_rewind(rt_fh *fh) /* v3 NEW */
{
    LARGE_INTEGER z;
    z.QuadPart = 0;
    return SetFilePointerEx(fh->h, z, NULL, FILE_BEGIN) ? 0 : -1;
}

/* v3 NEW: periodic sweep (unix seconds -> FILETIME ticks) */
void plat_sweep(long long since)
{
    int i;
    ULONGLONG ft = ((ULONGLONG)(since < 0 ? 0 : since) + 11644473600ull) * 10000000ull;
    for (i = 0; i < g_cfg.npaths && !RT_STOPPING(); i++) walk_dir(g_cfg.paths[i], WALK_RECENT, ft, 0);
}

/* v3 NEW: canary file (same name/content idea as the Linux back-end). */
int plat_create_canary(const char *dir, char *path_out, size_t outsz)
{
    static const char name[] = "AAAA_clamrt_canary_do_not_edit.docx";
    char text[4096];
    size_t n = 0;
    wchar_t *w;
    HANDLE h;
    DWORD wr = 0;
    if (snprintf(path_out, outsz, "%s%s%s", dir, (dir[0] && dir[strlen(dir) - 1] == '\\') ? "" : "\\", name) >= (int)outsz) return -1;
    w = u8_to_w(path_out, 1);
    if (!w) return -1;
    h = CreateFileW(w, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_FILE_EXISTS) { /* from an earlier run: accept a plain, non-empty file */
            WIN32_FILE_ATTRIBUTE_DATA ad;
            int ok = GetFileAttributesExW(w, GetFileExInfoStandard, &ad) && !(ad.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) && ad.nFileSizeLow > 0;
            free(w);
            return ok ? 0 : -1;
        }
        free(w);
        return -1;
    }
    free(w);
    while (n + 64 < sizeof text) n += (size_t)snprintf(text + n, sizeof text - n, "clamrt canary file - low entropy by design %ld\r\n", (long)(n / 50));
    if (!WriteFile(h, text, (DWORD)n, &wr, NULL) || wr != n) { CloseHandle(h); return -1; }
    CloseHandle(h);
    return 0;
}

void plat_close(rt_fh *fh)
{
    if (fh->h && fh->h != INVALID_HANDLE_VALUE) CloseHandle(fh->h);
    fh->h = INVALID_HANDLE_VALUE;
}

int plat_still_same(const rt_fh *fh, const char *path)
{
    BY_HANDLE_FILE_INFORMATION bi;
    int same;
    HANDLE h = open_win(path, FILE_READ_ATTRIBUTES, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    same = GetFileInformationByHandle(h, &bi) && !(bi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
           !reparse_is_unsafe(h, bi.dwFileAttributes) && bi.dwVolumeSerialNumber == fh->vol &&
           bi.nFileIndexHigh == fh->idhi && bi.nFileIndexLow == fh->idlo;
    CloseHandle(h);
    return same;
}

/* ---------------------------------------------------------------- quarantine / remove */
int plat_quarantine(const rt_fh *fh, const char *path, const char *qdir, const char *sig, char *out, size_t outsz)
{
    char safe[104];
    char *info = NULL;
    const char *base = strrchr(path, '\\');
    size_t i = 0;
    uint32_t h = 2166136261u;
    const char *c;
    wchar_t *wsrc, *wdst;
    BOOL moved = FALSE;
    int seq;

    base = base ? base + 1 : path;
    for (; *base && i < sizeof safe - 1; base++, i++) {
        unsigned char ch = (unsigned char)*base;
        safe[i] = ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '.' || ch == '-' || ch == '_')
                      ? (char)ch : '_';
    }
    safe[i] = '\0';
    for (c = path; *c; c++) { h ^= (unsigned char)*c; h *= 16777619u; }

    if (!plat_still_same(fh, path)) return -1; /* v2 NEW: re-verify immediately before the move */
    wsrc = u8_to_w(path, 1);
    if (!wsrc) return -1;

    /* v2 FIX: a name collision (same path detected twice within one second) left the infected file in place;
     * now a sequence number is tried.  No REPLACE_EXISTING: never clobber an earlier quarantined file. */
    for (seq = 0; seq < 100 && !moved; seq++) {
        int n;
        if (seq == 0) n = snprintf(out, outsz, "%s\\%lld_%08x_%s", qdir, (long long)time(NULL), h, safe);
        else n = snprintf(out, outsz, "%s\\%lld_%08x_%d_%s", qdir, (long long)time(NULL), h, seq, safe);
        if (n < 0 || (size_t)n >= outsz) break;
        wdst = u8_to_w(out, 1);
        if (!wdst) break;
        moved = MoveFileExW(wsrc, wdst, MOVEFILE_COPY_ALLOWED);
        free(wdst);
        if (!moved && GetLastError() != ERROR_ALREADY_EXISTS && GetLastError() != ERROR_FILE_EXISTS) break;
    }
    free(wsrc);

    if (moved) {
        /* sidecar with the original location and signature, for restore/audit */
        info = malloc(strlen(out) + 6);
        if (info) {
            wchar_t *winfo;
            sprintf(info, "%s.info", out);
            winfo = u8_to_w(info, 1);
            if (winfo) {
                HANDLE fi = CreateFileW(winfo, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
                if (fi != INVALID_HANDLE_VALUE) {
                    char body[4600], safep[4200];
                    size_t k;
                    DWORD wr;
                    int bn;
                    /* v2 FIX: strip control characters (CR/LF injection of fake key=value lines) */
                    for (k = 0; path[k] && k < sizeof safep - 1; k++) safep[k] = ((unsigned char)path[k] < 0x20 || path[k] == 0x7f) ? '?' : path[k];
                    safep[k] = '\0';
                    bn = snprintf(body, sizeof body, "original=%s\r\nsignature=%s\r\ntime=%lld\r\nclamrt=" CLAMRT_VERSION "\r\n",
                                  safep, sig, (long long)time(NULL));
                    if (bn > 0 && (size_t)bn < sizeof body) WriteFile(fi, body, (DWORD)bn, &wr, NULL);
                    CloseHandle(fi);
                }
                free(winfo);
            }
            free(info);
        }
    }
    return moved ? 0 : -1;
}

int plat_remove(const rt_fh *fh, const char *path)
{
    wchar_t *w;
    BOOL ok;
    if (!plat_still_same(fh, path)) return -1; /* v2 NEW: identity re-check right before the delete */
    w = u8_to_w(path, 1);
    if (!w) return -1;
    SetFileAttributesW(w, FILE_ATTRIBUTE_NORMAL); /* clear read-only so DeleteFile can succeed */
    ok = DeleteFileW(w);
    free(w);
    return ok ? 0 : -1;
}
