/*
 * clamrt_win_ext.c -- clamrt v3 NEW (v4 revised): Windows platform helpers added in v3.
 *   - process info / suspend / kill (tripwire)           - subprocess runner without a shell (threat intel, curl.exe)
 *   - Event Log sink                                     - console dashboard support (VT sequences)
 *   - ETW consumer (Microsoft-Windows-Kernel-File)       - minifilter port client (blocking execution verdicts)
 *
 * NOTE: cross-compiled and compile-checked on Linux (mingw-w64); NOT run on a Windows machine in this build
 * environment.  The ETW session needs Administrator; the minifilter driver (minifilter\clamrt_mf.c) needs the WDK,
 * a test-signing / EV-signed build and is, in addition, untested.
 */
#include "clamrt.h"

#include <conio.h>
#include <evntcons.h>
#include <evntrace.h>
#include <fltuser.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "minifilter/clamrt_mf_proto.h"

/* ------------------------------------------------------------------ UTF-8 <-> wide (local copies) */
static wchar_t *to_w(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w;
    if (n <= 0) return NULL;
    w = malloc((size_t)n * sizeof *w);
    if (w && MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) <= 0) { free(w); return NULL; }
    return w;
}

static int to_u8(const wchar_t *w, int wlen, char *out, size_t outsz)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, out, (int)outsz - 1, NULL, NULL);
    if (n <= 0) { out[0] = '\0'; return -1; }
    out[n] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ process info / control */
static int proc_image(long pid, wchar_t *out, DWORD outchars)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    DWORD n = outchars;
    BOOL ok;
    if (!h) return -1;
    ok = QueryFullProcessImageNameW(h, 0, out, &n);
    CloseHandle(h);
    return ok ? 0 : -1;
}

int plat_pid_comm(long pid, char *out, size_t outsz)
{
    wchar_t img[MAX_PATH * 2];
    const wchar_t *base;
    out[0] = '\0';
    if (proc_image(pid, img, MAX_PATH * 2) != 0) return -1;
    base = wcsrchr(img, L'\\');
    base = base ? base + 1 : img;
    return to_u8(base, -1, out, outsz);
}

/* v4 NEW: full image path of the process (for --tripwire-ignore-exe) */
int plat_pid_exe(long pid, char *out, size_t outsz)
{
    wchar_t img[MAX_PATH * 2];
    out[0] = '\0';
    if (proc_image(pid, img, MAX_PATH * 2) != 0) return -1;
    return to_u8(img, -1, out, outsz);
}

int plat_pid_info(long pid, char *out, size_t outsz)
{
    wchar_t img[MAX_PATH * 2];
    char exe[1024] = "?", comm[128] = "?";
    size_t i;
    if (proc_image(pid, img, MAX_PATH * 2) == 0) to_u8(img, -1, exe, sizeof exe);
    plat_pid_comm(pid, comm, sizeof comm);
    for (i = 0; exe[i]; i++) if ((unsigned char)exe[i] < 0x20) exe[i] = '?';
    snprintf(out, outsz, "%s exe=%s", comm, exe);
    return 0;
}

typedef LONG (NTAPI *NtSuspendProcess_t)(HANDLE);

int plat_suspend_pid(long pid, int kill_it)
{
    /* v4: list extended (registry, lsm, dwm, fontdrvhost, Defender, the shell) -- stopping these hangs or blinds the machine */
    static const char *const protectedp[] = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
                                             "lsass.exe", "lsm.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "explorer.exe",
                                             "msmpeng.exe", "mssense.exe", "wmiprvse.exe", "clamrt.exe", NULL};
    char comm[128];
    HANDLE h;
    int rc = -1, i;
    if (pid <= 4 || (DWORD)pid == GetCurrentProcessId()) return -1;
    if (plat_pid_comm(pid, comm, sizeof comm) == 0)
        for (i = 0; protectedp[i]; i++) if (_stricmp(comm, protectedp[i]) == 0) return -1; /* never touch core OS processes */
    h = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return -1;
    if (kill_it) {
        rc = TerminateProcess(h, 1) ? 0 : -1;
    } else {
        NtSuspendProcess_t f = (NtSuspendProcess_t)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess");
        if (f && f(h) >= 0) rc = 0;
    }
    CloseHandle(h);
    return rc;
}

/* ------------------------------------------------------------------ subprocess without a shell */
static void quote_arg(const char *a, char *o, size_t osz)
{
    /* Microsoft C runtime argv rules: wrap in quotes, double backslashes that precede a quote, escape quotes */
    size_t n = 0, bs = 0;
    o[n++] = '"';
    for (; *a && n + bs + 6 < osz; a++) { /* v4 FIX: bound includes the extra backslashes a quote can add (v3: n + 4 < osz allowed an overflow) */
        if (*a == '\\') { bs++; o[n++] = '\\'; continue; }
        if (*a == '"') { size_t k; for (k = 0; k < bs; k++) o[n++] = '\\'; o[n++] = '\\'; o[n++] = '"'; bs = 0; continue; }
        bs = 0;
        o[n++] = *a;
    }
    { size_t k; for (k = 0; k < bs; k++) o[n++] = '\\'; } /* trailing backslashes precede the closing quote: double them */
    o[n++] = '"';
    o[n] = '\0';
}

int plat_run_capture(const char *const *argv, const char *stdin_data, char *out, size_t outsz, unsigned timeout_ms)
{
    char cmd[4096] = "", q[1200];
    wchar_t *wcmd;
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    HANDLE inr = NULL, inw = NULL, outr = NULL, outw = NULL, nul;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    size_t len = 0;
    DWORD code = (DWORD)-1, deadline, written = 0;
    int i, rc = -1;

    out[0] = '\0';
    for (i = 0; argv[i]; i++) {
        quote_arg(argv[i], q, sizeof q);
        if (strlen(cmd) + strlen(q) + 2 >= sizeof cmd) return -1;
        if (i) strcat(cmd, " ");
        strcat(cmd, q);
    }
    wcmd = to_w(cmd);
    if (!wcmd) return -1;
    if (!CreatePipe(&inr, &inw, &sa, 0) || !CreatePipe(&outr, &outw, &sa, 0)) { free(wcmd); return -1; }
    SetHandleInformation(inw, HANDLE_FLAG_INHERIT, 0);  /* our ends must not be inherited */
    SetHandleInformation(outr, HANDLE_FLAG_INHERIT, 0);
    nul = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = inr; si.hStdOutput = outw; si.hStdError = nul;
    memset(&pi, 0, sizeof pi);
    if (!CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        free(wcmd); CloseHandle(inr); CloseHandle(inw); CloseHandle(outr); CloseHandle(outw);
        if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
        return -1;
    }
    free(wcmd);
    CloseHandle(inr); CloseHandle(outw);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    if (stdin_data && *stdin_data) WriteFile(inw, stdin_data, (DWORD)strlen(stdin_data), &written, NULL); /* config is < 4 KiB: fits the pipe buffer */
    CloseHandle(inw);
    deadline = GetTickCount() + timeout_ms;
    for (;;) {
        DWORD avail = 0, got = 0;
        if (PeekNamedPipe(outr, NULL, 0, NULL, &avail, NULL) && avail) {
            if (ReadFile(outr, out + len, (DWORD)(outsz - 1 - len < avail ? outsz - 1 - len : avail), &got, NULL)) len += got;
            if (len >= outsz - 1) { TerminateProcess(pi.hProcess, 1); break; }
            continue;
        }
        if (WaitForSingleObject(pi.hProcess, 100) == WAIT_OBJECT_0) {
            while (PeekNamedPipe(outr, NULL, 0, NULL, &avail, NULL) && avail && len < outsz - 1) { /* drain */
                if (!ReadFile(outr, out + len, (DWORD)(outsz - 1 - len < avail ? outsz - 1 - len : avail), &got, NULL)) break;
                len += got;
            }
            break;
        }
        if ((LONG)(GetTickCount() - deadline) >= 0 || RT_STOPPING()) { TerminateProcess(pi.hProcess, 1); break; }
    }
    out[len] = '\0';
    WaitForSingleObject(pi.hProcess, 2000);
    if (GetExitCodeProcess(pi.hProcess, &code)) rc = (int)code;
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(outr);
    return rc;
}

/* ------------------------------------------------------------------ Event Log sink */
void plat_syslog(int level, const char *msg)
{
    static HANDLE src;
    static int tried;
    wchar_t *w;
    const wchar_t *strs[1];
    WORD type = level == RT_LOG_ERR ? EVENTLOG_ERROR_TYPE : level == RT_LOG_WARN ? EVENTLOG_WARNING_TYPE : EVENTLOG_INFORMATION_TYPE;
    if (!tried) {
        HKEY k;
        tried = 1;
        /* Register the source so Event Viewer renders the text (EventCreate.exe supplies a generic %1 message).
         * Needs Administrator; harmless otherwise: events are still written, the viewer just shows a generic header. */
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\clamrt", 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) == ERROR_SUCCESS) {
            static const wchar_t mf[] = L"%SystemRoot%\\System32\\EventCreate.exe";
            DWORD types = 7;
            RegSetValueExW(k, L"EventMessageFile", 0, REG_EXPAND_SZ, (const BYTE *)mf, sizeof mf);
            RegSetValueExW(k, L"TypesSupported", 0, REG_DWORD, (const BYTE *)&types, sizeof types);
            RegCloseKey(k);
        }
        src = RegisterEventSourceW(NULL, L"clamrt");
    }
    if (!src) return;
    w = to_w(msg);
    if (!w) return;
    strs[0] = w;
    ReportEventW(src, type, 0, 1, NULL, 1, 0, strs, NULL);
    free(w);
}

void plat_journald(int level, const char *msg, const char *const *kv) { (void)level; (void)msg; (void)kv; } /* Linux only */

/* ------------------------------------------------------------------ console dashboard */
static DWORD g_old_out_mode;
static HANDLE g_hout;

void plat_tui_init(void)
{
    DWORD m = 0;
    g_hout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleMode(g_hout, &m)) {
        g_old_out_mode = m;
        SetConsoleMode(g_hout, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING); /* ANSI escapes (Windows 10+) */
    }
    SetConsoleOutputCP(CP_UTF8);
    fputs("\033[?1049h\033[?25l", stdout);
    fflush(stdout);
}

void plat_tui_done(void)
{
    fputs("\033[?25h\033[?1049l", stdout);
    fflush(stdout);
    if (g_hout) SetConsoleMode(g_hout, g_old_out_mode);
}

int plat_tui_key(unsigned ms)
{
    DWORD end = GetTickCount() + ms;
    do {
        if (_kbhit()) return _getch();
        Sleep(50);
    } while ((LONG)(GetTickCount() - end) < 0);
    return -1;
}

/* ================================================================== ETW: who wrote that file?
 * A real-time ETW session on Microsoft-Windows-Kernel-File (keyword KERNEL_FILE_KEYWORD_CREATE = 0x80) delivers an
 * event for every file open with the ProcessId of the opener.  The callback keeps, per watched path, the most recent
 * opener; the ReadDirectoryChangesW watcher asks plat_etw_pid_for(path) when it emits a change.  This is a heuristic
 * attribution (the last process that opened the file within 10 s), good enough to point the tripwire at the process
 * hammering a directory.  Needs Administrator (or membership of "Performance Log Users").
 * Event 12 payload (manifest v0): IrpPtr, FileObject (pointer size), IssuingThreadId, CreateOptions, CreateAttributes,
 * ShareAccess (4 bytes each), FileName (NUL-terminated UTF-16). */
static const GUID KFILE_GUID = {0xEDD08927, 0x9CC4, 0x4E65, {0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}};
static const wchar_t ETW_SESSION[] = L"clamrt-etw";

#define PC_SLOTS 8192
typedef struct { uint64_t key; DWORD pid; ULONGLONG tick; } pcslot;
static pcslot g_pc[PC_SLOTS];
static CRITICAL_SECTION g_pcmu;
static int g_etw_on;
static TRACEHANDLE g_session, g_consumer = INVALID_PROCESSTRACE_HANDLE;
static HANDLE g_etw_thread;
static wchar_t g_devname[26][64];
static wchar_t g_devroot[26][8]; /* "C:" */
static int g_ndev;

static uint64_t path_key_w(const wchar_t *p, size_t n)
{
    uint64_t h = 1469598103934665603ull;
    size_t i;
    for (i = 0; i < n; i++) {
        wchar_t c = p[i];
        if (c >= L'A' && c <= L'Z') c = (wchar_t)(c + 32);
        if (c == L'/') c = L'\\';
        h = (h ^ (uint64_t)c) * 1099511628211ull;
    }
    return h;
}

static void load_devmap(void)
{
    wchar_t drive[3] = L"A:", buf[256];
    int i;
    g_ndev = 0;
    for (i = 0; i < 26; i++) {
        drive[0] = (wchar_t)(L'A' + i);
        if (QueryDosDeviceW(drive, buf, 256) && wcsncmp(buf, L"\\Device\\", 8) == 0 && g_ndev < 26) {
            wcsncpy(g_devname[g_ndev], buf, 63);
            wcscpy(g_devroot[g_ndev], drive);
            g_ndev++;
        }
    }
}

/* NT path -> "C:\rest" (writes into out, returns length or 0) */
static size_t nt_to_dos(const wchar_t *nt, size_t ntlen, wchar_t *out, size_t outsz)
{
    int i;
    for (i = 0; i < g_ndev; i++) {
        size_t dl = wcslen(g_devname[i]);
        if (ntlen > dl && _wcsnicmp(nt, g_devname[i], dl) == 0 && nt[dl] == L'\\' && ntlen - dl + 2 < outsz) {
            out[0] = g_devroot[i][0]; out[1] = L':';
            memcpy(out + 2, nt + dl, (ntlen - dl) * sizeof(wchar_t));
            return ntlen - dl + 2;
        }
    }
    return 0;
}

static VOID WINAPI on_etw_event(PEVENT_RECORD er)
{
    const BYTE *ud;
    size_t off, ptr, avail, nch, dl;
    const wchar_t *fn;
    wchar_t dos[1024];
    uint64_t k;
    char u8[2048];
    int i, under = 0;

    if (er->EventHeader.EventDescriptor.Id != 12 || !IsEqualGUID(&er->EventHeader.ProviderId, &KFILE_GUID)) return;
    ud = (const BYTE *)er->UserData;
    ptr = (er->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
    off = 2 * ptr + 4 * 4;
    if (!ud || er->UserDataLength <= off + 2) return;
    fn = (const wchar_t *)(ud + off);
    avail = (er->UserDataLength - off) / sizeof(wchar_t);
    for (nch = 0; nch < avail && fn[nch]; nch++) {}
    if (nch == 0 || nch >= avail) return; /* not NUL terminated inside the record: ignore */
    dl = nt_to_dos(fn, nch, dos, 1024);
    if (!dl) return;
    if (to_u8(dos, (int)dl, u8, sizeof u8) != 0) return;
    for (i = 0; i < g_cfg.npaths; i++) if (plat_str_prefix(u8, g_cfg.paths[i])) { under = 1; break; }
    if (!under || er->EventHeader.ProcessId == GetCurrentProcessId()) return;
    k = path_key_w(dos, dl);
    EnterCriticalSection(&g_pcmu);
    {   /* v4 FIX: FIRST opener wins for 3 s.  v3 let the LAST opener overwrite, so the indexer / antivirus that opens a file
         * right after the real writer was blamed (and, with --tripwire-action suspend, stopped). */
        pcslot *sl = &g_pc[k % PC_SLOTS];
        ULONGLONG nowt = GetTickCount64();
        if (!(sl->key == k && nowt - sl->tick < 3000)) {
            sl->key = k;
            sl->pid = er->EventHeader.ProcessId;
            sl->tick = nowt;
        }
    }
    LeaveCriticalSection(&g_pcmu);
}

long plat_etw_pid_for(const char *path)
{
    wchar_t *w;
    uint64_t k;
    long pid = 0;
    size_t n;
    if (!g_etw_on) return 0;
    w = to_w(path);
    if (!w) return 0;
    n = wcslen(w);
    if (n > 4 && wcsncmp(w, L"\\\\?\\", 4) == 0) { memmove(w, w + 4, (n - 3) * sizeof(wchar_t)); n -= 4; }
    k = path_key_w(w, n);
    free(w);
    EnterCriticalSection(&g_pcmu);
    if (g_pc[k % PC_SLOTS].key == k && GetTickCount64() - g_pc[k % PC_SLOTS].tick < 10000) pid = (long)g_pc[k % PC_SLOTS].pid;
    LeaveCriticalSection(&g_pcmu);
    return pid;
}

static unsigned __stdcall etw_thread(void *arg)
{
    (void)arg;
    ProcessTrace(&g_consumer, 1, NULL, NULL); /* blocks until the session is stopped */
    return 0;
}

int plat_etw_start(void)
{
    size_t sz = sizeof(EVENT_TRACE_PROPERTIES) + sizeof ETW_SESSION + 16;
    EVENT_TRACE_PROPERTIES *p = calloc(1, sz);
    EVENT_TRACE_LOGFILEW lf;
    ULONG st;
    uintptr_t th;
    if (!p) return -1;
    InitializeCriticalSection(&g_pcmu);
    load_devmap();
    p->Wnode.BufferSize = (ULONG)sz;
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1;
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p->BufferSize = 64;
    p->MinimumBuffers = 4;
    p->MaximumBuffers = 32;
    p->FlushTimer = 1;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    st = StartTraceW(&g_session, ETW_SESSION, p);
    if (st == ERROR_ALREADY_EXISTS) { /* stale session from a crashed run */
        ControlTraceW(0, ETW_SESSION, p, EVENT_TRACE_CONTROL_STOP);
        memset(p, 0, sz);
        p->Wnode.BufferSize = (ULONG)sz; p->Wnode.Flags = WNODE_FLAG_TRACED_GUID; p->Wnode.ClientContext = 1;
        p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE; p->BufferSize = 64; p->MinimumBuffers = 4; p->MaximumBuffers = 32;
        p->FlushTimer = 1; p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        st = StartTraceW(&g_session, ETW_SESSION, p);
    }
    free(p);
    if (st != ERROR_SUCCESS) return -1;
    st = EnableTraceEx2(g_session, &KFILE_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0x80, 0, 0, NULL);
    if (st != ERROR_SUCCESS) { plat_etw_stop(); return -1; }
    memset(&lf, 0, sizeof lf);
    lf.LoggerName = (LPWSTR)ETW_SESSION;
    lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = on_etw_event;
    g_consumer = OpenTraceW(&lf);
    if (g_consumer == INVALID_PROCESSTRACE_HANDLE) { plat_etw_stop(); return -1; }
    th = _beginthreadex(NULL, 0, etw_thread, NULL, 0, NULL);
    if (!th) { plat_etw_stop(); return -1; }
    g_etw_thread = (HANDLE)th;
    g_etw_on = 1;
    rt_log(RT_LOG_INFO, "ETW: Microsoft-Windows-Kernel-File session started (process attribution for the tripwire)");
    return 0;
}

void plat_etw_stop(void)
{
    if (g_session) {
        size_t sz = sizeof(EVENT_TRACE_PROPERTIES) + sizeof ETW_SESSION + 16;
        EVENT_TRACE_PROPERTIES *p = calloc(1, sz);
        if (p) {
            p->Wnode.BufferSize = (ULONG)sz;
            p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            ControlTraceW(g_session, NULL, p, EVENT_TRACE_CONTROL_STOP); /* unblocks ProcessTrace */
            free(p);
        }
        g_session = 0;
    }
    if (g_etw_thread) { WaitForSingleObject(g_etw_thread, 5000); CloseHandle(g_etw_thread); g_etw_thread = NULL; }
    if (g_consumer != INVALID_PROCESSTRACE_HANDLE) { CloseTrace(g_consumer); g_consumer = INVALID_PROCESSTRACE_HANDLE; }
    g_etw_on = 0;
}

/* ================================================================== minifilter port client
 * Serves "process N is about to execute this file" messages from clamrt_mf.sys: scan with a deadline, reply allow/deny.
 * One thread per worker, each blocked in FilterGetMessage (overlapped, so shutdown is prompt). */
static HANDLE g_port;
static HANDLE g_mf_thr[8];
static int g_mf_n;

static unsigned __stdcall mf_thread(void *arg)
{
    OVERLAPPED ov;
    struct { FILTER_MESSAGE_HEADER h; CLAMRT_MF_REQUEST r; } msg;
    (void)arg;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    while (!RT_STOPPING()) {
        HRESULT hr;
        DWORD got = 0;
        struct { FILTER_REPLY_HEADER h; CLAMRT_MF_REPLY r; } rep;
        char path[2048], sig[1024];
        wchar_t dos[1024];
        size_t dl;
        int verdict = g_cfg.exec_fail_closed ? 1 : 0;
        rt_fh fh;

        ResetEvent(ov.hEvent);
        memset(&msg, 0, sizeof msg);
        hr = FilterGetMessage(g_port, &msg.h, sizeof msg, &ov);
        if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
            while (WaitForSingleObject(ov.hEvent, 500) == WAIT_TIMEOUT)
                if (RT_STOPPING()) { CancelIoEx(g_port, &ov); goto out; }
            if (!GetOverlappedResult(g_port, &ov, &got, FALSE)) break;
        } else if (FAILED(hr)) {
            break;
        }
        if (msg.r.PathChars == 0 || msg.r.PathChars >= CLAMRT_MF_MAX_CHARS) verdict = 0;
        else {
            dl = nt_to_dos((const wchar_t *)msg.r.Path, msg.r.PathChars, dos, 1024);
            if (dl && to_u8(dos, (int)dl, path, sizeof path) == 0 && !rt_excluded(path)) {
                int under = 0, i;
                for (i = 0; i < g_cfg.npaths; i++) if (plat_str_prefix(path, g_cfg.paths[i])) under = 1;
                if (!under) verdict = 0;
                else if (plat_open(path, &fh) == RT_OK) {
                    int r;
                    RT_INC(exec_checked);
                    r = rt_scan_for_exec(&fh, path, plat_now_ms() + g_cfg.exec_timeout_ms, sig, sizeof sig);
                    if (r == RT_SR_INFECTED) {
                        verdict = 1;
                        RT_INC(exec_denied);
                        rt_detected(path, sig, &fh, (long)msg.r.Pid, "exec-block");
                    } else if (r != RT_SR_ERROR) verdict = 0;
                    plat_close(&fh);
                }
            } else verdict = 0;
        }
        memset(&rep, 0, sizeof rep);
        rep.h.MessageId = msg.h.MessageId;
        rep.h.Status = 0;
        rep.r.Verdict = (ULONG)verdict;
        FilterReplyMessage(g_port, &rep.h, sizeof rep);
    }
out:
    CloseHandle(ov.hEvent);
    return 0;
}

int plat_mf_start(void)
{
    CLAMRT_MF_CONNECT ctx;
    HRESULT hr;
    int i;
    ctx.Version = CLAMRT_MF_PROTO_VERSION;
    ctx.ClientPid = GetCurrentProcessId();
    ctx.TimeoutMs = g_cfg.exec_timeout_ms;
    ctx.FailClosed = (ULONG)g_cfg.exec_fail_closed;
    hr = FilterConnectCommunicationPort(CLAMRT_MF_PORT_NAME, 0, &ctx, sizeof ctx, NULL, &g_port);
    if (FAILED(hr)) return -1;
    for (i = 0; i < g_cfg.workers + 1 && i < 8; i++) {
        uintptr_t t = _beginthreadex(NULL, 0, mf_thread, NULL, 0, NULL);
        if (t) g_mf_thr[g_mf_n++] = (HANDLE)t;
    }
    if (!g_mf_n) { CloseHandle(g_port); g_port = NULL; return -1; }
    rt_log(RT_LOG_INFO, "minifilter: connected, BLOCKING executions of infected files (timeout %u ms, fail-%s)",
           g_cfg.exec_timeout_ms, g_cfg.exec_fail_closed ? "closed" : "open");
    return 0;
}

void plat_mf_stop(void)
{
    int i;
    for (i = 0; i < g_mf_n; i++) { WaitForSingleObject(g_mf_thr[i], 3000); CloseHandle(g_mf_thr[i]); }
    g_mf_n = 0;
    if (g_port) { CloseHandle(g_port); g_port = NULL; }
}
