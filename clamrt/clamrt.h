/*
 * clamrt.h -- clamrt v4: real-time (on-write) scanner front-end for clamd.
 *
 * Shared declarations between the portable core (clamrt_core.c) and the
 * platform back-ends (clamrt_linux.c: inotify, clamrt_fan.c: fanotify, clamrt_win.c: ReadDirectoryChangesW)
 * plus the v3+ portable modules: clamrt_obs.c (sinks, /metrics, TUI), clamrt_trip.c (ransomware tripwire),
 * clamrt_intel.c (hash-only threat intel), clamrt_sha256.c.
 *
 * VERSIONING: CLAMRT_VERSION is the single source of truth for the in-file
 * version.  Bump it together with the deliverable names
 * (clamrt_vN.patch, clamrt_guide_vN.md, clamrt_vN_*.exe).
 *
 * Markers: v2/v3/v4 FIX / NEW = changes made in that version (v4 = this release; see clamrt_guide_v4.md).
 */
#ifndef CLAMRT_H
#define CLAMRT_H

#define CLAMRT_VERSION "4"
#define CLAMRT_BANNER "clamrt v" CLAMRT_VERSION " (real-time scan front-end for clamd)"

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET rt_sock;
#define RT_BADSOCK INVALID_SOCKET
typedef struct {
    HANDLE h;
    uint64_t size;
    DWORD vol, idhi, idlo; /* file identity for the "still the same file?" check */
    uint64_t mtime;        /* v3 NEW: FILETIME of last write (verdict cache key) */
} rt_fh;
/* v2 FIX: WaitForMultipleObjects accepts at most 64 handles; one is the stop event. */
#define RT_MAX_ROOTS 63
#else
#include <sys/types.h>
typedef int rt_sock;
#define RT_BADSOCK (-1)
typedef struct {
    int fd;
    uint64_t size;
    dev_t dev;
    ino_t ino;
    uint64_t mtime;        /* v3 NEW: st_mtim in ns (verdict cache key) */
} rt_fh;
#define RT_MAX_ROOTS 64
#endif

#define RT_MAX_LIST 64

/* log levels */
enum { RT_LOG_ERR = 0, RT_LOG_WARN = 1, RT_LOG_INFO = 2, RT_LOG_DEBUG = 3 };

/* plat_open() results */
enum {
    RT_OK     = 0,
    RT_SKIP   = 1,  /* vanished / directory / symlink / not a regular file: ignore silently   */
    RT_DENIED = 2,  /* permission problem: log, do not retry                                  */
    RT_ERR    = -1  /* transient (sharing violation, EMFILE ...): retry with backoff          */
};

typedef enum { ACT_REPORT = 0, ACT_QUARANTINE, ACT_REMOVE } rt_action;

typedef struct {
    const char *paths[RT_MAX_LIST];    /* absolute, normalised watch roots */
    int npaths;
    const char *excludes[RT_MAX_LIST]; /* substring excludes */
    int nexcludes;
    const char *sock_path;             /* unix socket (Linux only) */
    const char *host;                  /* TCP host (default 127.0.0.1) */
    const char *port;                  /* TCP port (default 3310) */
    rt_action action;
    const char *qdir;                  /* absolute quarantine dir */
    uint64_t max_size;                 /* bytes; larger files are skipped */
    unsigned debounce_ms;              /* quiet period before a file is scanned */
    int recursive;
    int scan_existing;                 /* scan files already present at start-up */
    int verbose;
    /* ---- v3 NEW ---- */
    int workers;                       /* scan worker threads (default 2)                          */
    int log_json;                      /* --log-format json                                          */
    int log_syslog, log_journald, log_eventlog; /* extra log sinks                                  */
    const char *metrics_host;          /* --metrics HOST:PORT (NULL = off)                          */
    const char *metrics_port;
    int mode;                          /* RT_MODE_*                                                  */
    int block_exec;                    /* fanotify: deny execution of infected files                 */
    unsigned exec_timeout_ms;          /* verdict deadline for blocked executions (default 4000)    */
    int exec_fail_closed;              /* on timeout / clamd failure: deny (1) or allow (0, default) */
    unsigned sweep_s;                  /* periodic safety-net sweep (0 = off)                        */
    unsigned verdict_ttl_s;            /* clean-verdict cache lifetime (default 600)                 */
    int intel;                         /* RT_INTEL_*                                                 */
    const char *intel_url;             /* override API base URL (testing / mirrors)                  */
    const char *intel_key_env;         /* name of the env var holding the API key                    */
    const char *curl_path;             /* default "curl"                                             */
    int tripwire;                      /* enable ransomware tripwire                                 */
    int trip_canary;                   /* create canary files in each root                           */
    int trip_action;                   /* RT_TRIP_ALERT / SUSPEND / KILL                             */
    unsigned trip_rate, trip_window_s; /* N high-entropy writes by one pid within T seconds          */
    const char *trip_ignore_comm[RT_MAX_LIST]; int ntrip_ignore;
    /* ---- v4 NEW ---- */
    const char *trip_ignore_exe[RT_MAX_LIST]; int ntrip_ignore_exe; /* absolute executable paths: not spoofable like comm */
} rt_config;

enum { RT_MODE_AUTO = 0, RT_MODE_INOTIFY, RT_MODE_FANOTIFY, RT_MODE_ETW, RT_MODE_MINIFILTER };
enum { RT_INTEL_NONE = 0, RT_INTEL_MB, RT_INTEL_VT };
enum { RT_TRIP_ALERT = 0, RT_TRIP_SUSPEND, RT_TRIP_KILL };

/* v3 NEW: statistics are updated from several threads and read by the /metrics thread -> relaxed atomics. */
typedef struct {
    uint64_t scanned, infected, clean, errors, skipped, dropped, actions_failed, overflows;
    uint64_t exec_checked, exec_denied, exec_cache_hits, verdict_cache_hits;
    uint64_t tripwire_alerts, tripwire_actions, canary_hits;
    uint64_t intel_queries, intel_hits, intel_errors;
    uint64_t scan_ns_total, scan_count_timed;      /* for average latency */
    uint64_t queue_depth;                          /* gauge */
} rt_stats;
extern rt_stats g_st;
#define RT_INC(f) __atomic_add_fetch(&g_st.f, 1, __ATOMIC_RELAXED)
#define RT_ADD(f, n) __atomic_add_fetch(&g_st.f, (n), __ATOMIC_RELAXED)
#define RT_GET(f) __atomic_load_n(&g_st.f, __ATOMIC_RELAXED)

/* v2 FIX: sig_atomic_t is the only type the C standard guarantees safe to set from a signal handler. */
extern volatile sig_atomic_t g_stop; /* set by signal / console handler */
extern rt_config g_cfg;

/* v2 FIX: g_stop is written from a signal handler / console-control thread and read by two threads.  Plain volatile
 * loads/stores are not a data race-free handshake (ThreadSanitizer flagged it), so every access goes through
 * relaxed atomics -- which are also async-signal-safe for lock-free integer types. */
#define RT_STOPPING() __atomic_load_n(&g_stop, __ATOMIC_RELAXED)
#define RT_REQUEST_STOP() __atomic_store_n(&g_stop, 1, __ATOMIC_RELAXED)

/* seconds of history re-scanned after the OS dropped change events (inotify/ReadDirectoryChangesW overflow) */
#define RT_OVERFLOW_RESCAN_WINDOW_S 300

/* ---- provided by the core ---- */
void rt_log(int level, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;
void rt_emit(const char *path_utf8); /* watchers call this for every candidate file */
int rt_excluded(const char *path_utf8);
void rt_note_overflow(void);         /* v2 NEW: back-ends report dropped events (counted + logged) */
/* ---- v3 NEW (core) ---- */
void rt_requeue(const char *path_utf8); /* v4 NEW: queue a path for a normal scan/action WITHOUT the tripwire hooks (used after a blocked exec) */
void rt_emit_pid(const char *path_utf8, long pid); /* like rt_emit, with the originating process when the OS says (fanotify / ETW); 0 = unknown */
/* structured log: key,value,... NULL-terminated.  Text sinks print msg only; JSON / journald get the fields. */
void rt_log_kv(int level, const char *msg, ...);
/* scan an open handle.  deadline_ms = absolute plat_now_ms() deadline (0 = none).  Returns RT_SR_*. */
enum { RT_SR_CLEAN = 0, RT_SR_INFECTED, RT_SR_ERROR, RT_SR_SKIP };
int rt_scan_for_exec(rt_fh *fh, const char *path, uint64_t deadline_ms, char *sig, size_t sigsz);
void rt_detected(const char *path, const char *sig, rt_fh *fh, long pid, const char *how); /* log+metrics+intel for a detection */
/* ---- v3 NEW: observability (clamrt_obs.c) ---- */
int rt_metrics_start(void);
void rt_metrics_stop(void);
void rt_obs_event(const char *kind, const char *line); /* appended to the /events ring */
int rt_tui_main(const char *addr); /* --tui HOST:PORT */
/* ---- v3 NEW: tripwire (clamrt_trip.c) ---- */
int rt_trip_init(void);
void rt_trip_cleanup(void);
void rt_trip_note_write(const char *path, long pid);   /* a file was written: rate+entropy heuristic */
int rt_trip_is_canary(const char *path);
int rt_trip_canary_count(void);
const char *rt_trip_canary_path(int i);
void rt_trip_canary_event(const char *path, long pid, const char *what);
/* ---- v3 NEW: threat intel (clamrt_intel.c) and SHA-256 (clamrt_sha256.c) ---- */
int rt_intel_start(void);
void rt_intel_stop(void);
void rt_intel_submit(const char *path, const char *sig, const char *sha256hex);
typedef struct { uint32_t h[8]; uint64_t len; unsigned char buf[64]; size_t n; } rt_sha256;
void rt_sha256_init(rt_sha256 *c);
void rt_sha256_update(rt_sha256 *c, const void *p, size_t n);
void rt_sha256_hex(rt_sha256 *c, char out[65]);
int rt_hash_handle(rt_fh *fh, char out[65]);  /* rewinds + hashes the open file */

/* ---- provided by the platform back-end ---- */
int plat_init(void);
void plat_cleanup(void);
void plat_args(int *argc, char ***argv);       /* v2 NEW: Windows -> UTF-8 argv (ANSI argv mangles non-ASCII paths); no-op on Linux */
FILE *plat_fopen_log(const char *path);        /* v2 NEW: append, no symlink-follow, 0640 / Unicode-safe */
int plat_take_log_reopen(void);                /* v2 NEW: SIGHUP (logrotate) -> returns 1 once */
int plat_watch_run(void);                      /* blocks until g_stop; returns 0 on clean stop */
uint64_t plat_now_ms(void);                    /* monotonic */
int plat_abspath(const char *in, char *out, size_t outsz);
int plat_prepare_dir(const char *in, char *out, size_t outsz); /* create + verify private + absolute path */
int plat_open(const char *path, rt_fh *fh);
long plat_read(rt_fh *fh, void *buf, size_t n); /* >0 bytes, 0 EOF, <0 error */
void plat_close(rt_fh *fh);
int plat_still_same(const rt_fh *fh, const char *path);
/* v2 FIX: quarantine/remove now take the scanned handle and re-verify identity themselves */
int plat_quarantine(const rt_fh *fh, const char *path, const char *qdir, const char *sig, char *out, size_t outsz);
int plat_remove(const rt_fh *fh, const char *path);
int plat_str_prefix(const char *s, const char *prefix);   /* case-insensitive on Windows */
int plat_str_contains(const char *hay, const char *needle);
/* ---- v3 NEW platform API ---- */
int plat_rewind(rt_fh *fh);
/* pid -> short process description ("comm exe cmdline", sanitised). */
int plat_pid_info(long pid, char *out, size_t outsz);
/* stop (SIGSTOP / NtSuspendProcess) or kill a process; refuses pid<=2, our own pid, kernel threads. */
int plat_suspend_pid(long pid, int kill_it);
int plat_pid_comm(long pid, char *out, size_t outsz);
int plat_pid_exe(long pid, char *out, size_t outsz); /* v4 NEW: absolute path of the process image ("" + -1 if unknown) */
/* run argv[] (no shell), feed stdin_data, capture stdout (<= outsz-1 bytes), timeout in ms. returns exit code or -1. */
int plat_run_capture(const char *const *argv, const char *stdin_data, char *out, size_t outsz, unsigned timeout_ms);
void plat_syslog(int level, const char *msg);          /* syslog(3) / Windows Event Log */
void plat_journald(int level, const char *msg, const char *const *kv); /* native journald datagram (Linux) */
void plat_tui_init(void);                              /* raw mode / VT processing */
void plat_tui_done(void);
int plat_tui_key(unsigned ms);                         /* wait <= ms for a key; returns char or -1 */
int plat_create_canary(const char *dir, char *path_out, size_t outsz); /* v3 NEW: create the canary file in dir */
#ifdef _WIN32
/* Windows only (clamrt_win_ext.c): ETW file-create events give the originating PID of a write (tripwire);
 * the minifilter port client serves execution verdicts to the optional kernel driver (minifilter/). */
int plat_etw_start(void);
void plat_etw_stop(void);
long plat_etw_pid_for(const char *path_utf8);   /* 0 = unknown */
int plat_mf_start(void);
void plat_mf_stop(void);
#endif
/* fanotify (Linux). plat_fan_available() = can we use it (root/CAP_SYS_ADMIN, kernel support). */
int plat_fan_available(void);
int plat_fan_run(void);
/* v3 NEW: periodic sweep: emit regular files whose mtime or ctime >= since (unix seconds); never adds watches */
void plat_sweep(long long since);

#endif /* CLAMRT_H */
