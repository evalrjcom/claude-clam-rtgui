/*
 * clamrt_trip.c -- clamrt v3 NEW (v4 revised): ransomware tripwire (portable core; PID source is the back-end).
 *
 * Two independent signals:
 *   1. CANARY FILES (--canary): a plausible document (AAAA_clamrt_canary_do_not_edit.docx, sorts first) is planted
 *      in every watch root.  Nothing legitimate touches it, so ANY write / delete / rename is a high-confidence alert.
 *      With fanotify the writer's PID is known from the first write().
 *   2. RATE + ENTROPY (--tripwire): the first 16 KiB of each freshly written file is sampled; a file whose Shannon
 *      entropy is >= 7.5 bits/byte is "encrypted-looking".  Files that legitimately have high entropy (zip, jpg, mp4,
 *      git objects ...) are recognised by their header and do not count.  When one process produces --tripwire-rate
 *      DISTINCT such files within --tripwire-window seconds, the tripwire fires: alert, and optionally suspend
 *      (SIGSTOP / NtSuspendProcess) or kill that process.
 *
 * Safety rails: never acts on pid <= 2, on clamrt itself or on kernel threads (plat_suspend_pid); processes named in
 * --tripwire-ignore-comm / running an --tripwire-ignore-exe image are never counted or acted on; alerts per process
 * are rate-limited; entropy sampling is capped at ~200 files/s.  Without a PID (inotify mode) the heuristic still
 * alerts, but cannot suspend anything.
 *
 * v4 FIX / v4 NEW (vs v3):
 *   - SAMPLING MOVED OFF THE WATCHER THREAD.  v3 opened and read each file inside rt_emit_pid(), i.e. on the thread that
 *     answers fanotify permission events (a slow disk / NFS stalled every execve on the mount) and on Windows at the
 *     instant of the change notification, when the writer often still holds the file (sharing violation -> the write
 *     was never counted).  A sampler thread now does the reads, retrying transient open failures.
 *   - DISTINCT FILES ARE COUNTED.  v3 counted events: a process rewriting ONE compressed/encrypted file 50 times (a
 *     database, a VM image, an encrypted container, a re-compressed archive) tripped the alarm.
 *   - FEWER FALSE POSITIVES: any recognised container header (zip/gz/xz/zstd/png/... whatever the extension) and zlib
 *     streams (git loose objects, many caches) are benign.  Ciphertext does not start with a valid header.
 *   - IGNORE BY EXECUTABLE PATH (--tripwire-ignore-exe) in addition to comm.  comm is the 15-character task name that any
 *     process can change with prctl(PR_SET_NAME); v3 also never matched names longer than 15 characters.
 *   - the canary alert limiter is per process (v3: one alert per second globally -> a second process touching the
 *     canary within that second was never acted on).
 */
#define _GNU_SOURCE
#include "clamrt.h"

#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <process.h>
typedef CRITICAL_SECTION trip_mu;
#define TM_INIT(m) InitializeCriticalSection(m)
#define TM_LOCK(m) EnterCriticalSection(m)
#define TM_UNLOCK(m) LeaveCriticalSection(m)
#define TSLEEP(ms) Sleep(ms)
typedef HANDLE trip_thr;
#else
#include <pthread.h>
#include <unistd.h>
typedef pthread_mutex_t trip_mu;
#define TM_INIT(m) pthread_mutex_init(m, NULL)
#define TM_LOCK(m) pthread_mutex_lock(m)
#define TM_UNLOCK(m) pthread_mutex_unlock(m)
#define TSLEEP(ms) usleep((ms) * 1000u)
typedef pthread_t trip_thr;
#endif

#define MAX_CANARY RT_MAX_LIST
#define NSUB 10          /* sub-buckets of the sliding window */
#define MAX_PIDS 256
#define SAMPLE 16384
#define ENTROPY_MIN 7.5
#define SAMPLE_MIN 512   /* below this the entropy estimate is meaningless */
#define SEEN_N 256       /* v4: recent distinct paths remembered per process */
#define QSZ 1024         /* v4: sampler queue */
#define MAX_TRIES 4

static char *g_can[MAX_CANARY];
static int g_ncan;
static trip_mu g_tmu;
static int g_tinit;

typedef struct {
    long pid;
    uint64_t base;       /* start of bucket 0 (ms) */
    unsigned cnt[NSUB];
    uint64_t last_alert; /* ms */
    uint64_t last_seen;
    uint64_t seen[SEEN_N]; /* v4 NEW: hashes of the last SEEN_N distinct paths counted for this process */
    unsigned seen_n;
    int used;
} pidst;
static pidst g_pids[MAX_PIDS];

/* ---------------------------------------------------------------- sampler queue (v4 NEW) */
typedef struct { char *path; long pid; uint64_t due; int tries; } tjob;
static tjob g_tq[QSZ];
static unsigned g_tqh, g_tqn;
static trip_thr g_tth;
static int g_tstarted, g_tstop;

static int tq_push(char *path, long pid, uint64_t due, int tries)
{
    int ok = 0;
    TM_LOCK(&g_tmu);
    if (g_tqn < QSZ) {
        tjob *j = &g_tq[(g_tqh + g_tqn) % QSZ];
        j->path = path; j->pid = pid; j->due = due; j->tries = tries;
        g_tqn++;
        ok = 1;
    }
    TM_UNLOCK(&g_tmu);
    return ok;
}

/* pops the first job that is due; returns 0 when none is ready */
static int tq_pop(tjob *out)
{
    unsigned i;
    uint64_t now = plat_now_ms();
    int ok = 0;
    TM_LOCK(&g_tmu);
    for (i = 0; i < g_tqn; i++) {
        tjob *j = &g_tq[(g_tqh + i) % QSZ];
        if (j->due <= now) {
            *out = *j;
            /* close the gap: move the head job into the hole, then drop the head */
            *j = g_tq[g_tqh % QSZ];
            g_tqh = (g_tqh + 1) % QSZ;
            g_tqn--;
            ok = 1;
            break;
        }
    }
    TM_UNLOCK(&g_tmu);
    return ok;
}

static void *sampler_main(void *arg);
#ifdef _WIN32
static unsigned __stdcall sampler_tramp(void *a) { sampler_main(a); return 0; }
#endif

/* ---------------------------------------------------------------- canaries */
int rt_trip_init(void)
{
    int i;
    TM_INIT(&g_tmu);
    g_tinit = 1;
    if (g_cfg.trip_canary) {
        for (i = 0; i < g_cfg.npaths && g_ncan < MAX_CANARY; i++) {
            char p[4096];
            if (plat_create_canary(g_cfg.paths[i], p, sizeof p) == 0) {
                g_can[g_ncan] = strdup(p);
                if (g_can[g_ncan]) g_ncan++;
            } else {
                rt_log(RT_LOG_WARN, "cannot create canary in %s (read-only or not ours?) -- skipped", g_cfg.paths[i]);
            }
        }
    }
    rt_log(RT_LOG_INFO, "tripwire: %d canary file(s), rate trigger %u distinct files / %u s, action=%s", g_ncan, g_cfg.trip_rate,
           g_cfg.trip_window_s, g_cfg.trip_action == RT_TRIP_ALERT ? "alert" : g_cfg.trip_action == RT_TRIP_SUSPEND ? "suspend" : "kill");
#ifdef _WIN32
    { uintptr_t h = _beginthreadex(NULL, 0, sampler_tramp, NULL, 0, NULL); if (h) { g_tth = (HANDLE)h; g_tstarted = 1; } }
#else
    if (pthread_create(&g_tth, NULL, sampler_main, NULL) == 0) g_tstarted = 1;
#endif
    if (!g_tstarted) rt_log(RT_LOG_WARN, "tripwire: cannot start the sampler thread -- only canary files are active");
    return 0;
}

void rt_trip_cleanup(void)
{
    int i;
    if (g_tstarted) {
        __atomic_store_n(&g_tstop, 1, __ATOMIC_RELAXED);
#ifdef _WIN32
        WaitForSingleObject(g_tth, 5000);
        CloseHandle(g_tth);
#else
        pthread_join(g_tth, NULL);
#endif
        g_tstarted = 0;
    }
    while (g_tqn) { free(g_tq[g_tqh].path); g_tqh = (g_tqh + 1) % QSZ; g_tqn--; }
    for (i = 0; i < g_ncan; i++) free(g_can[i]);
    g_ncan = 0;
}

int rt_trip_canary_count(void) { return g_ncan; }
const char *rt_trip_canary_path(int i) { return (i >= 0 && i < g_ncan) ? g_can[i] : NULL; }

int rt_trip_is_canary(const char *path)
{
    int i;
    for (i = 0; i < g_ncan; i++)
        if (plat_str_prefix(path, g_can[i]) && plat_str_prefix(g_can[i], path)) return 1;
    return 0;
}

/* ---------------------------------------------------------------- helpers */
/* v4 FIX: comm / executable matching.  On Linux comm is truncated to 15 characters by the kernel, so a configured name
 * longer than that (unattended-upgrades) never matched in v3 -- compare the truncated form.  The exe path cannot be
 * changed by the process itself, so --tripwire-ignore-exe is the robust choice. */
static int ignored_proc(long pid)
{
    char comm[64], exe[4096];
    int i;
    if (pid <= 0) return 0;
    if (g_cfg.ntrip_ignore > 0 && plat_pid_comm(pid, comm, sizeof comm) == 0) {
        for (i = 0; i < g_cfg.ntrip_ignore; i++) {
            const char *want = g_cfg.trip_ignore_comm[i];
            if (strcmp(comm, want) == 0) return 1;
#ifndef _WIN32
            if (strlen(comm) == 15 && strlen(want) > 15 && strncmp(comm, want, 15) == 0) return 1;
#endif
        }
    }
    if (g_cfg.ntrip_ignore_exe > 0 && plat_pid_exe(pid, exe, sizeof exe) == 0) {
        size_t n = strlen(exe);
        if (n > 10 && strcmp(exe + n - 10, " (deleted)") == 0) exe[n - 10] = '\0'; /* binary replaced while running (package upgrade) */
        for (i = 0; i < g_cfg.ntrip_ignore_exe; i++)
            if (plat_str_prefix(exe, g_cfg.trip_ignore_exe[i]) && plat_str_prefix(g_cfg.trip_ignore_exe[i], exe)) return 1; /* equality (case-insensitive on Windows) */
    }
    return 0;
}

static void act_on(long pid, const char *why)
{
    char info[512] = "", pidbuf[32];
    snprintf(pidbuf, sizeof pidbuf, "%ld", pid);
    if (pid > 0) plat_pid_info(pid, info, sizeof info);
    if (g_cfg.trip_action == RT_TRIP_ALERT) return;
    if (pid <= 0) {
        rt_log(RT_LOG_WARN, "tripwire: cannot %s -- the originating process is unknown (inotify mode); use --mode fanotify",
               g_cfg.trip_action == RT_TRIP_KILL ? "kill" : "suspend");
        return;
    }
    if (ignored_proc(pid)) { rt_log(RT_LOG_WARN, "tripwire: pid %ld is on the ignore list; not acting", pid); return; }
    if (plat_suspend_pid(pid, g_cfg.trip_action == RT_TRIP_KILL) == 0) {
        RT_INC(tripwire_actions);
        rt_log_kv(RT_LOG_ERR, g_cfg.trip_action == RT_TRIP_KILL ? "tripwire: process KILLED" : "tripwire: process SUSPENDED (SIGSTOP; resume with kill -CONT)",
                  "event", "tripwire_action", "pid", pidbuf, "process", info, "reason", why, NULL);
    } else {
        rt_log(RT_LOG_ERR, "tripwire: could not stop pid %ld (gone, protected or not permitted)", pid);
    }
}

static uint64_t path_hash(const char *p)
{
    uint64_t h = 1469598103934665603ull;
    for (; *p; p++) {
        unsigned char c = (unsigned char)*p;
#ifdef _WIN32
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
#endif
        h = (h ^ c) * 1099511628211ull;
    }
    return h;
}

static pidst *pid_slot(long pid, uint64_t now)
{
    int i, free_i = -1, old_i = 0;
    for (i = 0; i < MAX_PIDS; i++) {
        if (g_pids[i].used && g_pids[i].pid == pid) return &g_pids[i];
        if (!g_pids[i].used && free_i < 0) free_i = i;
        if (g_pids[i].used && g_pids[i].last_seen < g_pids[old_i].last_seen) old_i = i;
    }
    i = free_i >= 0 ? free_i : old_i; /* evict least recently seen */
    memset(&g_pids[i], 0, sizeof g_pids[i]);
    g_pids[i].used = 1;
    g_pids[i].pid = pid;
    g_pids[i].base = now;
    return &g_pids[i];
}

/* ---------------------------------------------------------------- entropy / file-format recognition */
static int ext_is(const char *path, const char *ext)
{
    size_t pl = strlen(path), el = strlen(ext);
    size_t i;
    if (pl < el + 1 || path[pl - el - 1] != '.') return 0;
    for (i = 0; i < el; i++) if (tolower((unsigned char)path[pl - el + i]) != ext[i]) return 0;
    return 1;
}

/* returns 1 = extension is a known high-entropy format; *magic_ok says whether the header matches it */
static int known_compressed(const char *path, const unsigned char *b, size_t n, int *magic_ok)
{
    static const struct { const char *ext; const char *magic; size_t mlen; size_t off; } t[] = {
        {"jpg", "\xff\xd8\xff", 3, 0}, {"jpeg", "\xff\xd8\xff", 3, 0}, {"png", "\x89PNG", 4, 0}, {"gif", "GIF8", 4, 0},
        {"zip", "PK", 2, 0}, {"docx", "PK", 2, 0}, {"xlsx", "PK", 2, 0}, {"pptx", "PK", 2, 0}, {"odt", "PK", 2, 0},
        {"ods", "PK", 2, 0}, {"odp", "PK", 2, 0}, {"epub", "PK", 2, 0}, {"docm", "PK", 2, 0}, {"xlsm", "PK", 2, 0},
        {"jar", "PK", 2, 0}, {"apk", "PK", 2, 0}, {"whl", "PK", 2, 0}, {"gz", "\x1f\x8b", 2, 0}, {"tgz", "\x1f\x8b", 2, 0},
        {"bz2", "BZh", 3, 0}, {"xz", "\xfd" "7zXZ", 5, 0}, {"zst", "\x28\xb5\x2f\xfd", 4, 0}, {"7z", "7z\xbc\xaf", 4, 0},
        {"rar", "Rar!", 4, 0}, {"pdf", "%PDF", 4, 0}, {"mp4", "ftyp", 4, 4}, {"mov", "ftyp", 4, 4}, {"m4a", "ftyp", 4, 4},
        {"heic", "ftyp", 4, 4}, {"avif", "ftyp", 4, 4}, {"webp", "RIFF", 4, 0}, {"ogg", "OggS", 4, 0}, {"flac", "fLaC", 4, 0},
        {"mkv", "\x1a\x45\xdf\xa3", 4, 0}, {"webm", "\x1a\x45\xdf\xa3", 4, 0}, {"deb", "!<arch>", 7, 0}, {"mp3", "ID3", 3, 0}};
    size_t i;
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        if (ext_is(path, t[i].ext)) {
            *magic_ok = n >= t[i].off + t[i].mlen && memcmp(b + t[i].off, t[i].magic, t[i].mlen) == 0;
            if (!*magic_ok && strcmp(t[i].ext, "mp3") == 0) *magic_ok = n > 2 && b[0] == 0xff && (b[1] & 0xe0) == 0xe0; /* raw MPEG frame */
            return 1;
        }
    }
    return 0;
}

/* v4 NEW: header of ANY recognised container/media/executable format, whatever the file is called.  Ciphertext does not
 * start with one (a random 2-byte magic matches with probability ~1/65536 per file). */
static int has_known_magic(const unsigned char *b, size_t n)
{
    static const struct { const char *magic; size_t mlen; size_t off; } m[] = {
        {"\xff\xd8\xff", 3, 0}, {"\x89PNG", 4, 0}, {"GIF8", 4, 0}, {"PK\x03\x04", 4, 0}, {"PK\x05\x06", 4, 0}, {"\x1f\x8b", 2, 0},
        {"BZh", 3, 0}, {"\xfd" "7zXZ", 5, 0}, {"\x28\xb5\x2f\xfd", 4, 0}, {"7z\xbc\xaf", 4, 0}, {"Rar!", 4, 0}, {"%PDF", 4, 0},
        {"ftyp", 4, 4}, {"RIFF", 4, 0}, {"OggS", 4, 0}, {"fLaC", 4, 0}, {"\x1a\x45\xdf\xa3", 4, 0}, {"!<arch>", 7, 0}, {"ID3", 3, 0},
        {"\x04\x22\x4d\x18", 4, 0}, {"\x1f\x9d", 2, 0}, {"\x7f" "ELF", 4, 0}, {"MZ", 2, 0}, {"\xca\xfe\xba\xbe", 4, 0},
        {"wOF2", 4, 0}, {"wOFF", 4, 0}, {"SQLite format 3", 15, 0}, {"\xd0\xcf\x11\xe0", 4, 0}};
    size_t i;
    for (i = 0; i < sizeof m / sizeof m[0]; i++)
        if (n >= m[i].off + m[i].mlen && memcmp(b + m[i].off, m[i].magic, m[i].mlen) == 0) return 1;
    return 0;
}

/* v4 NEW: a valid zlib header (RFC 1950: deflate, window <= 32 KiB, FCHECK divisible by 31).  Git loose objects and many
 * application caches are raw zlib streams without any extension. */
static int zlib_header(const unsigned char *b, size_t n)
{
    return n >= 2 && (b[0] & 0x0f) == 8 && (b[0] >> 4) <= 7 && (((unsigned)b[0] << 8) | b[1]) % 31 == 0;
}

static double entropy_of(const unsigned char *b, size_t n)
{
    unsigned c[256];
    double e = 0;
    size_t i;
    memset(c, 0, sizeof c);
    for (i = 0; i < n; i++) c[b[i]]++;
    for (i = 0; i < 256; i++) if (c[i]) { double p = (double)c[i] / (double)n; e -= p * log2(p); }
    return e;
}

/* ---------------------------------------------------------------- events */
void rt_trip_canary_event(const char *path, long pid, const char *what)
{
    static uint64_t last_ms;
    static long last_pid = -1;
    char pidbuf[32] = "", info[512] = "", msg[4400];
    uint64_t now = plat_now_ms();
    TM_LOCK(&g_tmu);
    /* v4 FIX: limit per process.  v3 allowed one alert per second for ALL processes, so a second process touching the
     * canary in that second was counted but never suspended. */
    if (last_ms && now - last_ms < 1000 && pid == last_pid) { TM_UNLOCK(&g_tmu); RT_INC(canary_hits); return; }
    last_ms = now;
    last_pid = pid;
    TM_UNLOCK(&g_tmu);
    RT_INC(canary_hits);
    RT_INC(tripwire_alerts);
    if (pid > 0) { snprintf(pidbuf, sizeof pidbuf, "%ld", pid); plat_pid_info(pid, info, sizeof info); }
    snprintf(msg, sizeof msg, "TRIPWIRE: canary file %s: %s", what, path);
    rt_obs_event("tripwire", msg);
    rt_log_kv(RT_LOG_ERR, msg, "event", "tripwire_canary", "path", path, "what", what, "pid", pidbuf, "process", info, NULL);
    act_on(pid, "canary file touched");
}

/* Counts one distinct encrypted-looking file for `pid`; fires the tripwire at the threshold. */
static void count_hit(const char *path, long pid, uint64_t now)
{
    pidst *ps;
    unsigned sum = 0, i;
    uint64_t bucket_ms, ph = path_hash(path);

    bucket_ms = (uint64_t)g_cfg.trip_window_s * 1000u / NSUB;
    if (!bucket_ms) bucket_ms = 1;
    TM_LOCK(&g_tmu);
    ps = pid_slot(pid > 0 ? pid : 0, now);
    ps->last_seen = now;
    for (i = 0; i < SEEN_N && i < ps->seen_n; i++) /* v4 NEW: the same file again is not a new victim */
        if (ps->seen[i] == ph) { TM_UNLOCK(&g_tmu); return; }
    ps->seen[ps->seen_n++ % SEEN_N] = ph;
    while (now - ps->base >= bucket_ms) { /* rotate buckets */
        memmove(&ps->cnt[0], &ps->cnt[1], sizeof ps->cnt[0] * (NSUB - 1));
        ps->cnt[NSUB - 1] = 0;
        ps->base += bucket_ms;
        if (now - ps->base > (uint64_t)NSUB * bucket_ms) { memset(ps->cnt, 0, sizeof ps->cnt); ps->base = now; }
    }
    ps->cnt[NSUB - 1]++;
    for (i = 0; i < NSUB; i++) sum += ps->cnt[i];
    if (sum >= g_cfg.trip_rate && (!ps->last_alert || now - ps->last_alert > 30000)) {
        char pidbuf[32] = "", info[512] = "", msg[4400], cntbuf[32];
        ps->last_alert = now;
        memset(ps->cnt, 0, sizeof ps->cnt);
        ps->seen_n = 0; /* a new storm must be able to re-count the same files */
        TM_UNLOCK(&g_tmu);
        RT_INC(tripwire_alerts);
        snprintf(cntbuf, sizeof cntbuf, "%u", sum);
        if (pid > 0) { snprintf(pidbuf, sizeof pidbuf, "%ld", pid); plat_pid_info(pid, info, sizeof info); }
        snprintf(msg, sizeof msg, "TRIPWIRE: %u encrypted-looking file writes within %u s (last: %s)", sum, g_cfg.trip_window_s, path);
        rt_obs_event("tripwire", msg);
        rt_log_kv(RT_LOG_ERR, msg, "event", "tripwire_rate", "path", path, "count", cntbuf, "pid", pidbuf, "process", info, NULL);
        act_on(pid, "high-entropy write storm");
        return;
    }
    TM_UNLOCK(&g_tmu);
}

/* Reads and judges one file.  Returns 1 = transient failure, retry later. */
static int sample_one(const char *path, long pid)
{
    unsigned char buf[SAMPLE];
    rt_fh fh;
    long n, got = 0;
    int magic_ok = 1, kc, r;

    r = plat_open(path, &fh);
    if (r == RT_ERR) return 1;        /* e.g. Windows sharing violation: the writer still holds the file */
    if (r != RT_OK) return 0;
    while (got < SAMPLE && (n = plat_read(&fh, buf + got, (size_t)(SAMPLE - got))) > 0) got += n;
    plat_close(&fh);
    if (got < SAMPLE_MIN) return 0;
    kc = known_compressed(path, buf, (size_t)got, &magic_ok);
    if (kc && magic_ok) return 0;                      /* a genuine jpg/zip/...: high entropy is normal */
    if (has_known_magic(buf, (size_t)got)) return 0;   /* v4: recognised format under any name (renamed archive, media) */
    if (zlib_header(buf, (size_t)got)) return 0;       /* v4: zlib stream (git objects, caches) */
    if (entropy_of(buf, (size_t)got) < ENTROPY_MIN) return 0;
    count_hit(path, pid, plat_now_ms());
    return 0;
}

static void *sampler_main(void *arg)
{
    (void)arg;
    while (!__atomic_load_n(&g_tstop, __ATOMIC_RELAXED) && !RT_STOPPING()) {
        tjob j;
        if (!tq_pop(&j)) { TSLEEP(20); continue; }
        /* ignore-list is decided at enqueue time (rt_trip_note_write): a short-lived writer is gone by now */
        if (sample_one(j.path, j.pid) && j.tries + 1 < MAX_TRIES) {
            if (tq_push(j.path, j.pid, plat_now_ms() + 150, j.tries + 1)) continue; /* ownership moved back to the queue */
        }
        free(j.path);
    }
    return NULL;
}

/* A file was written.  Called from the watcher thread: must be cheap and must never block -- it only enqueues. */
void rt_trip_note_write(const char *path, long pid)
{
    static uint64_t tokens_ms, tokens;
    uint64_t now = plat_now_ms();
    char *dup;

    if (!g_tinit || !g_tstarted) return;
    /* v4 FIX: evaluate the ignore lists NOW (one /proc read), while the writer still exists; judging later in the sampler
     * thread failed for short-lived processes (comm/exe unreadable once they exit) and they were counted. */
    if (ignored_proc(pid)) return;
    /* sampling budget: ~200 files per second */
    TM_LOCK(&g_tmu);
    if (now - tokens_ms >= 1000) { tokens_ms = now; tokens = 200; }
    if (tokens == 0) { TM_UNLOCK(&g_tmu); return; }
    tokens--;
    TM_UNLOCK(&g_tmu);
    dup = strdup(path);
    if (!dup) return;
    if (!tq_push(dup, pid, now, 0)) free(dup); /* queue full: the budget makes this rare; dropping a sample is safe */
}
