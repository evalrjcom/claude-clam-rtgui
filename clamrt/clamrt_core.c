/*
 * clamrt_core.c -- clamrt v4 portable core.
 *
 *   watcher (platform) --rt_emit()--> debounce queue --> worker thread
 *        --> clamd INSTREAM scan --> report / quarantine / remove
 *
 * Design notes (see clamrt_guide_v4.md):
 *  - Debounce queue: hash set (O(1) dedupe) + doubly linked list kept sorted by
 *    due-time, so the worker only ever looks at the head.  A file that is still
 *    being written keeps being pushed back (bounded by MAX_WAIT_MS).
 *  - Scanning streams the already-opened, non-followed file handle to clamd
 *    (INSTREAM) so clamd needs no filesystem access to the watched tree.
 *  - Before acting on a detection the path is re-checked against the scanned
 *    handle's identity (dev/inode, volume/file-index) to defeat swap races.
 *  - All network I/O has connect/send/recv timeouts; failures retry with
 *    exponential backoff, the queue is bounded, nothing blocks the watcher.
 *
 * v2 FIX / v2 NEW: changes in v2 (vs v1).   v3 NEW / v3 FIX: changes in v3 (vs v2):
 *   - worker pool (--workers), thread-safe atomic statistics, structured logging (JSON / syslog / journald /
 *     Event Log), verdict cache, per-thread scan deadlines (blocking exec verdicts), detection pipeline
 *     (SHA-256, threat intel, tripwire hooks), periodic sweep, new CLI options.
 *   v4 FIX / v4 NEW: changes in v4 (vs v3):
 *   - sweeper has its own condition variable and shutdown broadcasts (a queue wake-up could be consumed by the sweeper
 *     and leave every worker asleep for up to 1 s); AF_UNIX connect() that fails with EAGAIN (clamd backlog full) is
 *     retried instead of failing the scan; infected verdicts are cached (fast, clamd-independent denial of a repeatedly
 *     executed malware) and repeated detections of the same file state are reported once per 5 s (no log/metric flood,
 *     no double count after an exec block); syslog/Event Log records carry the structured fields; [IPv6]:PORT syntax
 *     for --metrics/--tui; --tripwire-ignore-exe; rt_requeue() for the post-block quarantine path.
 */
#define _GNU_SOURCE
#include "clamrt.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <process.h>
#else
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

/* ------------------------------------------------------------------ tunables */
#define CHUNK_SIZE        (64u * 1024u)
#define MAX_PENDING       65536u     /* bound on queued paths (memory cap)          */
#define HASH_BUCKETS      16384u     /* power of two                                */
#define MAX_WAIT_MS       10000u     /* a busy file is scanned at least this often  */
#define MAX_ATTEMPTS      8u         /* retries for transient errors                */
#define BACKOFF_CAP_MS    30000u
#define CONNECT_TIMEOUT_MS 5000
#define IO_TIMEOUT_MS     60000      /* no progress for this long = clamd is stuck  */
#define IO_SLICE_MS       1000       /* v2 NEW: socket timeout slice so g_stop is honoured promptly */
#define MAX_WORKERS       32         /* v3 NEW */
#define VCACHE_SLOTS      32768u     /* v3 NEW: clean-verdict cache (power of two, 2-way set associative, ~1.3 MiB) */
/* v3 NEW: per-thread absolute deadline (plat_now_ms) for the scan in progress; 0 = none.  Blocking exec verdicts
 * must answer the kernel in time, so every wait in the clamd client honours it. */
static __thread uint64_t t_deadline;

volatile sig_atomic_t g_stop = 0; /* v2 FIX: was "volatile int" (not async-signal-safe by the C standard) */
rt_config g_cfg;
rt_stats g_st; /* v3 NEW: shared with the other modules (was a static struct updated without synchronisation) */

/* ------------------------------------------------------------------ portability */
#ifdef _WIN32
typedef CRITICAL_SECTION rt_mutex;
typedef CONDITION_VARIABLE rt_cond;
typedef HANDLE rt_thread;
#define rt_closesock closesocket
#define rt_poll WSAPoll
#define SEND_FLAGS 0
static void mutex_init(rt_mutex *m) { InitializeCriticalSection(m); }
static void mutex_lock(rt_mutex *m) { EnterCriticalSection(m); }
static void mutex_unlock(rt_mutex *m) { LeaveCriticalSection(m); }
static void cond_init(rt_cond *c) { InitializeConditionVariable(c); }
static void cond_wait_ms(rt_cond *c, rt_mutex *m, unsigned ms) { SleepConditionVariableCS(c, m, ms); }
static void cond_signal(rt_cond *c) { WakeConditionVariable(c); }
static void cond_broadcast(rt_cond *c) { WakeAllConditionVariable(c); } /* v4 NEW */
typedef struct { void *(*fn)(void *); void *arg; } thr_start;
static unsigned __stdcall thr_tramp(void *p)
{
    thr_start s = *(thr_start *)p;
    free(p);
    s.fn(s.arg);
    return 0;
}
static int thread_start(rt_thread *t, void *(*fn)(void *), void *arg)
{
    thr_start *s = malloc(sizeof *s);
    if (!s) return -1;
    s->fn = fn;
    s->arg = arg;
    uintptr_t h = _beginthreadex(NULL, 0, thr_tramp, s, 0, NULL);
    if (!h) { free(s); return -1; }
    *t = (HANDLE)h;
    return 0;
}
static void thread_join(rt_thread t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
static int sock_nonblock(rt_sock s, int nb) { u_long m = (u_long)nb; return ioctlsocket(s, FIONBIO, &m); }
static void sock_timeouts(rt_sock s, int ms)
{
    DWORD t = (DWORD)ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof t);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&t, sizeof t);
}
static int connect_in_progress(void) { return WSAGetLastError() == WSAEWOULDBLOCK; }
static int err_interrupted(void) { return 0; }
static int err_timed_out(void) { int e = WSAGetLastError(); return e == WSAETIMEDOUT || e == WSAEWOULDBLOCK; } /* v2 NEW */
#else
typedef pthread_mutex_t rt_mutex;
typedef pthread_cond_t rt_cond;
typedef pthread_t rt_thread;
#define rt_closesock close
#define rt_poll poll
#ifdef MSG_NOSIGNAL
#define SEND_FLAGS MSG_NOSIGNAL
#else
#define SEND_FLAGS 0
#endif
static void mutex_init(rt_mutex *m) { pthread_mutex_init(m, NULL); }
static void mutex_lock(rt_mutex *m) { pthread_mutex_lock(m); }
static void mutex_unlock(rt_mutex *m) { pthread_mutex_unlock(m); }
static void cond_init(rt_cond *c)
{
    pthread_condattr_t a;
    pthread_condattr_init(&a);
    pthread_condattr_setclock(&a, CLOCK_MONOTONIC); /* immune to wall-clock jumps */
    pthread_cond_init(c, &a);
    pthread_condattr_destroy(&a);
}
static void cond_wait_ms(rt_cond *c, rt_mutex *m, unsigned ms)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    pthread_cond_timedwait(c, m, &ts);
}
static void cond_signal(rt_cond *c) { pthread_cond_signal(c); }
static void cond_broadcast(rt_cond *c) { pthread_cond_broadcast(c); } /* v4 NEW */
static int thread_start(rt_thread *t, void *(*fn)(void *), void *arg) { return pthread_create(t, NULL, fn, arg); }
static void thread_join(rt_thread t) { pthread_join(t, NULL); }
static int sock_nonblock(rt_sock s, int nb)
{
    int f = fcntl(s, F_GETFL, 0);
    if (f < 0) return -1;
    return fcntl(s, F_SETFL, nb ? (f | O_NONBLOCK) : (f & ~O_NONBLOCK));
}
static void sock_timeouts(rt_sock s, int ms)
{
    struct timeval tv = {ms / 1000, (ms % 1000) * 1000};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}
static int connect_in_progress(void) { return errno == EINPROGRESS; }
static int err_interrupted(void) { return errno == EINTR; }
static int err_timed_out(void) { return errno == EAGAIN || errno == EWOULDBLOCK; } /* v2 NEW */
#endif

/* ------------------------------------------------------------------ logging */
static FILE *g_logf;
static const char *g_logpath; /* v2 NEW: remembered so SIGHUP (logrotate) can reopen it */
static rt_mutex g_logmu;

static void sanitize(char *m) /* log-injection defence: file names are attacker controlled */
{
    size_t i;
    for (i = 0; m[i]; i++) {
        unsigned char c = (unsigned char)m[i];
        if (c < 0x20 || c == 0x7f) m[i] = '?';
    }
}

/* v3 NEW: JSON string escaper (RFC 8259).  Invalid UTF-8 bytes are replaced by '?' so every record parses. */
static size_t json_esc(char *o, size_t osz, const char *in)
{
    size_t n = 0;
    const unsigned char *p = (const unsigned char *)in;
    if (osz < 8) return 0;
    for (; *p && n + 7 < osz; p++) {
        unsigned char c = *p;
        if (c == '"' || c == '\\') { o[n++] = '\\'; o[n++] = (char)c; }
        else if (c < 0x20 || c == 0x7f) n += (size_t)snprintf(o + n, osz - n, "\\u%04x", c);
        else if (c >= 0x80) {
            int need = c >= 0xf5 ? -1 : c >= 0xf0 ? 3 : c >= 0xe0 ? 2 : c >= 0xc2 ? 1 : -1, k, ok = need > 0; /* v3: 0xf5+ is never valid UTF-8 */
            for (k = 1; ok && k <= need; k++) if ((p[k] & 0xc0) != 0x80) ok = 0;
            if (!ok) o[n++] = '?';
            else { memcpy(o + n, p, (size_t)need + 1); n += (size_t)need + 1; p += need; }
        } else o[n++] = (char)c;
    }
    o[n] = '\0';
    return n;
}

static void log_emit(int level, const char *msgin, const char *const *kv)
{
    static const char *const names[] = {"ERROR", "WARN", "INFO", "DEBUG"};
    char msg[8192], ts[40];
    time_t now = time(NULL);
    struct tm tmv;

    if (level == RT_LOG_DEBUG && !g_cfg.verbose) return;
    snprintf(msg, sizeof msg, "%s", msgin);
    sanitize(msg);
#ifdef _WIN32
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    strftime(ts, sizeof ts, g_cfg.log_json ? "%Y-%m-%dT%H:%M:%S%z" : "%Y-%m-%d %H:%M:%S", &tmv);

    mutex_lock(&g_logmu);
    /* v2 NEW: logrotate support -- reopen the log file after SIGHUP. */
    if (g_logf && g_logpath && plat_take_log_reopen()) {
        FILE *n = plat_fopen_log(g_logpath);
        if (n) { fclose(g_logf); g_logf = n; }
    }
    if (g_cfg.log_json) { /* v3 NEW: one JSON object per line (JSON Lines) for SIEM ingestion */
        char e1[16384], e2[8192];
        FILE *o = g_logf ? g_logf : stderr;
        int i;
        json_esc(e1, sizeof e1, msg);
        fprintf(o, "{\"ts\":\"%s\",\"level\":\"%s\",\"msg\":\"%s\"", ts, names[level], e1);
        for (i = 0; kv && kv[i] && kv[i + 1]; i += 2) {
            json_esc(e1, sizeof e1, kv[i]);
            json_esc(e2, sizeof e2, kv[i + 1]);
            fprintf(o, ",\"%s\":\"%s\"", e1, e2);
        }
        fputs("}\n", o);
        fflush(o);
    } else {
        /* v3 NEW: text sinks also get the useful structured fields (sha256, pid, process ...) appended as key=value;
         * fields already present in the message (path, signature ...) are not repeated. */
        char extra[2048];
        size_t en = 0;
        int i;
        extra[0] = '\0';
        for (i = 0; kv && kv[i] && kv[i + 1]; i += 2) {
            static const char *const skip[] = {"event", "path", "signature", "what", "reason", NULL};
            int k, sk = 0;
            for (k = 0; skip[k]; k++) if (!strcmp(kv[i], skip[k])) sk = 1;
            if (sk || !kv[i + 1][0] || en + 8 >= sizeof extra) continue;
            en += (size_t)snprintf(extra + en, sizeof extra - en, " %s=%s", kv[i], kv[i + 1]);
        }
        sanitize(extra);
        fprintf(g_logf ? g_logf : stderr, "%s [%s] %s%s\n", ts, names[level], msg, extra);
        fflush(g_logf ? g_logf : stderr);
    }
    mutex_unlock(&g_logmu);
    if (g_cfg.log_syslog || g_cfg.log_eventlog) { /* v3 NEW; v4 FIX: the structured fields (sha256, pid, process ...) are appended too -- v3 sent the bare message only */
        char line[8192 + 2048];
        char ex[2048];
        size_t en = 0;
        int i;
        ex[0] = '\0';
        for (i = 0; kv && kv[i] && kv[i + 1]; i += 2) {
            static const char *const skip[] = {"event", "path", "signature", "what", "reason", NULL};
            int k, sk = 0;
            for (k = 0; skip[k]; k++) if (!strcmp(kv[i], skip[k])) sk = 1;
            if (sk || !kv[i + 1][0] || en + 8 >= sizeof ex) continue;
            en += (size_t)snprintf(ex + en, sizeof ex - en, " %s=%s", kv[i], kv[i + 1]);
        }
        sanitize(ex);
        snprintf(line, sizeof line, "%s%s", msg, ex);
        plat_syslog(level, line);
    }
    if (g_cfg.log_journald) plat_journald(level, msg, kv);                      /* v3 NEW */
}

void rt_log(int level, const char *fmt, ...)
{
    char msg[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    log_emit(level, msg, NULL);
}

/* v3 NEW: structured record.  Usage: rt_log_kv(level, "text", "key", "value", ..., NULL) */
void rt_log_kv(int level, const char *msg, ...)
{
    const char *kv[40];
    int n = 0;
    va_list ap;
    const char *k;
    va_start(ap, msg);
    while (n < 38 && (k = va_arg(ap, const char *)) != NULL) {
        kv[n++] = k;
        kv[n++] = va_arg(ap, const char *);
        if (!kv[n - 1]) kv[n - 1] = "";
    }
    va_end(ap);
    kv[n] = NULL;
    log_emit(level, msg, kv);
}

/* ------------------------------------------------------------------ statistics */
void rt_note_overflow(void) /* v2 NEW */
{
    RT_INC(overflows);
    rt_log(RT_LOG_WARN, "the OS dropped change events; re-scanning files modified in the last %d s",
           RT_OVERFLOW_RESCAN_WINDOW_S);
}

/* ------------------------------------------------------------------ debounce queue */
typedef struct pend {
    struct pend *hnext;       /* hash chain */
    struct pend *prev, *next; /* list sorted by due-time (head = earliest) */
    uint64_t due, first_seen;
    uint32_t hash;
    unsigned attempts;
    char path[1];
} pend;

static rt_mutex g_qmu;
static rt_cond g_qcv;
static rt_mutex g_swmu; /* v4 FIX: the sweeper used to sleep on g_qcv: queue_add()'s single cond_signal could wake the */
static rt_cond g_swcv;  /*   sweeper instead of a worker (worker then idled up to 1 s), and shutdown woke only one thread. */
static pend *g_buckets[HASH_BUCKETS];
static pend *g_head, *g_tail;
static unsigned g_count;

static uint32_t fnv1a(const char *s)
{
    uint32_t h = 2166136261u;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 16777619u;
    }
    return h;
}

static void list_unlink(pend *e)
{
    if (e->prev) e->prev->next = e->next; else g_head = e->next;
    if (e->next) e->next->prev = e->prev; else g_tail = e->prev;
    e->prev = e->next = NULL;
}

/* insert keeping ascending due order; scans backwards from the tail (O(1) typical) */
static void list_insert_sorted(pend *e)
{
    pend *p = g_tail;
    while (p && p->due > e->due) p = p->prev;
    e->prev = p;
    e->next = p ? p->next : g_head;
    if (e->next) e->next->prev = e; else g_tail = e;
    if (p) p->next = e; else g_head = e;
}

static pend *hash_find(const char *path, uint32_t h)
{
    pend *e;
    for (e = g_buckets[h & (HASH_BUCKETS - 1)]; e; e = e->hnext)
        if (e->hash == h && strcmp(e->path, path) == 0) return e;
    return NULL;
}

static void hash_remove(pend *e)
{
    pend **pp = &g_buckets[e->hash & (HASH_BUCKETS - 1)];
    while (*pp && *pp != e) pp = &(*pp)->hnext;
    if (*pp) *pp = e->hnext;
}

/* attempts==0: a fresh filesystem event (extends the quiet period of a pending entry).
 * attempts>0 : a retry re-queue (never disturbs an already pending entry). */
static void queue_add(const char *path, unsigned delay_ms, unsigned attempts)
{
    uint32_t h = fnv1a(path);
    uint64_t now = plat_now_ms();
    pend *e;

    mutex_lock(&g_qmu);
    e = hash_find(path, h);
    if (e) {
        if (attempts == 0 && now - e->first_seen < MAX_WAIT_MS) {
            e->due = now + delay_ms;
            list_unlink(e);
            list_insert_sorted(e);
        }
    } else if (g_count >= MAX_PENDING) {
        if ((RT_INC(dropped) % 1000) == 1)
            rt_log(RT_LOG_WARN, "queue full (%u): dropping events (%llu dropped so far)", MAX_PENDING,
                   (unsigned long long)RT_GET(dropped));
    } else {
        size_t len = strlen(path);
        e = malloc(sizeof(pend) + len);
        if (!e) {
            RT_INC(dropped);
        } else {
            memcpy(e->path, path, len + 1);
            e->hash = h;
            e->attempts = attempts;
            e->first_seen = now;
            e->due = now + delay_ms;
            e->hnext = g_buckets[h & (HASH_BUCKETS - 1)];
            g_buckets[h & (HASH_BUCKETS - 1)] = e;
            list_insert_sorted(e);
            g_count++;
        }
    }
    __atomic_store_n(&g_st.queue_depth, (uint64_t)g_count, __ATOMIC_RELAXED); /* v3 NEW: gauge for /metrics */
    cond_signal(&g_qcv);
    mutex_unlock(&g_qmu);
}

/* ------------------------------------------------------------------ exclusion / emit */
int rt_excluded(const char *path)
{
    int i;
    if (g_cfg.qdir && plat_str_prefix(path, g_cfg.qdir)) return 1; /* never rescan our own quarantine */
    for (i = 0; i < g_cfg.nexcludes; i++)
        if (plat_str_contains(path, g_cfg.excludes[i])) return 1;
    return 0;
}

/* v3 NEW: back-ends that know the originating process (fanotify, Windows ETW) call this; rt_emit() = unknown pid. */
void rt_emit_pid(const char *path, long pid)
{
    if (g_cfg.tripwire && rt_trip_is_canary(path)) { /* canary: never scanned, always an alert */
        rt_trip_canary_event(path, pid, "modified");
        return;
    }
    if (rt_excluded(path)) return;
    rt_log(RT_LOG_DEBUG, "event: %s", path);
    if (g_cfg.tripwire) rt_trip_note_write(path, pid);
    queue_add(path, g_cfg.debounce_ms, 0);
}

/* v4 NEW: plain "scan / act on this path" request.  Used after a blocked execution so that the quarantine/remove action
 * runs through the normal worker pipeline without feeding the malware file to the ransomware heuristic (v3 called
 * rt_emit_pid(path, 0), which also sampled it for entropy and bumped the unknown-process counter). */
void rt_requeue(const char *path)
{
    if (rt_excluded(path)) return;
    queue_add(path, 0, 0);
}

void rt_emit(const char *path) { rt_emit_pid(path, 0); }

/* ------------------------------------------------------------------ clamd client */
/* v2 FIX: the connect wait is sliced (IO_SLICE_MS) so SIGTERM/Ctrl-C is honoured within ~1 s, not after 5 s. */
static rt_sock connect_with_timeout(int family, int type, int proto, const struct sockaddr *sa, socklen_t len)
{
    rt_sock s = socket(family, type, proto);
    struct pollfd pfd;
    int r, soerr = 0;
    socklen_t sl = sizeof soerr;
    uint64_t end;

    if (s == RT_BADSOCK) return RT_BADSOCK;
    if (sock_nonblock(s, 1) != 0) goto fail;
    end = plat_now_ms() + CONNECT_TIMEOUT_MS;
    r = connect(s, sa, len);
#ifndef _WIN32
    /* v4 FIX: a non-blocking connect() to a UNIX socket whose listen backlog is full fails with EAGAIN (not
     * EINPROGRESS).  With several workers/exec threads hammering clamd this made scans fail and be retried with
     * seconds of backoff although clamd was healthy.  Retry briefly until the connect deadline. */
    while (r != 0 && family == AF_UNIX && errno == EAGAIN) {
        uint64_t now = plat_now_ms();
        if (RT_STOPPING() || now >= end || (t_deadline && now >= t_deadline)) goto fail;
        { struct timespec ts = {0, 5 * 1000000L}; nanosleep(&ts, NULL); }
        r = connect(s, sa, len);
    }
#endif
    if (r != 0) {
        if (!connect_in_progress()) goto fail;
        for (;;) {
            uint64_t now = plat_now_ms();
            if (RT_STOPPING() || now >= end || (t_deadline && now >= t_deadline)) goto fail; /* v3: honour the exec-verdict deadline */
            pfd.fd = s;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            r = rt_poll(&pfd, 1, (int)(end - now > IO_SLICE_MS ? IO_SLICE_MS : end - now));
            if (r > 0) break;
            if (r < 0 && !err_interrupted()) goto fail;
        }
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &sl) != 0 || soerr != 0) goto fail;
    }
    sock_nonblock(s, 0);
    sock_timeouts(s, IO_SLICE_MS); /* v2 FIX: 1 s slices; send_all/recv_reply enforce the overall IO_TIMEOUT_MS */
    return s;
fail:
    rt_closesock(s);
    return RT_BADSOCK;
}

/* v2 NEW: resolve the TCP target once and reuse it (v1 called getaddrinfo for every file: a DNS lookup
 * per scan for non-numeric hosts).  The cache is dropped after a failed connect so a changed DNS record
 * is picked up.  Only the worker thread (and main before the worker starts) calls this. */
static struct addrinfo *g_ai;
static rt_mutex g_aimu; /* v3 FIX: several workers now share the cache */

static rt_sock clamd_connect(void)
{
#ifndef _WIN32
    if (g_cfg.sock_path) {
        struct sockaddr_un sun;
        if (strlen(g_cfg.sock_path) >= sizeof sun.sun_path) return RT_BADSOCK;
        memset(&sun, 0, sizeof sun);
        sun.sun_family = AF_UNIX;
        strcpy(sun.sun_path, g_cfg.sock_path);
        return connect_with_timeout(AF_UNIX, SOCK_STREAM, 0, (struct sockaddr *)&sun, sizeof sun);
    }
#endif
    {
        struct addrinfo hints, *ai;
        rt_sock s = RT_BADSOCK;
        struct addrinfo *mine = NULL;
        mutex_lock(&g_aimu);
        if (!g_ai) {
            memset(&hints, 0, sizeof hints);
            hints.ai_family   = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(g_cfg.host, g_cfg.port, &hints, &g_ai) != 0) { g_ai = NULL; mutex_unlock(&g_aimu); return RT_BADSOCK; }
        }
        {   /* v3 FIX: private copy of the (small) list so a concurrent failure in another worker cannot free it under us */
            struct addrinfo **tail = &mine;
            for (ai = g_ai; ai; ai = ai->ai_next) {
                struct addrinfo *c = malloc(sizeof *c + ai->ai_addrlen);
                if (!c) break;
                *c = *ai;
                c->ai_addr = (struct sockaddr *)(c + 1);
                memcpy(c->ai_addr, ai->ai_addr, ai->ai_addrlen);
                c->ai_next = NULL; c->ai_canonname = NULL;
                *tail = c; tail = &c->ai_next;
            }
        }
        mutex_unlock(&g_aimu);
        for (ai = mine; ai && s == RT_BADSOCK; ai = ai->ai_next)
            s = connect_with_timeout(ai->ai_family, ai->ai_socktype, ai->ai_protocol, ai->ai_addr,
                                     (socklen_t)ai->ai_addrlen);
        while (mine) { struct addrinfo *nx = mine->ai_next; free(mine); mine = nx; }
        if (s == RT_BADSOCK) {
            mutex_lock(&g_aimu);
            if (g_ai) { freeaddrinfo(g_ai); g_ai = NULL; }
            mutex_unlock(&g_aimu);
        }
        return s;
    }
}

/* v2 FIX: socket timeouts are now 1 s slices; the loops below retry on timeout until IO_TIMEOUT_MS passes
 * without progress or g_stop is set.  v1 blocked up to 60 s inside send()/recv(), delaying shutdown. */
static int send_all(rt_sock s, const char *b, size_t n)
{
    uint64_t deadline = plat_now_ms() + IO_TIMEOUT_MS;
    while (n) {
        int want = n > 0x40000000u ? 0x40000000 : (int)n;
        long r = (long)send(s, b, want, SEND_FLAGS);
        if (r < 0) {
            if (err_interrupted()) continue;
            if (err_timed_out()) {
                if (RT_STOPPING() || plat_now_ms() >= deadline || (t_deadline && plat_now_ms() >= t_deadline)) return -1;
                continue;
            }
            return -1;
        }
        if (r == 0) return -1;
        b += r;
        n -= (size_t)r;
        deadline = plat_now_ms() + IO_TIMEOUT_MS; /* progress made */
    }
    return 0;
}

/* Reads a NUL-terminated (z-command) reply. */
static int recv_reply(rt_sock s, char *out, size_t outsz)
{
    size_t len = 0;
    uint64_t deadline = plat_now_ms() + IO_TIMEOUT_MS;
    while (len < outsz - 1) {
        long r = (long)recv(s, out + len, (int)(outsz - 1 - len), 0);
        if (r < 0) {
            if (err_interrupted()) continue;
            if (err_timed_out()) {
                if (RT_STOPPING() || plat_now_ms() >= deadline || (t_deadline && plat_now_ms() >= t_deadline)) break;
                continue;
            }
            break;
        }
        if (r == 0) break;
        len += (size_t)r;
        if (memchr(out + len - r, '\0', (size_t)r)) break;
    }
    out[len] = '\0';
    return len ? 0 : -1;
}

static int clamd_ping(void)
{
    char reply[64];
    rt_sock s = clamd_connect();
    int ok = 0;
    if (s == RT_BADSOCK) return 0;
    if (send_all(s, "zPING", 6) == 0 && recv_reply(s, reply, sizeof reply) == 0 && strncmp(reply, "PONG", 4) == 0) ok = 1;
    rt_closesock(s);
    return ok;
}

#define SR_CLEAN RT_SR_CLEAN /* v3 FIX: one definition shared with the header */
#define SR_INFECTED RT_SR_INFECTED
#define SR_ERROR RT_SR_ERROR
#define SR_SKIP RT_SR_SKIP

static int scan_handle(rt_fh *fh, char *sig, size_t sigsz)
{
    static __thread unsigned char buf[4 + CHUNK_SIZE]; /* v3 FIX: per-thread (several workers + exec-verdict threads) */
    char reply[1024];
    uint64_t total = 0;
    int send_failed = 0, rc = SR_ERROR;
    rt_sock s = clamd_connect();
    char *p, *end;
    size_t l;

    sig[0] = '\0';
    if (s == RT_BADSOCK) return SR_ERROR;
    if (send_all(s, "zINSTREAM", 10) != 0) { rt_closesock(s); return SR_ERROR; }

    for (;;) {
        long n = plat_read(fh, buf + 4, CHUNK_SIZE);
        uint32_t be;
        if (RT_STOPPING() || (t_deadline && plat_now_ms() >= t_deadline)) { rt_closesock(s); return SR_ERROR; } /* v2 NEW/v3: abort big streams on shutdown or verdict deadline */
        if (n < 0) { rt_closesock(s); return SR_ERROR; }
        if (n == 0) break;
        total += (uint64_t)n;
        if (total > g_cfg.max_size) { rt_closesock(s); return SR_SKIP; } /* grew past the limit while reading */
        be = (uint32_t)n;
        buf[0] = (unsigned char)(be >> 24);
        buf[1] = (unsigned char)(be >> 16);
        buf[2] = (unsigned char)(be >> 8);
        buf[3] = (unsigned char)be;
        if (send_all(s, (const char *)buf, (size_t)n + 4) != 0) { send_failed = 1; break; }
    }
    if (!send_failed) {
        static const char term[4] = {0, 0, 0, 0};
        if (send_all(s, term, 4) != 0) send_failed = 1;
    }
    /* Even after a send failure clamd may have sent an explanatory reply. */
    if (recv_reply(s, reply, sizeof reply) != 0) { rt_closesock(s); return SR_ERROR; }
    rt_closesock(s);

    p = reply;
    if (strncmp(p, "stream: ", 8) == 0) p += 8;
    l = strlen(p);
    while (l && (p[l - 1] == '\n' || p[l - 1] == '\r' || p[l - 1] == ' ')) p[--l] = '\0';

    if (l >= 6 && strcmp(p + l - 6, " FOUND") == 0) {
        end = p + l - 6;
        *end = '\0';
        snprintf(sig, sigsz, "%s", p);
        rc = SR_INFECTED;
    } else if (l >= 2 && strcmp(p + l - 2, "OK") == 0 && !send_failed) {
        rc = SR_CLEAN;
    } else if (strstr(p, "size limit exceeded")) {
        rc = SR_SKIP;
    } else {
        rt_log(RT_LOG_DEBUG, "clamd reply: %s", p);
        rc = SR_ERROR;
    }
    return rc;
}

/* ------------------------------------------------------------------ verdict cache (v3 NEW)
 * Remembers "this exact file state was scanned clean" so executing /bin/ls a thousand times, or sweeping
 * unchanged files, costs one scan.  Key = identity + size + change stamp (mtime AND ctime, so a forged mtime
 * cannot hide a modification).  Entries expire after --verdict-ttl so new signatures still apply.
 * Only clean verdicts are cached; direct-mapped, mutex protected. */
typedef struct { uint64_t k0, k1, k2, size, expires; } vslot;
static vslot g_vc[VCACHE_SLOTS];
static rt_mutex g_vcmu;

static void fh_key(const rt_fh *fh, uint64_t k[3])
{
#ifdef _WIN32
    k[0] = ((uint64_t)fh->vol << 32) ^ fh->idhi;
    k[1] = fh->idlo;
#else
    k[0] = (uint64_t)fh->dev;
    k[1] = (uint64_t)fh->ino;
#endif
    k[2] = fh->mtime;
}

static size_t vc_index(const uint64_t k[3]) { return (size_t)((k[0] * 0x9E3779B97F4A7C15ull ^ k[1] * 0xC2B2AE3D27D4EB4Full ^ k[2]) & (VCACHE_SLOTS - 1)); }

static int vcache_hit(const rt_fh *fh)
{
    uint64_t k[3], now;
    size_t i;
    int hit = 0, w;
    if (!g_cfg.verdict_ttl_s) return 0;
    fh_key(fh, k);
    now = plat_now_ms();
    i = vc_index(k);
    mutex_lock(&g_vcmu);
    for (w = 0; w < 2 && !hit; w++) { /* v3: 2-way set associative (index, index^1) -- direct mapping lost ~25% of entries to collisions */
        const vslot *v = &g_vc[i ^ (size_t)w];
        hit = v->expires > now && v->k0 == k[0] && v->k1 == k[1] && v->k2 == k[2] && v->size == fh->size;
    }
    mutex_unlock(&g_vcmu);
    return hit;
}

static void vcache_put(const rt_fh *fh)
{
    uint64_t k[3], now;
    size_t i;
    vslot *v;
    if (!g_cfg.verdict_ttl_s) return;
    fh_key(fh, k);
    now = plat_now_ms();
    i = vc_index(k);
    mutex_lock(&g_vcmu);
    v = &g_vc[i];
    if (g_vc[i ^ 1].expires <= now || (v->expires > now && g_vc[i ^ 1].expires < v->expires)) v = &g_vc[i ^ 1]; /* free/expired way first, else evict the older */
    if (g_vc[i].k0 == k[0] && g_vc[i].k1 == k[1] && g_vc[i].k2 == k[2]) v = &g_vc[i];       /* refresh in place */
    v->k0 = k[0]; v->k1 = k[1]; v->k2 = k[2]; v->size = fh->size;
    v->expires = now + (uint64_t)g_cfg.verdict_ttl_s * 1000u;
    mutex_unlock(&g_vcmu);
}

/* v4 NEW: table of INFECTED file states.  Two jobs:
 *   1. verdict cache for malware: a program that is executed again and again is denied in microseconds, and still denied
 *      when clamd is down or slow (the clean cache alone made every repeat exec cost a full scan, and fail-open let it run
 *      whenever clamd was unavailable).  Entries live min(--verdict-ttl, 60) s so a signature fix (false positive) applies
 *      quickly; with --verdict-ttl 0 nothing is served from here.
 *   2. report de-duplication: the same file state is logged/counted/looked-up once per BAD_REPORT_MS.  Without it a
 *      looping malware flooded the log, and a blocked exec was reported twice (exec-block + the follow-up scan).
 * Small (256 entries, round-robin replacement), linear search under g_vcmu. */
#define BAD_SLOTS 256u
#define BAD_REPORT_MS 5000u
typedef struct { uint64_t k0, k1, k2, size, expires, report_until; char sig[64]; int used; } badslot;
static badslot g_bad[BAD_SLOTS];
static unsigned g_bad_next;

static badslot *bad_find_locked(const uint64_t k[3], uint64_t size)
{
    unsigned i;
    for (i = 0; i < BAD_SLOTS; i++)
        if (g_bad[i].used && g_bad[i].k0 == k[0] && g_bad[i].k1 == k[1] && g_bad[i].k2 == k[2] && g_bad[i].size == size) return &g_bad[i];
    return NULL;
}

static badslot *bad_get_locked(const uint64_t k[3], uint64_t size)
{
    badslot *b = bad_find_locked(k, size);
    if (!b) { /* prefer an unused/expired slot, else evict round-robin */
        uint64_t now = plat_now_ms();
        unsigned i;
        for (i = 0; i < BAD_SLOTS && !b; i++) {
            badslot *c = &g_bad[(g_bad_next + i) % BAD_SLOTS];
            if (!c->used || (c->expires <= now && c->report_until <= now)) b = c;
        }
        if (!b) b = &g_bad[g_bad_next];
        g_bad_next = (unsigned)((b - g_bad) + 1) % BAD_SLOTS;
        memset(b, 0, sizeof *b);
        b->used = 1; b->k0 = k[0]; b->k1 = k[1]; b->k2 = k[2]; b->size = size;
    }
    return b;
}

static int bad_hit(const rt_fh *fh, char *sig, size_t sigsz)
{
    uint64_t k[3], now = plat_now_ms();
    badslot *b;
    int hit = 0;
    if (!g_cfg.verdict_ttl_s) return 0;
    fh_key(fh, k);
    mutex_lock(&g_vcmu);
    b = bad_find_locked(k, fh->size);
    if (b && b->expires > now) { snprintf(sig, sigsz, "%s", b->sig); hit = 1; }
    mutex_unlock(&g_vcmu);
    return hit;
}

static void bad_note(const rt_fh *fh, const char *sig)
{
    uint64_t k[3], now = plat_now_ms(), life = (g_cfg.verdict_ttl_s < 60 ? g_cfg.verdict_ttl_s : 60) * 1000ull;
    badslot *b;
    fh_key(fh, k);
    mutex_lock(&g_vcmu);
    b = bad_get_locked(k, fh->size);
    snprintf(b->sig, sizeof b->sig, "%s", sig);
    b->expires = life ? now + life : 0;
    mutex_unlock(&g_vcmu);
}

/* returns 1 when this detection should be reported now (and arms the de-dup window), 0 when it is a repeat */
static int bad_report_once(const rt_fh *fh, const char *sig)
{
    uint64_t k[3], now = plat_now_ms();
    badslot *b;
    int first;
    fh_key(fh, k);
    mutex_lock(&g_vcmu);
    b = bad_get_locked(k, fh->size);
    first = b->report_until <= now;
    if (first) { b->report_until = now + BAD_REPORT_MS; if (!b->sig[0]) snprintf(b->sig, sizeof b->sig, "%s", sig); }
    mutex_unlock(&g_vcmu);
    return first;
}

/* Scan with cache and latency accounting.  deadline_ms: absolute (0 = none). */
static int scan_cached(rt_fh *fh, char *sig, size_t sigsz, uint64_t deadline_ms, int *from_cache)
{
    uint64_t t0;
    int r;
    sig[0] = '\0';
    *from_cache = 0;
    if (vcache_hit(fh)) { *from_cache = 1; RT_INC(verdict_cache_hits); return SR_CLEAN; }
    if (bad_hit(fh, sig, sigsz)) { *from_cache = 1; RT_INC(verdict_cache_hits); return SR_INFECTED; } /* v4 NEW */
    t_deadline = deadline_ms;
    t0 = plat_now_ms();
    r = scan_handle(fh, sig, sigsz);
    t_deadline = 0;
    RT_ADD(scan_ns_total, (plat_now_ms() - t0) * 1000000ull);
    RT_INC(scan_count_timed);
    if (r == SR_CLEAN) vcache_put(fh);
    else if (r == SR_INFECTED) bad_note(fh, sig); /* v4 NEW */
    return r;
}

/* v3 NEW: verdict for a blocked execution (called from the fanotify permission-event threads). */
int rt_scan_for_exec(rt_fh *fh, const char *path, uint64_t deadline_ms, char *sig, size_t sigsz)
{
    int cached, r;
    (void)path;
    if (fh->size > g_cfg.max_size) { sig[0] = '\0'; return SR_SKIP; }
    r = scan_cached(fh, sig, sigsz, deadline_ms, &cached);
    if (cached) RT_INC(exec_cache_hits);
    return r;
}

/* v3 NEW: single place for everything that happens on a detection (file scans and blocked executions):
 * structured log record with SHA-256, metrics, /events ring, optional threat-intel lookup. */
void rt_detected(const char *path, const char *sig, rt_fh *fh, long pid, const char *how)
{
    char sha[65] = "", pidbuf[32] = "", proc[512] = "";
    if (fh && !bad_report_once(fh, sig)) { /* v4 NEW: same file state reported within the last 5 s (repeat exec / follow-up scan) */
        rt_log(RT_LOG_DEBUG, "detection repeated (suppressed): %s: %s [%s]", path, sig, how);
        return;
    }
    RT_INC(infected);
    if (fh && rt_hash_handle(fh, sha) != 0) sha[0] = '\0';
    if (pid > 0) {
        snprintf(pidbuf, sizeof pidbuf, "%ld", pid);
        plat_pid_info(pid, proc, sizeof proc);
    }
    {
        char line[2048];
        snprintf(line, sizeof line, "%s %s [%s]", sig, path, how);
        rt_obs_event("detection", line);
    }
    {
        char msg[4600];
        snprintf(msg, sizeof msg, "INFECTED: %s: %s", path, sig); /* v2 text format kept for text sinks */
        rt_log_kv(RT_LOG_WARN, msg, "event", "detection", "path", path, "signature", sig, "sha256", sha, "how", how,
                  "pid", pidbuf, "process", proc, NULL);
    }
    if (sha[0] && g_cfg.intel != RT_INTEL_NONE) rt_intel_submit(path, sig, sha);
}

/* ------------------------------------------------------------------ worker */
static void schedule_retry(const char *path, unsigned attempts, const char *why)
{
    unsigned delay;
    if (RT_STOPPING()) return; /* v2 FIX: during shutdown an aborted scan is not an error; v1 logged a bogus retry */
    if (attempts >= MAX_ATTEMPTS) {
        RT_INC(errors);
        rt_log(RT_LOG_ERR, "giving up on %s after %u attempts (%s)", path, attempts, why);
        return;
    }
    delay = 1000u << (attempts < 5 ? attempts : 5);
    if (delay > BACKOFF_CAP_MS) delay = BACKOFF_CAP_MS;
    rt_log(RT_LOG_WARN, "%s: %s; retry %u/%u in %u ms", path, why, attempts + 1, MAX_ATTEMPTS, delay);
    queue_add(path, delay, attempts + 1);
}

static void handle_infected(rt_fh *fh, const char *path, const char *sig, unsigned attempts)
{
    char dest[4096];

    rt_detected(path, sig, fh, 0, "scan"); /* v3: structured record, SHA-256, metrics, threat intel */
    if (g_cfg.action == ACT_REPORT) return;

    /* Only touch the path if it still names the exact file we scanned. */
    if (!plat_still_same(fh, path)) {
        RT_INC(actions_failed);
        rt_log(RT_LOG_WARN, "%s changed since it was scanned; not acting, re-queued", path);
        /* v2 FIX: goes through schedule_retry() so the attempt count is capped (v1 re-queued with a constant
         * attempts=1, so a file that kept changing could loop forever). */
        schedule_retry(path, attempts, "file changed after scan");
        return;
    }
    if (g_cfg.action == ACT_QUARANTINE) {
        /* v2 FIX: plat_quarantine re-verifies identity itself and resolves name collisions. */
        if (plat_quarantine(fh, path, g_cfg.qdir, sig, dest, sizeof dest) == 0)
            rt_log(RT_LOG_INFO, "quarantined: %s -> %s", path, dest);
        else {
            RT_INC(actions_failed);
            rt_log(RT_LOG_ERR, "quarantine FAILED for %s", path);
            schedule_retry(path, attempts, "quarantine failed"); /* v2 FIX: v1 left the infected file in place and never retried */
        }
    } else {
        if (plat_remove(fh, path) == 0)
            rt_log(RT_LOG_INFO, "removed: %s", path);
        else {
            RT_INC(actions_failed);
            rt_log(RT_LOG_ERR, "remove FAILED for %s", path);
            schedule_retry(path, attempts, "remove failed");
        }
    }
}

static void process(const char *path, unsigned attempts)
{
    rt_fh fh;
    char sig[1024]; /* >= clamd reply buffer, so no truncation */
    int r, cached;

    if (rt_excluded(path)) return;
    r = plat_open(path, &fh);
    if (r == RT_SKIP) { RT_INC(skipped); return; }
    if (r == RT_DENIED) {
        RT_INC(errors);
        rt_log(RT_LOG_WARN, "permission denied: %s", path);
        return;
    }
    if (r != RT_OK) { schedule_retry(path, attempts, "cannot open"); return; }

    if (fh.size > g_cfg.max_size) {
        RT_INC(skipped);
        rt_log(RT_LOG_INFO, "skipped (larger than --max-size): %s", path);
        plat_close(&fh);
        return;
    }

    switch (scan_cached(&fh, sig, sizeof sig, 0, &cached)) { /* v3: verdict cache */
        case SR_CLEAN:
            RT_INC(scanned);
            RT_INC(clean);
            rt_log(RT_LOG_DEBUG, cached ? "clean (cached): %s" : "clean: %s", path);
            break;
        case SR_INFECTED:
            RT_INC(scanned);
            handle_infected(&fh, path, sig, attempts);
            break;
        case SR_SKIP:
            RT_INC(skipped);
            rt_log(RT_LOG_INFO, "skipped (clamd size limit or file grew): %s", path);
            break;
        default:
            schedule_retry(path, attempts, "clamd unavailable or scan error");
            break;
    }
    plat_close(&fh);
}

static void *worker_main(void *arg)
{
    (void)arg;
    for (;;) {
        pend *e = NULL;
        mutex_lock(&g_qmu);
        while (!RT_STOPPING()) {
            uint64_t now;
            if (!g_head) {
                cond_wait_ms(&g_qcv, &g_qmu, 1000);
                continue;
            }
            now = plat_now_ms();
            if (g_head->due <= now) { e = g_head; break; }
            {
                uint64_t w = g_head->due - now;
                cond_wait_ms(&g_qcv, &g_qmu, (unsigned)(w > 1000 ? 1000 : w)); /* wake to notice g_stop */
            }
        }
        if (e) {
            list_unlink(e);
            hash_remove(e);
            g_count--;
            __atomic_store_n(&g_st.queue_depth, (uint64_t)g_count, __ATOMIC_RELAXED);
        }
        mutex_unlock(&g_qmu);
        if (!e) break; /* stopping */
        process(e->path, e->attempts);
        free(e);
    }
    return NULL;
}

/* v3 NEW: periodic safety-net sweep (--sweep-interval): re-queues files whose mtime OR ctime is newer than the
 * last sweep.  ctime catches hard links and renames-in that raise no write event; the verdict cache makes
 * re-visiting unchanged files nearly free. */
static void *sweeper_main(void *arg)
{
    uint64_t next;
    (void)arg;
    next = plat_now_ms() + (uint64_t)g_cfg.sweep_s * 1000u;
    while (!RT_STOPPING()) {
        uint64_t now = plat_now_ms();
        if (now >= next) {
            plat_sweep((long long)time(NULL) - (long long)g_cfg.sweep_s - 5);
            next = plat_now_ms() + (uint64_t)g_cfg.sweep_s * 1000u;
        } else {
            uint64_t w = next - now;
            mutex_lock(&g_swmu);
            if (!RT_STOPPING()) cond_wait_ms(&g_swcv, &g_swmu, (unsigned)(w > 1000 ? 1000 : w));
            mutex_unlock(&g_swmu);
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ CLI */
static void usage(FILE *to, const char *argv0) /* v2 FIX: --help goes to stdout (exit 0), errors to stderr */
{
    fprintf(to,
            CLAMRT_BANNER "\n\n"
            "Usage: %s --path DIR [--path DIR ...] [options]\n\n"
            "  -p, --path DIR            directory to watch (repeatable, required)\n"
            "      --no-recursive        do not watch sub-directories\n"
            "      --scan-existing       also scan files already present at start-up\n"
            "      --clamd-socket PATH   clamd unix socket (Linux)\n"
            "      --clamd-host HOST     clamd TCP host (default 127.0.0.1)\n"
            "      --clamd-port PORT     clamd TCP port (default 3310)\n"
            "      --action A            report (default) | quarantine | remove\n"
            "      --quarantine-dir DIR  required for --action quarantine (must be private to this user)\n"
            "      --exclude SUBSTR      skip paths containing SUBSTR (repeatable)\n"
            "      --max-size MB         skip larger files (default 100; keep <= clamd StreamMaxLength)\n"
            "      --debounce-ms N       quiet period before scanning (default 500)\n"
            "      --log FILE            append log to FILE (default stderr; SIGHUP reopens it on Linux)\n"
            "  -v, --verbose             debug logging\n"
            "      --version | --help\n\n"
            "v3/v4 options:\n"
            "      --mode M              auto (default) | inotify | fanotify (Linux, root) | etw (Windows, admin)\n"
            "      --block-exec          fanotify/minifilter: DENY execution of infected files (blocking)\n"
            "      --exec-timeout-ms N   verdict deadline for blocked executions (default 4000)\n"
            "      --exec-fail closed|open  on timeout/clamd failure deny or allow execution (default open)\n"
            "      --workers N           parallel scan workers (default 2, max %d)\n"
            "      --verdict-ttl S       clean-verdict cache lifetime (default 600, 0 = off)\n"
            "      --sweep-interval S    periodic safety-net sweep of recently changed files (default off)\n"
            "      --log-format F        text (default) | json\n"
            "      --syslog | --journald | --eventlog   additional log sinks (Linux / Windows)\n"
            "      --metrics [HOST:]PORT Prometheus /metrics, /status.json, /events (default host 127.0.0.1; IPv6: [::1]:PORT)\n"
            "      --tui [HOST:]PORT     live terminal dashboard for a running clamrt with --metrics\n"
            "      --tripwire            ransomware tripwire (rate + entropy heuristic)\n"
            "      --canary              plant canary files in each root (implies --tripwire)\n"
            "      --tripwire-action A   alert (default) | suspend | kill   (process that trips it)\n"
            "      --tripwire-rate N     high-entropy writes by one process ... (default 50)\n"
            "      --tripwire-window S   ... within S seconds (default 10)\n"
            "      --tripwire-ignore-comm NAME  never act on processes with this name (repeatable; e.g. backup tools).\n"
            "                            Linux: the kernel keeps only 15 characters and any process can rename itself,\n"
            "                            so prefer --tripwire-ignore-exe\n"
            "      --tripwire-ignore-exe PATH   never act on processes running this absolute executable path (repeatable)\n"
            "      --intel mb|vt         hash-only threat-intel lookup of detections (MalwareBazaar / VirusTotal)\n"
            "      --intel-key-env VAR   environment variable holding the API key (never put keys on the command line)\n"
            "      --intel-url URL       override the API base URL\n"
            "      --curl PATH           curl executable used for intel lookups (default: curl)\n",
            argv0, MAX_WORKERS);
}

static int parse_u64(const char *s, uint64_t *out)
{
    char *end;
    unsigned long long v;
    if (!s || !*s || !isdigit((unsigned char)*s)) return -1;
    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno || *end) return -1;
    *out = v;
    return 0;
}

static int same_path(const char *a, const char *b) /* v2 NEW: root de-duplication */
{
    return plat_str_prefix(a, b) && plat_str_prefix(b, a);
}

static const char *g_tui_host, *g_tui_port; /* v3 NEW: --tui target */

static int parse_args(int argc, char **argv, const char **qdir_in, const char **log_in)
{
    int i, j;
    const char *rawpaths[RT_MAX_LIST];
    int nraw = 0;
    uint64_t v;

    g_cfg.host        = "127.0.0.1";
    g_cfg.port        = "3310";
    g_cfg.action      = ACT_REPORT;
    g_cfg.max_size    = 100ull * 1024 * 1024;
    g_cfg.debounce_ms = 500;
    g_cfg.recursive   = 1;
    g_cfg.workers     = 2;       /* v3 NEW defaults */
    g_cfg.exec_timeout_ms = 4000;
    g_cfg.verdict_ttl_s = 600;
    g_cfg.trip_rate   = 50;
    g_cfg.trip_window_s = 10;
    g_cfg.curl_path   = "curl";

#define NEEDVAL()                                                       \
    do {                                                                \
        if (!val) {                                                     \
            if (i + 1 >= argc) { fprintf(stderr, "%s needs a value\n", a); return -1; } \
            val = argv[++i];                                            \
        }                                                               \
    } while (0)

    for (i = 1; i < argc; i++) {
        char *a = argv[i], *val = NULL, *eq;
        char optbuf[64];
        if (a[0] == '-' && a[1] == '-' && (eq = strchr(a, '=')) != NULL) { /* --opt=value */
            size_t n = (size_t)(eq - a);
            if (n >= sizeof optbuf) { fprintf(stderr, "bad option %s\n", a); return -1; }
            memcpy(optbuf, a, n);
            optbuf[n] = '\0';
            val = eq + 1;
            a   = optbuf;
        }
        if (!strcmp(a, "-p") || !strcmp(a, "--path")) {
            NEEDVAL();
            if (nraw >= RT_MAX_ROOTS) { fprintf(stderr, "too many --path (max %d)\n", RT_MAX_ROOTS); return -1; } /* v2 FIX: Windows limit is 63 */
            rawpaths[nraw++] = val;
        } else if (!strcmp(a, "--no-recursive")) g_cfg.recursive = 0;
        else if (!strcmp(a, "--scan-existing")) g_cfg.scan_existing = 1;
        else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) g_cfg.verbose = 1;
        else if (!strcmp(a, "--clamd-socket")) { NEEDVAL(); g_cfg.sock_path = val; }
        else if (!strcmp(a, "--clamd-host")) { NEEDVAL(); g_cfg.host = val; }
        else if (!strcmp(a, "--clamd-port")) {
            NEEDVAL();
            if (!*val) { fprintf(stderr, "empty --clamd-port\n"); return -1; } /* v2 FIX: validated (v1 passed "" to getaddrinfo) */
            g_cfg.port = val;
        }
        else if (!strcmp(a, "--quarantine-dir")) { NEEDVAL(); *qdir_in = val; }
        else if (!strcmp(a, "--log")) { NEEDVAL(); *log_in = val; }
        else if (!strcmp(a, "--exclude")) {
            NEEDVAL();
            /* v2 FIX: an empty pattern matches every path (strstr(x,"") != NULL) and silently disabled all scanning. */
            if (!*val) { fprintf(stderr, "--exclude needs a non-empty pattern\n"); return -1; }
            if (g_cfg.nexcludes >= RT_MAX_LIST) { fprintf(stderr, "too many --exclude\n"); return -1; }
            g_cfg.excludes[g_cfg.nexcludes++] = val;
        } else if (!strcmp(a, "--action")) {
            NEEDVAL();
            if (!strcmp(val, "report")) g_cfg.action = ACT_REPORT;
            else if (!strcmp(val, "quarantine")) g_cfg.action = ACT_QUARANTINE;
            else if (!strcmp(val, "remove")) g_cfg.action = ACT_REMOVE;
            else { fprintf(stderr, "unknown action: %s\n", val); return -1; }
        } else if (!strcmp(a, "--max-size")) {
            NEEDVAL();
            if (parse_u64(val, &v) || v == 0 || v > (1u << 20)) { fprintf(stderr, "bad --max-size\n"); return -1; }
            g_cfg.max_size = v * 1024 * 1024;
        } else if (!strcmp(a, "--debounce-ms")) {
            NEEDVAL();
            if (parse_u64(val, &v) || v > 60000) { fprintf(stderr, "bad --debounce-ms (0..60000)\n"); return -1; }
            g_cfg.debounce_ms = (unsigned)v;
        } else if (!strcmp(a, "--workers")) {
            NEEDVAL();
            if (parse_u64(val, &v) || v < 1 || v > MAX_WORKERS) { fprintf(stderr, "bad --workers (1..%d)\n", MAX_WORKERS); return -1; }
            g_cfg.workers = (int)v;
        } else if (!strcmp(a, "--verdict-ttl")) {
            NEEDVAL();
            if (parse_u64(val, &v) || v > 86400) { fprintf(stderr, "bad --verdict-ttl (0..86400)\n"); return -1; }
            g_cfg.verdict_ttl_s = (unsigned)v;
        } else if (!strcmp(a, "--sweep-interval")) {
            NEEDVAL();
            if (parse_u64(val, &v) || (v && v < 5) || v > 86400) { fprintf(stderr, "bad --sweep-interval (0 or 5..86400)\n"); return -1; }
            g_cfg.sweep_s = (unsigned)v;
        } else if (!strcmp(a, "--mode")) {
            NEEDVAL();
            if (!strcmp(val, "auto")) g_cfg.mode = RT_MODE_AUTO;
            else if (!strcmp(val, "inotify")) g_cfg.mode = RT_MODE_INOTIFY;
            else if (!strcmp(val, "fanotify")) g_cfg.mode = RT_MODE_FANOTIFY;
            else if (!strcmp(val, "etw")) g_cfg.mode = RT_MODE_ETW;
            else if (!strcmp(val, "minifilter")) g_cfg.mode = RT_MODE_MINIFILTER;
            else { fprintf(stderr, "unknown --mode %s\n", val); return -1; }
        } else if (!strcmp(a, "--block-exec")) g_cfg.block_exec = 1;
        else if (!strcmp(a, "--exec-timeout-ms")) {
            NEEDVAL();
            if (parse_u64(val, &v) || v < 100 || v > 30000) { fprintf(stderr, "bad --exec-timeout-ms (100..30000)\n"); return -1; }
            g_cfg.exec_timeout_ms = (unsigned)v;
        } else if (!strcmp(a, "--exec-fail")) {
            NEEDVAL();
            if (!strcmp(val, "closed")) g_cfg.exec_fail_closed = 1;
            else if (!strcmp(val, "open")) g_cfg.exec_fail_closed = 0;
            else { fprintf(stderr, "--exec-fail closed|open\n"); return -1; }
        } else if (!strcmp(a, "--log-format")) {
            NEEDVAL();
            if (!strcmp(val, "json")) g_cfg.log_json = 1;
            else if (!strcmp(val, "text")) g_cfg.log_json = 0;
            else { fprintf(stderr, "--log-format text|json\n"); return -1; }
        } else if (!strcmp(a, "--syslog")) g_cfg.log_syslog = 1;
        else if (!strcmp(a, "--journald")) g_cfg.log_journald = 1;
        else if (!strcmp(a, "--eventlog")) g_cfg.log_eventlog = 1;
        else if (!strcmp(a, "--metrics") || !strcmp(a, "--tui")) {
            char *colon, *hostcopy, *portcopy;
            int tui = a[2] == 't';
            NEEDVAL();
            hostcopy = strdup(val);
            if (!hostcopy) return -1;
            colon = strrchr(hostcopy, ':');
            if (colon) { *colon++ = '\0'; portcopy = strdup(colon); }
            else { portcopy = hostcopy; hostcopy = strdup("127.0.0.1"); } /* bare PORT */
            if (!portcopy || !hostcopy) return -1;
            if (!*portcopy || parse_u64(portcopy, &v) || v < 1 || v > 65535) { fprintf(stderr, "bad %s address (use [HOST:]PORT)\n", a); return -1; }
            if (!hostcopy[0]) { free(hostcopy); hostcopy = strdup("127.0.0.1"); }
            /* v4 FIX: "[::1]:9109" -- the brackets are URL syntax, getaddrinfo() rejects them (v3: IPv6 literal impossible) */
            {
                size_t hl = strlen(hostcopy);
                if (hl >= 2 && hostcopy[0] == '[' && hostcopy[hl - 1] == ']') { memmove(hostcopy, hostcopy + 1, hl - 2); hostcopy[hl - 2] = '\0'; }
            }
            if (tui) { g_tui_host = hostcopy; g_tui_port = portcopy; }
            else { g_cfg.metrics_host = hostcopy; g_cfg.metrics_port = portcopy; }
        } else if (!strcmp(a, "--tripwire")) g_cfg.tripwire = 1;
        else if (!strcmp(a, "--canary")) { g_cfg.tripwire = 1; g_cfg.trip_canary = 1; }
        else if (!strcmp(a, "--tripwire-action")) {
            NEEDVAL();
            if (!strcmp(val, "alert")) g_cfg.trip_action = RT_TRIP_ALERT;
            else if (!strcmp(val, "suspend")) g_cfg.trip_action = RT_TRIP_SUSPEND;
            else if (!strcmp(val, "kill")) g_cfg.trip_action = RT_TRIP_KILL;
            else { fprintf(stderr, "--tripwire-action alert|suspend|kill\n"); return -1; }
            g_cfg.tripwire = 1;
        } else if (!strcmp(a, "--tripwire-rate")) {
            NEEDVAL();
            if (parse_u64(val, &v) || v < 2 || v > 1000000) { fprintf(stderr, "bad --tripwire-rate\n"); return -1; }
            g_cfg.trip_rate = (unsigned)v;
        } else if (!strcmp(a, "--tripwire-window")) {
            NEEDVAL();
            if (parse_u64(val, &v) || v < 1 || v > 3600) { fprintf(stderr, "bad --tripwire-window (1..3600)\n"); return -1; }
            g_cfg.trip_window_s = (unsigned)v;
        } else if (!strcmp(a, "--tripwire-ignore-comm")) {
            NEEDVAL();
            if (!*val || g_cfg.ntrip_ignore >= RT_MAX_LIST) { fprintf(stderr, "bad --tripwire-ignore-comm\n"); return -1; }
            g_cfg.trip_ignore_comm[g_cfg.ntrip_ignore++] = val;
        } else if (!strcmp(a, "--tripwire-ignore-exe")) { /* v4 NEW */
            NEEDVAL();
            if (!*val || g_cfg.ntrip_ignore_exe >= RT_MAX_LIST) { fprintf(stderr, "bad --tripwire-ignore-exe\n"); return -1; }
            g_cfg.trip_ignore_exe[g_cfg.ntrip_ignore_exe++] = val;
            g_cfg.tripwire = 1;
        } else if (!strcmp(a, "--intel")) {
            NEEDVAL();
            if (!strcmp(val, "mb")) g_cfg.intel = RT_INTEL_MB;
            else if (!strcmp(val, "vt")) g_cfg.intel = RT_INTEL_VT;
            else { fprintf(stderr, "--intel mb|vt\n"); return -1; }
        } else if (!strcmp(a, "--intel-key-env")) { NEEDVAL(); g_cfg.intel_key_env = val; }
        else if (!strcmp(a, "--intel-url")) { NEEDVAL(); g_cfg.intel_url = val; }
        else if (!strcmp(a, "--curl")) { NEEDVAL(); g_cfg.curl_path = val; }
        else if (!strcmp(a, "--version")) {
            puts(CLAMRT_BANNER);
            exit(0);
        } else if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
            usage(stdout, argv[0]);
            exit(0);
        } else {
            fprintf(stderr, "unknown option: %s\n", a);
            usage(stderr, argv[0]);
            return -1;
        }
    }
    if (g_tui_port) return 0; /* v3 NEW: --tui needs no watch roots */
    if (nraw == 0) { fprintf(stderr, "at least one --path is required\n"); usage(stderr, argv[0]); return -1; }
    if (g_cfg.action == ACT_QUARANTINE && !*qdir_in) { fprintf(stderr, "--action quarantine needs --quarantine-dir\n"); return -1; }
#ifdef _WIN32
    if (g_cfg.sock_path) { fprintf(stderr, "--clamd-socket is not supported on Windows; use --clamd-host/--clamd-port\n"); return -1; }
#endif
    /* normalise watch roots */
    for (i = 0; i < nraw; i++) {
        char *abs = malloc(4096);
        if (!abs || plat_abspath(rawpaths[i], abs, 4096) != 0) {
            fprintf(stderr, "cannot resolve path: %s\n", rawpaths[i]);
            free(abs); /* v2 FIX: leaked on this error path (found by LeakSanitizer) */
            return -1;
        }
        for (j = 0; j < g_cfg.npaths; j++) /* v2 NEW: drop duplicate roots (one watch per directory) */
            if (same_path(g_cfg.paths[j], abs)) break;
        if (j < g_cfg.npaths) { free(abs); continue; }
        g_cfg.paths[g_cfg.npaths++] = abs;
    }
    return 0;
}

/* ------------------------------------------------------------------ main */
int main(int argc, char **argv)
{
    const char *qdir_in = NULL, *log_in = NULL;
    rt_thread workers[MAX_WORKERS], sweeper;
    int rc = 0, nworkers = 0, have_sweeper = 0, i;

    plat_args(&argc, &argv); /* v2 FIX: Windows ANSI argv -> UTF-8 (non-ASCII --path values were mangled) */
    mutex_init(&g_logmu);
    mutex_init(&g_qmu);
    mutex_init(&g_swmu);
    mutex_init(&g_aimu);
    mutex_init(&g_vcmu);
    cond_init(&g_qcv);
    cond_init(&g_swcv);

    if (parse_args(argc, argv, &qdir_in, &log_in) != 0) return 2;
    if (plat_init() != 0) { fprintf(stderr, "platform initialisation failed\n"); return 1; }
    if (g_tui_port) { /* v3 NEW: dashboard client mode */
        char addr[300];
        snprintf(addr, sizeof addr, "%s:%s", g_tui_host, g_tui_port);
        rc = rt_tui_main(addr);
        plat_cleanup();
        return rc;
    }

    if (log_in) {
        g_logf = plat_fopen_log(log_in); /* v2 FIX: O_NOFOLLOW + mode 0640 (Linux), Unicode path (Windows) */
        if (!g_logf) { fprintf(stderr, "cannot open log %s: %s\n", log_in, strerror(errno)); return 1; }
        g_logpath = log_in;
    }
    if (qdir_in) {
        char *q = malloc(4096);
        if (!q || plat_prepare_dir(qdir_in, q, 4096) != 0) {
            rt_log(RT_LOG_ERR, "cannot create/resolve a private quarantine dir at %s", qdir_in);
            return 1;
        }
        g_cfg.qdir = q;
    }

    if (g_cfg.block_exec && g_cfg.mode == RT_MODE_INOTIFY) {
        rt_log(RT_LOG_ERR, "--block-exec needs --mode fanotify (or auto) -- inotify cannot block");
        return 2;
    }
    if (g_cfg.exec_fail_closed && !g_cfg.block_exec) rt_log(RT_LOG_WARN, "--exec-fail has no effect without --block-exec");
    if (g_cfg.exec_fail_closed && g_cfg.block_exec)
        rt_log(RT_LOG_WARN, "fail-closed: while clamd is unavailable EVERY program under the watched roots is denied execution after %u ms "
                            "-- do not watch / or your own login shell's directories this way", g_cfg.exec_timeout_ms);
    rt_log(RT_LOG_INFO, CLAMRT_BANNER " starting; action=%s, %d root(s), debounce=%ums",
           g_cfg.action == ACT_REPORT ? "report" : g_cfg.action == ACT_QUARANTINE ? "quarantine" : "remove",
           g_cfg.npaths, g_cfg.debounce_ms);
    if (!clamd_ping())
        rt_log(RT_LOG_WARN, "clamd is not answering yet; scans will be retried with backoff");

    if (g_cfg.tripwire && rt_trip_init() != 0) return 1;            /* v3 NEW: canaries + heuristic state */
    if (g_cfg.metrics_port && rt_metrics_start() != 0) return 1;     /* v3 NEW */
    if (g_cfg.intel != RT_INTEL_NONE && rt_intel_start() != 0) return 1;

    for (i = 0; i < g_cfg.workers; i++) { /* v3 NEW: worker pool (v2 had exactly one) */
        if (thread_start(&workers[nworkers], worker_main, NULL) != 0) {
            rt_log(RT_LOG_ERR, "cannot start worker thread %d", i);
            break;
        }
        nworkers++;
    }
    if (nworkers == 0) return 1;
    if (g_cfg.sweep_s && thread_start(&sweeper, sweeper_main, NULL) == 0) have_sweeper = 1;

    rc = plat_watch_run();

    RT_REQUEST_STOP();
    mutex_lock(&g_qmu);
    cond_broadcast(&g_qcv); /* v4 FIX: wake EVERY worker (v3 woke one; the rest noticed g_stop within their 1 s slice) */
    mutex_unlock(&g_qmu);
    mutex_lock(&g_swmu);
    cond_broadcast(&g_swcv);
    mutex_unlock(&g_swmu);
    for (i = 0; i < nworkers; i++) thread_join(workers[i]);
    if (have_sweeper) thread_join(sweeper);
    rt_metrics_stop();
    rt_intel_stop();
    rt_trip_cleanup();

    rt_log(RT_LOG_INFO,
           "stopping: scanned=%llu clean=%llu infected=%llu skipped=%llu errors=%llu dropped=%llu overflows=%llu action_failures=%llu exec_checked=%llu exec_denied=%llu tripwire_alerts=%llu pending=%u",
           (unsigned long long)RT_GET(scanned), (unsigned long long)RT_GET(clean), (unsigned long long)RT_GET(infected),
           (unsigned long long)RT_GET(skipped), (unsigned long long)RT_GET(errors), (unsigned long long)RT_GET(dropped),
           (unsigned long long)RT_GET(overflows), (unsigned long long)RT_GET(actions_failed),
           (unsigned long long)RT_GET(exec_checked), (unsigned long long)RT_GET(exec_denied),
           (unsigned long long)RT_GET(tripwire_alerts), g_count);
    if (g_ai) freeaddrinfo(g_ai);
    plat_cleanup();
    if (g_logf) fclose(g_logf);
    return rc ? 1 : 0;
}
