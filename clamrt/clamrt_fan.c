/*
 * clamrt_fan.c -- clamrt v3 NEW (v4 revised): Linux fanotify back-end.
 *
 * What it adds over inotify (clamrt_linux.c):
 *   - mount-wide marks: no per-directory watches, so no fs.inotify.max_user_watches limit, no recursion races, no
 *     "directory created after listing" gap, and a queue that is not lost (FAN_UNLIMITED_QUEUE);
 *   - the originating PID of every event (feeds the ransomware tripwire);
 *   - FAN_OPEN_EXEC_PERM: the kernel holds execve()/mmap(PROT_EXEC) of a file until we answer, so an infected
 *     binary can be DENIED before it runs (--block-exec).  Verdicts come from the same clamd scan, are cached by
 *     file state (verdict cache in the core) and have a hard deadline (--exec-timeout-ms, fail-open by default).
 * Needs CAP_SYS_ADMIN (run as root).  --mode auto only selects it when --block-exec is given.
 *
 * v4 FIX: the event-reading thread must NEVER do slow work, because every execve() on the marked mount is parked in the
 * kernel until it has answered.  v3 ran the start-up walk (--scan-existing) and the overflow re-scan on that thread, so
 * on a big tree every program on the mount (including login shells) hung until the walk finished.  Walks now run on a
 * separate sweep thread; execs outside the watch roots are answered by the reading thread itself (no thread hand-off).
 *
 * Not covered: files that appear without a write-close (hard links, rename-in).  Use --sweep-interval to catch
 * them (the sweep looks at ctime as well as mtime).
 */
#define _GNU_SOURCE
#include "clamrt.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef FAN_OPEN_EXEC_PERM
#define FAN_OPEN_EXEC_PERM 0x00040000
#endif
#ifndef FAN_UNLIMITED_QUEUE
#define FAN_UNLIMITED_QUEUE 0x10
#define FAN_UNLIMITED_MARKS 0x20
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define JOBQ 512

typedef struct { int fd; long pid; char *path; } job; /* v4: path resolved once by the reader thread */

static int g_ffd = -1;
static job g_jobs[JOBQ];
static unsigned g_jh, g_jt, g_jn;
static pthread_mutex_t g_jmu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_jcv = PTHREAD_COND_INITIALIZER;
static int g_jstop;

int plat_fan_available(void)
{
    int fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF, O_RDONLY | O_LARGEFILE);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

static void respond(int fd, unsigned allow)
{
    struct fanotify_response r;
    r.fd = fd;
    r.response = allow ? FAN_ALLOW : FAN_DENY;
    while (write(g_ffd, &r, sizeof r) < 0 && errno == EINTR) {}
}

static int fd_path(int fd, char *out, size_t outsz)
{
    char link[64];
    ssize_t n;
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    n = readlink(link, out, outsz - 1);
    if (n <= 0) return -1;
    out[n] = '\0';
    if (n > 10 && strcmp(out + n - 10, " (deleted)") == 0) return -1; /* unlinked while we looked */
    return 0;
}

/* Mount marks deliver events for the WHOLE mount: keep only paths inside a watch root (and, with --no-recursive,
 * only direct children of a root). */
static int under_root(const char *path)
{
    int i;
    for (i = 0; i < g_cfg.npaths; i++) {
        size_t rl = strlen(g_cfg.paths[i]);
        if (!plat_str_prefix(path, g_cfg.paths[i])) continue;
        if (!g_cfg.recursive) {
            const char *rest = path + rl;
            while (*rest == '/') rest++;
            if (strchr(rest, '/')) continue; /* deeper than one level */
        }
        return 1;
    }
    return 0;
}

/* One blocked execution: scan with a deadline and answer the kernel.  ALWAYS responds, ownership of the fd ends here. */
static void exec_verdict(job *j)
{
    const char *path = j->path; /* v4: resolved + scope-checked by the reader thread */
    char sig[1024];
    struct stat st;
    rt_fh fh;
    int allow = 1, r, responded = 0;

    sig[0] = '\0';
    if (fstat(j->fd, &st) != 0 || !S_ISREG(st.st_mode)) goto done;
    memset(&fh, 0, sizeof fh);
    fh.fd = j->fd;
    fh.size = (uint64_t)st.st_size;
    fh.dev = st.st_dev;
    fh.ino = st.st_ino;
    fh.mtime = ((uint64_t)st.st_mtim.tv_sec * 1000000000ull + (uint64_t)st.st_mtim.tv_nsec) * 1099511628211ull ^
               ((uint64_t)st.st_ctim.tv_sec * 1000000000ull + (uint64_t)st.st_ctim.tv_nsec); /* same stamp as plat_open() */
    RT_INC(exec_checked);
    r = rt_scan_for_exec(&fh, path, plat_now_ms() + g_cfg.exec_timeout_ms, sig, sizeof sig);
    if (r == RT_SR_INFECTED) {
        allow = 0;
        RT_INC(exec_denied);
        respond(j->fd, 0); /* answer the kernel FIRST: hashing a large binary for the log must not delay the denial */
        responded = 1;
        rt_detected(path, sig, &fh, j->pid, "exec-block");
        if (g_cfg.action != ACT_REPORT) rt_requeue(path); /* v4: normal pipeline quarantines / removes it (v3: rt_emit_pid also fed it to the tripwire) */
    } else if (r == RT_SR_ERROR) {
        allow = !g_cfg.exec_fail_closed;
        if (!RT_STOPPING())
            rt_log(RT_LOG_WARN, "exec verdict unavailable for %s (timeout or clamd error): %s", path, allow ? "ALLOWED (fail-open)" : "DENIED (fail-closed)");
    }
done:
    if (!responded) respond(j->fd, (unsigned)allow);
    close(j->fd);
    free(j->path);
}

static void *exec_worker(void *arg)
{
    (void)arg;
    for (;;) {
        job j;
        pthread_mutex_lock(&g_jmu);
        while (!g_jn && !g_jstop) pthread_cond_wait(&g_jcv, &g_jmu);
        if (!g_jn) { pthread_mutex_unlock(&g_jmu); break; } /* stopping and drained */
        j = g_jobs[g_jh];
        g_jh = (g_jh + 1) % JOBQ;
        g_jn--;
        pthread_mutex_unlock(&g_jmu);
        if (RT_STOPPING()) { respond(j.fd, 1); close(j.fd); free(j.path); continue; } /* shutting down: never leave a process hanging */
        exec_verdict(&j);
    }
    return NULL;
}

static int enqueue_job(int fd, long pid, char *path)
{
    int ok = 0;
    pthread_mutex_lock(&g_jmu);
    if (g_jn < JOBQ) {
        g_jobs[g_jt].fd = fd;
        g_jobs[g_jt].pid = pid;
        g_jobs[g_jt].path = path;
        g_jt = (g_jt + 1) % JOBQ;
        g_jn++;
        ok = 1;
        pthread_cond_signal(&g_jcv);
    }
    pthread_mutex_unlock(&g_jmu);
    return ok;
}

/* ---- v4 NEW: sweep thread.  Requests coalesce (the earliest "since" wins). */
static pthread_t g_swth;
static int g_sw_started, g_sw_stop;
static long long g_sw_req = -1;
static pthread_mutex_t g_swmu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_swcv = PTHREAD_COND_INITIALIZER;

static void sweep_request(long long since)
{
    pthread_mutex_lock(&g_swmu);
    if (g_sw_req < 0 || since < g_sw_req) g_sw_req = since;
    pthread_cond_signal(&g_swcv);
    pthread_mutex_unlock(&g_swmu);
}

static void *sweep_thread(void *arg)
{
    (void)arg;
    for (;;) {
        long long since;
        pthread_mutex_lock(&g_swmu);
        while (g_sw_req < 0 && !g_sw_stop) pthread_cond_wait(&g_swcv, &g_swmu);
        if (g_sw_stop) { pthread_mutex_unlock(&g_swmu); break; }
        since = g_sw_req;
        g_sw_req = -1;
        pthread_mutex_unlock(&g_swmu);
        plat_sweep(since); /* returns early once RT_STOPPING() */
    }
    return NULL;
}

int plat_fan_run(void)
{
    static char buf[256 * 1024] __attribute__((aligned(8)));
    pthread_t th[8];
    int nth = 0, i, rc = 0, ncan;
    unsigned init_flags = FAN_CLOEXEC | FAN_NONBLOCK | (g_cfg.block_exec ? FAN_CLASS_CONTENT : FAN_CLASS_NOTIF);
    uint64_t mask = FAN_CLOSE_WRITE | (g_cfg.block_exec ? FAN_OPEN_EXEC_PERM : 0);
    struct pollfd pfd;
    pid_t self = getpid();

    g_ffd = fanotify_init(init_flags | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (g_ffd < 0 && (errno == EINVAL || errno == EPERM)) /* no unlimited flags without CAP_SYS_ADMIN */
        g_ffd = fanotify_init(init_flags, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (g_ffd < 0) {
        rt_log(RT_LOG_ERR, "fanotify_init: %s (needs root / CAP_SYS_ADMIN%s)", strerror(errno),
               g_cfg.block_exec ? "; --block-exec cannot work without it" : "; use --mode inotify");
        return 1;
    }
    for (i = 0; i < g_cfg.npaths; i++) {
        if (fanotify_mark(g_ffd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, g_cfg.paths[i]) != 0) {
            rt_log(RT_LOG_ERR, "fanotify_mark(%s): %s", g_cfg.paths[i], strerror(errno));
            close(g_ffd);
            return 1;
        }
    }
    /* Canary files get an extra inode mark for FAN_MODIFY: we learn WHO writes them at the first write(), not at close. */
    ncan = g_cfg.tripwire ? rt_trip_canary_count() : 0;
    for (i = 0; i < ncan; i++)
        if (fanotify_mark(g_ffd, FAN_MARK_ADD, FAN_MODIFY, AT_FDCWD, rt_trip_canary_path(i)) != 0)
            rt_log(RT_LOG_WARN, "cannot mark canary %s: %s", rt_trip_canary_path(i), strerror(errno));

    if (g_cfg.block_exec) {
        int want = g_cfg.workers + 2;
        for (i = 0; i < want && i < 8; i++)
            if (pthread_create(&th[nth], NULL, exec_worker, NULL) == 0) nth++;
        if (nth == 0) { rt_log(RT_LOG_ERR, "cannot start exec-verdict threads"); close(g_ffd); return 1; }
    }
    rt_log(RT_LOG_INFO, "watching %d root(s) with fanotify (mount-wide%s%s)", g_cfg.npaths,
           g_cfg.block_exec ? ", BLOCKING executions of infected files" : "", ncan ? ", canary marks" : "");
    if (pthread_create(&g_swth, NULL, sweep_thread, NULL) == 0) g_sw_started = 1;
    else rt_log(RT_LOG_WARN, "cannot start the sweep thread: --scan-existing and overflow re-scans are disabled");
    if (g_cfg.scan_existing && g_sw_started) sweep_request(0); /* v4 FIX: was plat_sweep(0) on this thread: every exec on the mount hung meanwhile */

    pfd.fd = g_ffd;
    pfd.events = POLLIN;
    while (!RT_STOPPING()) {
        ssize_t n;
        struct fanotify_event_metadata *ev;
        int r = poll(&pfd, 1, 1000);
        if (r < 0) {
            if (errno == EINTR) continue;
            rt_log(RT_LOG_ERR, "poll(fanotify): %s", strerror(errno));
            rc = 1;
            break;
        }
        if (r == 0) continue;
        n = read(g_ffd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            rt_log(RT_LOG_ERR, "read(fanotify): %s", strerror(errno));
            rc = 1;
            break;
        }
        for (ev = (struct fanotify_event_metadata *)buf; FAN_EVENT_OK(ev, n); ev = FAN_EVENT_NEXT(ev, n)) {
            char path[PATH_MAX];
            if (ev->vers != FANOTIFY_METADATA_VERSION) { rt_log(RT_LOG_ERR, "fanotify metadata version mismatch"); rc = 1; goto out; }
            if (ev->mask & FAN_Q_OVERFLOW) {
                rt_note_overflow();
                if (g_sw_started) sweep_request((long long)time(NULL) - RT_OVERFLOW_RESCAN_WINDOW_S); /* v4 FIX: off the reader thread */
                continue;
            }
            if (ev->fd < 0) continue;
            if (ev->mask & FAN_OPEN_EXEC_PERM) {
                /* v4: scope check HERE (one readlink): the mount mark delivers every exec on the mount, and most are
                 * outside the watch roots -- answer those immediately instead of paying a queue + thread hand-off. */
                char *dup = NULL;
                if (ev->pid == self || fd_path(ev->fd, path, sizeof path) != 0 || !under_root(path) || rt_excluded(path)) {
                    respond(ev->fd, 1u);
                    close(ev->fd);
                    continue;
                }
                dup = strdup(path);
                if (!dup || !enqueue_job(ev->fd, ev->pid, dup)) {
                    /* out of memory or the queue is full: answer now, per policy */
                    free(dup);
                    respond(ev->fd, (unsigned)!g_cfg.exec_fail_closed);
                    close(ev->fd);
                }
                continue; /* ownership of the fd and the path passed to the worker */
            }
            if (ev->pid != self && fd_path(ev->fd, path, sizeof path) == 0) {
                /* v4 FIX: events can be MERGED (FAN_MODIFY|FAN_CLOSE_WRITE on a canary); v3's else-if dropped the close-write half */
                if ((ev->mask & FAN_MODIFY) && g_cfg.tripwire && rt_trip_is_canary(path)) rt_trip_canary_event(path, ev->pid, "written");
                if ((ev->mask & FAN_CLOSE_WRITE) && under_root(path)) rt_emit_pid(path, ev->pid);
            }
            close(ev->fd);
        }
    }
out:
    if (rc) RT_REQUEST_STOP(); /* error exit: make the sweep thread and workers wind down too */
    pthread_mutex_lock(&g_swmu);
    g_sw_stop = 1;
    pthread_cond_broadcast(&g_swcv);
    pthread_mutex_unlock(&g_swmu);
    if (g_sw_started) { pthread_join(g_swth, NULL); g_sw_started = 0; }
    pthread_mutex_lock(&g_jmu);
    g_jstop = 1; /* workers answer every queued permission event with ALLOW, then exit */
    pthread_cond_broadcast(&g_jcv);
    pthread_mutex_unlock(&g_jmu);
    for (i = 0; i < nth; i++) pthread_join(th[i], NULL);
    close(g_ffd); /* the kernel auto-allows anything still pending */
    g_ffd = -1;
    return rc;
}
