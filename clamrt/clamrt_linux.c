/*
 * clamrt_linux.c -- clamrt v4 Linux back-end (inotify; fanotify lives in clamrt_fan.c, helpers in clamrt_linux_ext.c).
 *
 * Why inotify rather than fanotify: it needs no privileges and works on any
 * filesystem the user can read.  It reports files AFTER they were closed for
 * writing (IN_CLOSE_WRITE), created (IN_CREATE) or moved in (IN_MOVED_TO),
 * i.e. "scan on write", not "block on open".  For blocking on-access scanning
 * use clamonacc (fanotify), which ships with ClamAV.
 *
 * Recursion: every directory gets its own watch.  New directories are watched
 * BEFORE they are listed, so files created in the race window are not missed.
 *
 * v2 FIX / v2 NEW comments mark changes relative to v1; v3 NEW / v3 FIX relative to v2.
 */
#define _GNU_SOURCE
#include "clamrt.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAX_WALK_DEPTH 128
#define WD_BUCKETS 4096u

static int g_ifd = -1;

/* ================================================================ safe path access (v2 NEW)
 * v1 opened the final path component with O_NOFOLLOW but followed symlinks in the PARENT
 * directories, so a directory swapped for a symlink between the event and the scan made clamrt
 * scan -- and, on a detection, quarantine/delete -- a file outside the watched tree.
 * v2 resolves the parent directory with NO symlink in any component (openat2 RESOLVE_NO_SYMLINKS
 * when the kernel has it, an openat(O_NOFOLLOW) component walk otherwise) and performs every
 * operation relative to that directory fd (openat/fstatat/linkat/unlinkat). */
struct rt_open_how { uint64_t flags, mode, resolve; };
#define RT_RESOLVE_NO_MAGICLINKS 0x02
#define RT_RESOLVE_NO_SYMLINKS 0x04
#ifndef SYS_openat2
#define SYS_openat2 437 /* same number on every architecture */
#endif
static int g_openat2_ok = 1; /* cleared on ENOSYS / seccomp refusal */

static int open_dir_nosymlinks(const char *dir)
{
    int cur, next;
    const char *p;
    char comp[NAME_MAX + 1];
    int ncomp = 0;

    if (dir[0] != '/') { errno = EINVAL; return -1; }
    if (g_openat2_ok) {
        struct rt_open_how how;
        long fd;
        memset(&how, 0, sizeof how);
        how.flags   = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
        how.resolve = RT_RESOLVE_NO_SYMLINKS | RT_RESOLVE_NO_MAGICLINKS;
        fd = syscall(SYS_openat2, AT_FDCWD, dir, &how, sizeof how);
        if (fd >= 0) return (int)fd;
        if (errno != ENOSYS && errno != EPERM && errno != EINVAL) return -1; /* real error (ENOENT, ELOOP ...) */
        g_openat2_ok = 0; /* fall through to the portable walk */
    }
    cur = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cur < 0) return -1;
    p = dir;
    while (*p) {
        size_t n = 0;
        while (*p == '/') p++;
        if (!*p) break;
        while (p[n] && p[n] != '/') n++;
        if (n > NAME_MAX || ++ncomp > 512 || (n == 2 && p[0] == '.' && p[1] == '.')) { close(cur); errno = EINVAL; return -1; }
        if (!(n == 1 && p[0] == '.')) {
            memcpy(comp, p, n);
            comp[n] = '\0';
            next = openat(cur, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            close(cur);
            if (next < 0) return -1;
            cur = next;
        }
        p += n;
    }
    return cur;
}

/* Splits an absolute path into an fd for its (symlink-free) parent directory and the final name. */
static int open_parent(const char *path, char *name, size_t namesz)
{
    char dir[PATH_MAX];
    const char *slash = strrchr(path, '/');
    size_t dl, nl;
    if (!slash || slash[1] == '\0') { errno = EINVAL; return -1; }
    nl = strlen(slash + 1);
    dl = (size_t)(slash - path);
    if (nl >= namesz || dl >= sizeof dir || !strcmp(slash + 1, ".") || !strcmp(slash + 1, "..")) { errno = EINVAL; return -1; }
    memcpy(dir, path, dl);
    dir[dl] = '\0';
    if (dl == 0) strcpy(dir, "/");
    strcpy(name, slash + 1);
    return open_dir_nosymlinks(dir);
}

/* ---------------------------------------------------------------- wd -> path map */
typedef struct wdent {
    struct wdent *next;
    int wd;
    char *path;
} wdent;
static wdent *g_wd[WD_BUCKETS];

static wdent *wd_find(int wd)
{
    wdent *e;
    for (e = g_wd[(unsigned)wd & (WD_BUCKETS - 1)]; e; e = e->next)
        if (e->wd == wd) return e;
    return NULL;
}

static void wd_set(int wd, const char *path)
{
    wdent *e = wd_find(wd);
    char *dup = strdup(path);
    if (!dup) return;
    if (e) { /* same inode re-added under a new name (rename): update path */
        free(e->path);
        e->path = dup;
        return;
    }
    e = malloc(sizeof *e);
    if (!e) { free(dup); return; }
    e->wd   = wd;
    e->path = dup;
    e->next = g_wd[(unsigned)wd & (WD_BUCKETS - 1)];
    g_wd[(unsigned)wd & (WD_BUCKETS - 1)] = e;
}

static void wd_del(int wd)
{
    wdent **pp = &g_wd[(unsigned)wd & (WD_BUCKETS - 1)];
    while (*pp) {
        if ((*pp)->wd == wd) {
            wdent *d = *pp;
            *pp = d->next;
            free(d->path);
            free(d);
            return;
        }
        pp = &(*pp)->next;
    }
}

/* Remove watches of a directory that was moved/renamed away, plus its subtree. */
static void drop_subtree(const char *prefix)
{
    size_t pl = strlen(prefix);
    unsigned b;
    for (b = 0; b < WD_BUCKETS; b++) {
        wdent *e = g_wd[b], *nx;
        for (; e; e = nx) {
            nx = e->next;
            if (strncmp(e->path, prefix, pl) == 0 && (e->path[pl] == '\0' || e->path[pl] == '/')) {
                int wd = e->wd;
                inotify_rm_watch(g_ifd, wd);
                wd_del(wd); /* may free e; nx was saved */
            }
        }
    }
}

/* v2 NEW: IN_CREATE is now handled for non-directories too -- hard links (`ln /elsewhere/evil dir/x`)
 * and O_TMPFILE+linkat() produce no IN_CLOSE_WRITE, so v1 never scanned them. */
/* v3 NEW: IN_DELETE so that deletion of a ransomware canary file is noticed. */
#define WATCH_MASK (IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_CREATE | IN_DELETE | IN_ONLYDIR | IN_EXCL_UNLINK)

static int add_watch(const char *dir)
{
    static int warned_nospc; /* v2 FIX: v1 logged one line per directory once the limit was hit (log flood) */
    int wd = inotify_add_watch(g_ifd, dir, WATCH_MASK);
    if (wd < 0) {
        if (errno == ENOSPC) {
            if (!warned_nospc) {
                warned_nospc = 1;
                rt_log(RT_LOG_ERR, "inotify watch limit reached at %s: part of the tree is NOT watched "
                                   "(raise fs.inotify.max_user_watches)", dir);
            }
        } else if (errno != ENOENT && errno != ENOTDIR) {
            rt_log(RT_LOG_WARN, "cannot watch %s: %s", dir, strerror(errno));
        }
        return -1;
    }
    wd_set(wd, dir);
    return 0;
}

/* v2 NEW: walk modes (v1 could only scan "all" or "none") */
enum { WALK_NONE = 0, WALK_ALL = 1, WALK_RECENT = 2 };

/* Watch `dir` (first!) and then list it, recursing into sub-directories.
 * Returns the number of directories successfully watched (v2 FIX: v1 returned nothing, so a start-up in which
 * every watch failed still reported "watching N root(s)" and then idled forever). */
static int walk(const char *dir, int mode, time_t since, int depth)
{
    DIR *d;
    struct dirent *de;
    char path[PATH_MAX];
    int watched = 0;

    if (depth > MAX_WALK_DEPTH) {
        rt_log(RT_LOG_WARN, "directory nesting too deep, not descending: %s", dir);
        return 0;
    }
    if (rt_excluded(dir)) return 0;
    if (add_watch(dir) != 0) return 0;
    watched = 1;
    d = opendir(dir);
    if (!d) return watched;
    while ((de = readdir(d)) != NULL) {
        unsigned char t = de->d_type;
        int n;
        struct stat st;
        int have_st = 0;
        if (de->d_name[0] == '.' && (de->d_name[1] == '\0' || (de->d_name[1] == '.' && de->d_name[2] == '\0'))) continue;
        n = snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        if (n < 0 || (size_t)n >= sizeof path) continue;
        if (t == DT_UNKNOWN || (t == DT_REG && mode == WALK_RECENT)) {
            if (lstat(path, &st) != 0) continue;
            have_st = 1;
            t = S_ISDIR(st.st_mode) ? DT_DIR : S_ISREG(st.st_mode) ? DT_REG : DT_UNKNOWN;
        }
        if (t == DT_DIR) {
            if (g_cfg.recursive) watched += walk(path, mode, since, depth + 1);
        } else if (t == DT_REG && mode != WALK_NONE) {
            if (mode == WALK_ALL || (have_st && st.st_mtime >= since)) rt_emit(path);
        }
        /* symlinks and special files are deliberately ignored */
    }
    closedir(d);
    return watched;
}

/* ---------------------------------------------------------------- signals / logging */
static volatile sig_atomic_t g_reopen;

static void on_signal(int sig)
{
    int saved = errno; /* v2 FIX: a handler must not clobber errno of the interrupted code (TSan: "spoils errno") */
    if (sig == SIGHUP) __atomic_store_n(&g_reopen, 1, __ATOMIC_RELAXED); /* v2 NEW: logrotate */
    else RT_REQUEST_STOP();
    errno = saved;
}

int plat_take_log_reopen(void)
{
    return __atomic_exchange_n(&g_reopen, 0, __ATOMIC_RELAXED) ? 1 : 0; /* v2 FIX: atomic test-and-clear */
}

int plat_init(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal; /* no SA_RESTART: poll() must return EINTR */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL); /* v2 FIX: v1 died on SIGHUP (terminal closed / logrotate postrotate) */
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

void plat_cleanup(void)
{
    if (g_ifd >= 0) close(g_ifd);
}

void plat_args(int *argc, char ***argv) { (void)argc; (void)argv; } /* v2 NEW: nothing to do on Linux */

FILE *plat_fopen_log(const char *path)
{
    /* v2 FIX: v1 used fopen(path,"a"): follows a symlink planted at the log path (as root: arbitrary file append)
     * and creates the log world-readable although it lists file names. */
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0640);
    FILE *f;
    if (fd < 0) return NULL;
    f = fdopen(fd, "a");
    if (!f) close(fd);
    return f;
}

uint64_t plat_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ---------------------------------------------------------------- watcher loop */
int plat_watch_run(void)
{
    int i, watched = 0;
    struct pollfd pfd;
    static char buf[64 * 1024] __attribute__((aligned(__alignof__(struct inotify_event))));
    int need_rescan = 0;
    time_t last_rescan = 0;

    /* v3 NEW: backend selection.  auto = inotify (unprivileged, unchanged v2 behaviour) unless --block-exec is
     * requested, which only fanotify can do. */
    /* v4 FIX: auto also picks fanotify when the tripwire is asked to suspend/kill a process -- only fanotify knows WHICH
     * process wrote a file.  v3's auto chose inotify and the action could never fire (it just logged "pid unknown").
     * Falls back to inotify (alert-only) with a warning when fanotify is unavailable. */
    if (g_cfg.mode == RT_MODE_AUTO && !g_cfg.block_exec && g_cfg.tripwire && g_cfg.trip_action != RT_TRIP_ALERT) {
        if (plat_fan_available()) {
            rt_log(RT_LOG_INFO, "tripwire action needs the writing process: using fanotify mode");
            return plat_fan_run();
        }
        rt_log(RT_LOG_WARN, "fanotify unavailable (not root?): tripwire stays alert-only, it cannot suspend/kill without the writer's pid");
    }
    if (g_cfg.mode == RT_MODE_FANOTIFY || (g_cfg.mode == RT_MODE_AUTO && g_cfg.block_exec)) return plat_fan_run();
    if (g_cfg.mode == RT_MODE_ETW || g_cfg.mode == RT_MODE_MINIFILTER) {
        rt_log(RT_LOG_ERR, "--mode etw/minifilter exist on Windows only");
        return 1;
    }

    g_ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (g_ifd < 0) {
        rt_log(RT_LOG_ERR, "inotify_init1: %s", strerror(errno));
        return 1;
    }
    for (i = 0; i < g_cfg.npaths; i++) {
        int w = walk(g_cfg.paths[i], g_cfg.scan_existing ? WALK_ALL : WALK_NONE, 0, 0);
        if (w == 0) rt_log(RT_LOG_ERR, "cannot watch root %s", g_cfg.paths[i]); /* v2 FIX: no more silent "watching" lie */
        watched += w ? 1 : 0;
    }
    if (watched == 0) {
        rt_log(RT_LOG_ERR, "no watch root could be watched; exiting");
        return 1;
    }
    rt_log(RT_LOG_INFO, "watching %d root(s) with inotify", watched);

    pfd.fd     = g_ifd;
    pfd.events = POLLIN;
    while (!RT_STOPPING()) {
        ssize_t n;
        char *p;
        int r;

        /* v2 FIX: after an overflow v1 only logged a warning, silently losing every file written meanwhile
         * (reproduced: 100 infected files created during an overflow, 8 reported) and never watching
         * directories created meanwhile.  Re-walk the roots: re-adds missing watches and re-queues recent files. */
        if (need_rescan && time(NULL) != last_rescan) {
            time_t since = time(NULL) - RT_OVERFLOW_RESCAN_WINDOW_S;
            need_rescan = 0;
            last_rescan = time(NULL);
            for (i = 0; i < g_cfg.npaths; i++) walk(g_cfg.paths[i], WALK_RECENT, since, 0);
        }

        r = poll(&pfd, 1, need_rescan ? 200 : 1000);
        if (r < 0) {
            if (errno == EINTR) continue;
            rt_log(RT_LOG_ERR, "poll: %s", strerror(errno));
            return 1;
        }
        if (r == 0) continue;
        n = read(g_ifd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            rt_log(RT_LOG_ERR, "read(inotify): %s", strerror(errno));
            return 1;
        }
        for (p = buf; p + sizeof(struct inotify_event) <= buf + n;) {
            struct inotify_event *ev = (struct inotify_event *)p;
            wdent *w;
            char full[PATH_MAX];
            int len;
            if (p + sizeof *ev + ev->len > buf + n) break; /* v2 NEW: never trust a length field beyond the buffer */
            p += sizeof *ev + ev->len;

            if (ev->mask & IN_Q_OVERFLOW) {
                rt_note_overflow();
                need_rescan = 1;
                continue;
            }
            if (ev->mask & IN_IGNORED) { /* watch removed (directory deleted) */
                /* v4 NEW: say so when a watch ROOT disappears (v3 went silent and kept "watching" nothing) */
                wdent *gone = wd_find(ev->wd);
                if (gone) {
                    int k;
                    for (k = 0; k < g_cfg.npaths; k++)
                        if (strcmp(gone->path, g_cfg.paths[k]) == 0) rt_log(RT_LOG_ERR, "watch root %s was deleted or unmounted: it is NO LONGER WATCHED", gone->path);
                }
                wd_del(ev->wd);
                continue;
            }
            if (ev->len == 0 || !(w = wd_find(ev->wd))) continue;
            len = snprintf(full, sizeof full, "%s/%s", w->path, ev->name);
            if (len < 0 || (size_t)len >= sizeof full) continue;

            if (ev->mask & IN_ISDIR) {
                if (!g_cfg.recursive) continue;
                if (ev->mask & (IN_CREATE | IN_MOVED_TO)) walk(full, WALK_ALL, 0, 0);
                else if (ev->mask & IN_MOVED_FROM) drop_subtree(full);
            } else if (ev->mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE)) {
                rt_emit(full);
            } else if ((ev->mask & (IN_DELETE | IN_MOVED_FROM)) && g_cfg.tripwire && rt_trip_is_canary(full)) {
                rt_trip_canary_event(full, 0, "deleted"); /* v3 NEW: inotify cannot tell who; fanotify mode can */
            }
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- paths / strings */
int plat_abspath(const char *in, char *out, size_t outsz)
{
    char tmp[PATH_MAX];
    if (!realpath(in, tmp) || strlen(tmp) >= outsz) return -1;
    strcpy(out, tmp);
    return 0;
}

/* v2 FIX: v1 accepted any pre-existing directory.  A world-writable (or foreign-owned) quarantine directory lets
 * another user replace quarantined malware, plant files that get restored, or race the move.  Now the directory must
 * be a real directory (no symlink), owned by the effective user, with no group/other write bits. */
int plat_prepare_dir(const char *in, char *out, size_t outsz)
{
    struct stat st;
    int fd;
    if (mkdir(in, 0700) != 0 && errno != EEXIST) return -1;
    if (plat_abspath(in, out, outsz) != 0) return -1;
    fd = open(out, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || st.st_uid != geteuid() || (st.st_mode & 022) != 0) {
        rt_log(RT_LOG_ERR, "quarantine dir %s must be owned by uid %u and not group/world-writable (mode is %o)", out,
               (unsigned)geteuid(), (unsigned)(st.st_mode & 07777));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int plat_str_prefix(const char *s, const char *prefix)
{
    size_t pl = strlen(prefix);
    return strncmp(s, prefix, pl) == 0 && (s[pl] == '\0' || s[pl] == '/' || (pl && prefix[pl - 1] == '/'));
}

int plat_str_contains(const char *hay, const char *needle)
{
    return strstr(hay, needle) != NULL;
}

/* ---------------------------------------------------------------- file access */
int plat_open(const char *path, rt_fh *fh)
{
    struct stat st;
    char name[NAME_MAX + 1];
    int fd, pfd = open_parent(path, name, sizeof name); /* v2 FIX: parent resolved without symlinks */
    if (pfd < 0) {
        switch (errno) {
            case ENOENT: case ENOTDIR: case ELOOP: case EINVAL: case EXDEV: return RT_SKIP;
            case EACCES: case EPERM: return RT_DENIED;
            default: return RT_ERR;
        }
    }
    /* O_NOFOLLOW: never scan through a symlink; O_NONBLOCK: a FIFO swapped in cannot hang us. */
    fd = openat(pfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
    close(pfd);
    if (fd < 0) {
        switch (errno) {
            case ENOENT: case ENOTDIR: case ELOOP: case ENXIO: case EISDIR: return RT_SKIP;
            case EACCES: case EPERM: return RT_DENIED;
            default: return RT_ERR;
        }
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return RT_SKIP;
    }
    (void)posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL); /* v2 NEW: doubles kernel read-ahead for the streaming read */
    fh->fd   = fd;
    fh->size = (uint64_t)st.st_size;
    fh->dev  = st.st_dev;
    fh->ino  = st.st_ino;
    /* v3 NEW: change stamp for the verdict cache: mtime AND ctime (ctime cannot be forged from user space) */
    fh->mtime = ((uint64_t)st.st_mtim.tv_sec * 1000000000ull + (uint64_t)st.st_mtim.tv_nsec) * 1099511628211ull ^
                ((uint64_t)st.st_ctim.tv_sec * 1000000000ull + (uint64_t)st.st_ctim.tv_nsec);
    return RT_OK;
}

long plat_read(rt_fh *fh, void *buf, size_t n)
{
    for (;;) {
        ssize_t r = read(fh->fd, buf, n);
        if (r < 0 && errno == EINTR) continue;
        return (long)r;
    }
}

int plat_rewind(rt_fh *fh) { return lseek(fh->fd, 0, SEEK_SET) == 0 ? 0 : -1; } /* v3 NEW */

void plat_close(rt_fh *fh)
{
    if (fh->fd >= 0) close(fh->fd);
    fh->fd = -1;
}

static int same_as(const struct stat *st, const rt_fh *fh)
{
    return S_ISREG(st->st_mode) && st->st_dev == fh->dev && st->st_ino == fh->ino;
}

int plat_still_same(const rt_fh *fh, const char *path)
{
    struct stat st;
    char name[NAME_MAX + 1];
    int ok, pfd = open_parent(path, name, sizeof name);
    if (pfd < 0) return 0;
    ok = fstatat(pfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && same_as(&st, fh);
    close(pfd);
    return ok;
}

/* ---------------------------------------------------------------- quarantine / remove */
/* copy src(name in pfd) -> dst(name in qfd); verifies the source is still the scanned file. */
static int copy_into(int pfd, const char *name, int qfd, const char *dname, const rt_fh *fh)
{
    /* v2 FIX: O_NONBLOCK + S_ISREG check; v1's open() of a FIFO swapped in after the scan blocked the worker forever. */
    int in = openat(pfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
    int out;
    struct stat st;
    char buf[65536];
    int ok = 0, werr = 0;
    if (in < 0) return -1;
    if (fstat(in, &st) != 0 || !same_as(&st, fh)) { close(in); errno = ESTALE; return -1; }
    out = openat(qfd, dname, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (out < 0) { int e = errno; close(in); errno = e; return -1; }
    for (;;) {
        ssize_t r = read(in, buf, sizeof buf), off = 0;
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) { ok = 1; break; }
        while (off < r) {
            ssize_t w = write(out, buf + off, (size_t)(r - off));
            if (w < 0) { if (errno == EINTR) continue; werr = 1; break; }
            off += w;
        }
        if (werr) break;
    }
    if (ok && fsync(out) != 0) ok = 0;
    if (close(out) != 0) ok = 0;
    close(in);
    if (!ok) unlinkat(qfd, dname, 0);
    return ok ? 0 : -1;
}

static void write_info(int qfd, const char *dname, const char *path, const char *sig)
{
    char iname[NAME_MAX + 1];
    char safep[PATH_MAX + 1];
    size_t i;
    int fd;
    FILE *f;
    if (snprintf(iname, sizeof iname, "%s.info", dname) >= (int)sizeof iname) return;
    /* v2 FIX: the original path is attacker controlled; a newline in it injected extra "key=value" lines
     * (e.g. a fake "original=/etc/passwd") into a file that restore tooling may parse. */
    for (i = 0; path[i] && i < PATH_MAX; i++) safep[i] = ((unsigned char)path[i] < 0x20 || path[i] == 0x7f) ? '?' : path[i];
    safep[i] = '\0';
    fd = openat(qfd, iname, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return;
    f = fdopen(fd, "w");
    if (!f) { close(fd); return; }
    fprintf(f, "original=%s\nsignature=%s\ntime=%lld\nclamrt=" CLAMRT_VERSION "\n", safep, sig, (long long)time(NULL));
    fclose(f);
}

int plat_quarantine(const rt_fh *fh, const char *path, const char *qdir, const char *sig, char *out, size_t outsz)
{
    char safe[104], name[NAME_MAX + 1], dname[NAME_MAX + 1];
    const char *base = strrchr(path, '/');
    size_t i = 0;
    uint32_t h = 2166136261u;
    const char *c;
    int pfd, qfd, seq, rc = -1;
    struct stat st;

    base = base ? base + 1 : path;
    for (; *base && i < sizeof safe - 1; base++, i++) {
        unsigned char ch = (unsigned char)*base;
        safe[i] = (isalnum(ch) || ch == '.' || ch == '-' || ch == '_') ? (char)ch : '_';
    }
    safe[i] = '\0';
    for (c = path; *c; c++) { h ^= (unsigned char)*c; h *= 16777619u; }

    pfd = open_parent(path, name, sizeof name);
    if (pfd < 0) return -1;
    qfd = open_dir_nosymlinks(qdir);
    if (qfd < 0) { close(pfd); return -1; }

    /* v2 FIX: v1 named the file <time>_<hash(path)>_<name>; two detections of the same path within one second
     * collided (EEXIST) and the infected file stayed in place (reproduced).  Now a sequence number is tried. */
    for (seq = 0; seq < 100; seq++) {
        if (seq == 0) snprintf(dname, sizeof dname, "%lld_%08x_%s", (long long)time(NULL), h, safe);
        else snprintf(dname, sizeof dname, "%lld_%08x_%d_%s", (long long)time(NULL), h, seq, safe);

        /* link()+unlink() = no-clobber atomic move on the same filesystem; copy otherwise. */
        if (linkat(pfd, name, qfd, dname, 0) == 0) {
            /* v2 NEW: verify that what we just linked really is the scanned file (path swapped after plat_still_same?)
             * If not, undo: the innocent file is still at its original name. */
            if (fstatat(qfd, dname, &st, AT_SYMLINK_NOFOLLOW) != 0 || !same_as(&st, fh)) {
                unlinkat(qfd, dname, 0);
                break;
            }
            if (unlinkat(pfd, name, 0) != 0) { unlinkat(qfd, dname, 0); break; }
            rc = 0;
            break;
        }
        if (errno == EEXIST) continue;
        /* EXDEV / EPERM (protected_hardlinks) / ENOTSUP / EMLINK ... : fall back to copy */
        if (copy_into(pfd, name, qfd, dname, fh) == 0) {
            /* re-verify just before the delete (v2 NEW) */
            if (fstatat(pfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && same_as(&st, fh) && unlinkat(pfd, name, 0) == 0) rc = 0;
            else unlinkat(qfd, dname, 0);
            break;
        }
        if (errno == EEXIST) continue;
        break;
    }
    if (rc == 0) {
        /* the quarantined file can no longer be executed or read by non-root */
        if (fchmodat(qfd, dname, 0000, 0) != 0) rt_log(RT_LOG_WARN, "cannot clear permissions of %s: %s", dname, strerror(errno)); /* v2 FIX: result was ignored */
        write_info(qfd, dname, path, sig);
        if (snprintf(out, outsz, "%s/%s", qdir, dname) >= (int)outsz) out[outsz - 1] = '\0';
    }
    close(pfd);
    close(qfd);
    return rc;
}

int plat_remove(const rt_fh *fh, const char *path)
{
    char name[NAME_MAX + 1];
    struct stat st;
    int rc = -1, pfd = open_parent(path, name, sizeof name); /* v2 FIX: unlinkat() relative to the symlink-free parent */
    if (pfd < 0) return -1;
    if (fstatat(pfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && same_as(&st, fh)) rc = unlinkat(pfd, name, 0);
    close(pfd);
    return rc;
}
