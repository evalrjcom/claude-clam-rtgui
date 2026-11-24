/*
 * clamrt_linux_ext.c -- clamrt v3 NEW (v4 revised): Linux platform helpers added in v3.
 *   process info / suspend (tripwire), subprocess runner (threat intel), syslog + journald sinks,
 *   TUI terminal control, canary creation, periodic sweep.
 */
#define _GNU_SOURCE
#include "clamrt.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ------------------------------------------------------------------ process info */
static int read_small(const char *path, char *out, size_t outsz)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t n;
    if (fd < 0) return -1;
    n = read(fd, out, outsz - 1);
    close(fd);
    if (n < 0) return -1;
    out[n] = '\0';
    return (int)n;
}

int plat_pid_comm(long pid, char *out, size_t outsz)
{
    char p[64];
    int n;
    snprintf(p, sizeof p, "/proc/%ld/comm", pid);
    n = read_small(p, out, outsz);
    if (n < 0) { out[0] = '\0'; return -1; }
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == ' ')) out[--n] = '\0';
    return 0;
}

/* v4 NEW: absolute path of the process image (readlink /proc/PID/exe).  Unlike comm it cannot be changed by the process. */
int plat_pid_exe(long pid, char *out, size_t outsz)
{
    char p[64];
    ssize_t n;
    snprintf(p, sizeof p, "/proc/%ld/exe", pid);
    n = readlink(p, out, outsz - 1);
    if (n <= 0) { out[0] = '\0'; return -1; }
    out[n] = '\0';
    return 0;
}

int plat_pid_info(long pid, char *out, size_t outsz)
{
    char p[64], comm[64] = "?", exe[PATH_MAX] = "", cmd[256] = "";
    ssize_t n;
    size_t i;
    int fd;
    plat_pid_comm(pid, comm, sizeof comm);
    snprintf(p, sizeof p, "/proc/%ld/exe", pid);
    n = readlink(p, exe, sizeof exe - 1);
    exe[n > 0 ? n : 0] = '\0';
    snprintf(p, sizeof p, "/proc/%ld/cmdline", pid);
    fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        n = read(fd, cmd, sizeof cmd - 1);
        close(fd);
        if (n < 0) n = 0;
        cmd[n] = '\0';
        for (i = 0; i < (size_t)n; i++) if (cmd[i] == '\0') cmd[i] = ' ';
    }
    for (i = 0; cmd[i]; i++) if ((unsigned char)cmd[i] < 0x20) cmd[i] = '?';
    snprintf(out, outsz, "%s exe=%s cmd=%s", comm, exe[0] ? exe : "?", cmd);
    return 0;
}

/* Refuses pid<=2, ourselves, and kernel threads (PF_KTHREAD). Uses pidfd when available so the signal cannot hit a
 * recycled pid between our checks and the kill. */
int plat_suspend_pid(long pid, int kill_it)
{
    /* v4 NEW: base system daemons are never stopped by the tripwire -- a false positive that SIGSTOPs sshd / systemd-journald /
     * logind / dbus would lock the administrator out.  (comm can be spoofed, but spoofing it here only PROTECTS the
     * spoofer from a SIGSTOP; the kill chain for ransomware is the exe-path ignore list, not this one.) */
    static const char *const protected_comm[] = {"systemd", "init", "sshd", "systemd-journal", "systemd-logind", "systemd-udevd",
                                                 "dbus-daemon", "login", "agetty", "NetworkManager", "containerd", "dockerd", NULL};
    char comm[64], p[64], st[1024];
    int pc;
    int pidfd, sig = kill_it ? SIGKILL : SIGSTOP, rc;
    unsigned long flags = 0;
    char *rp;
    if (pid <= 2 || pid == (long)getpid()) return -1;
    if (plat_pid_comm(pid, comm, sizeof comm) == 0)
        for (pc = 0; protected_comm[pc]; pc++) if (strcmp(comm, protected_comm[pc]) == 0) return -1;
    pidfd = (int)syscall(SYS_pidfd_open, (pid_t)pid, 0);
    snprintf(p, sizeof p, "/proc/%ld/stat", pid);
    if (read_small(p, st, sizeof st) < 0) { if (pidfd >= 0) close(pidfd); return -1; }
    rp = strrchr(st, ')');
    if (rp) {
        /* fields after ")": state ppid pgrp session tty_nr tpgid flags ... -> flags is the 9th */
        int field = 0;
        char *q = rp + 1;
        while (*q && field < 9) {
            while (*q == ' ') q++;
            if (++field == 9) { flags = strtoul(q, NULL, 10); break; }
            while (*q && *q != ' ') q++;
        }
    }
    if (flags & 0x00200000UL) { if (pidfd >= 0) close(pidfd); return -1; } /* PF_KTHREAD */
    if (pidfd >= 0) {
        rc = (int)syscall(SYS_pidfd_send_signal, pidfd, sig, NULL, 0);
        close(pidfd);
    } else {
        rc = kill((pid_t)pid, sig);
    }
    return rc == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ subprocess (threat intel) */
int plat_run_capture(const char *const *argv, const char *stdin_data, char *out, size_t outsz, unsigned timeout_ms)
{
    int inp[2], outp[2], status = 0, rc = -1;
    pid_t pid;
    posix_spawn_file_actions_t fa;
    size_t len = 0, wlen = stdin_data ? strlen(stdin_data) : 0, woff = 0;
    uint64_t end;
    struct timespec ts;

    out[0] = '\0';
    if (pipe2(inp, O_CLOEXEC) != 0) return -1;
    if (pipe2(outp, O_CLOEXEC) != 0) { close(inp[0]); close(inp[1]); return -1; }
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, inp[0], 0);
    posix_spawn_file_actions_adddup2(&fa, outp[1], 1);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    if (posix_spawnp(&pid, argv[0], &fa, NULL, (char *const *)argv, environ) != 0) {
        posix_spawn_file_actions_destroy(&fa);
        close(inp[0]); close(inp[1]); close(outp[0]); close(outp[1]);
        return -1;
    }
    posix_spawn_file_actions_destroy(&fa);
    close(inp[0]);
    close(outp[1]);
    fcntl(inp[1], F_SETFL, O_NONBLOCK);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    end = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u + timeout_ms;
    for (;;) {
        struct pollfd pf[2];
        int np = 0, r;
        uint64_t now;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        now = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
        if (now >= end || RT_STOPPING()) { kill(pid, SIGKILL); break; }
        pf[np].fd = outp[0]; pf[np].events = POLLIN; np++;
        if (inp[1] >= 0) { pf[np].fd = inp[1]; pf[np].events = POLLOUT; np++; }
        r = poll(pf, (nfds_t)np, (int)(end - now > 500 ? 500 : end - now));
        if (r < 0 && errno != EINTR) break;
        if (r > 0) {
            if (pf[0].revents & (POLLIN | POLLHUP)) {
                ssize_t n = read(outp[0], out + len, outsz - 1 - len);
                if (n > 0) { len += (size_t)n; if (len >= outsz - 1) { kill(pid, SIGKILL); break; } }
                else if (n == 0) break;
            }
            if (np > 1 && (pf[1].revents & POLLOUT)) {
                if (woff < wlen) {
                    ssize_t n = write(inp[1], stdin_data + woff, wlen - woff);
                    if (n > 0) woff += (size_t)n;
                }
                if (woff >= wlen) { close(inp[1]); inp[1] = -1; }
            }
        }
        if (wlen == 0 && inp[1] >= 0) { close(inp[1]); inp[1] = -1; }
    }
    out[len] = '\0';
    if (inp[1] >= 0) close(inp[1]);
    close(outp[0]);
    if (waitpid(pid, &status, 0) == pid && WIFEXITED(status)) rc = WEXITSTATUS(status);
    return rc;
}

/* ------------------------------------------------------------------ syslog / journald sinks */
static int sysprio(int level) { return level == RT_LOG_ERR ? LOG_ERR : level == RT_LOG_WARN ? LOG_WARNING : level == RT_LOG_INFO ? LOG_INFO : LOG_DEBUG; }

void plat_syslog(int level, const char *msg)
{
    static int opened;
    if (!opened) { openlog("clamrt", LOG_PID | LOG_NDELAY, LOG_DAEMON); opened = 1; }
    syslog(sysprio(level), "%s", msg);
}

static void jfield(char *buf, size_t cap, size_t *n, const char *k, const char *v)
{
    size_t vl = strlen(v), kl = strlen(k);
    if (strchr(v, '\n')) { /* binary-safe encoding: KEY\n<u64 LE length><value>\n */
        uint64_t l = vl;
        int i;
        if (*n + kl + 1 + 8 + vl + 1 > cap) return;
        memcpy(buf + *n, k, kl); *n += kl; buf[(*n)++] = '\n';
        for (i = 0; i < 8; i++) buf[(*n)++] = (char)((l >> (8 * i)) & 0xff);
        memcpy(buf + *n, v, vl); *n += vl; buf[(*n)++] = '\n';
    } else {
        if (*n + kl + 1 + vl + 1 > cap) return;
        memcpy(buf + *n, k, kl); *n += kl; buf[(*n)++] = '=';
        memcpy(buf + *n, v, vl); *n += vl; buf[(*n)++] = '\n';
    }
}

void plat_journald(int level, const char *msg, const char *const *kv)
{
    static int fd = -2;
    static char buf[16384];
    char prio[8], key[64];
    size_t n = 0;
    int i;
    struct sockaddr_un sun;
    if (fd == -2) { /* benign race: worst case two sockets, one leaks once */
        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    }
    if (fd < 0) return;
    snprintf(prio, sizeof prio, "%d", sysprio(level));
    {
        char local[16384]; /* per-call buffer: the log mutex is not held here */
        memset(&sun, 0, sizeof sun);
        sun.sun_family = AF_UNIX;
        strcpy(sun.sun_path, "/run/systemd/journal/socket");
        jfield(local, sizeof local, &n, "PRIORITY", prio);
        jfield(local, sizeof local, &n, "SYSLOG_IDENTIFIER", "clamrt");
        jfield(local, sizeof local, &n, "MESSAGE", msg);
        for (i = 0; kv && kv[i] && kv[i + 1]; i += 2) {
            size_t j, k = 0;
            if (!kv[i + 1][0]) continue;
            memcpy(key, "CLAMRT_", 7); k = 7;
            for (j = 0; kv[i][j] && k < sizeof key - 1; j++) key[k++] = isalnum((unsigned char)kv[i][j]) ? (char)toupper((unsigned char)kv[i][j]) : '_';
            key[k] = '\0';
            jfield(local, sizeof local, &n, key, kv[i + 1]);
        }
        (void)buf;
        sendto(fd, local, n, MSG_NOSIGNAL, (struct sockaddr *)&sun, sizeof sun); /* best effort: no journald, no record */
    }
}

/* ------------------------------------------------------------------ TUI terminal control */
static struct termios g_oldt;
static int g_tty;

void plat_tui_init(void)
{
    struct termios t;
    g_tty = isatty(0) && tcgetattr(0, &g_oldt) == 0;
    if (g_tty) {
        t = g_oldt;
        t.c_lflag &= (tcflag_t) ~(ICANON | ECHO);
        tcsetattr(0, TCSANOW, &t);
    }
    fputs("\033[?1049h\033[?25l", stdout); /* alternate screen, hide cursor */
    fflush(stdout);
}

void plat_tui_done(void)
{
    fputs("\033[?25h\033[?1049l", stdout);
    fflush(stdout);
    if (g_tty) tcsetattr(0, TCSANOW, &g_oldt);
}

int plat_tui_key(unsigned ms)
{
    struct pollfd pf = {0, POLLIN, 0};
    unsigned char c;
    if (poll(&pf, 1, (int)ms) > 0 && (pf.revents & POLLIN)) {
        if (read(0, &c, 1) == 1) return c;
        return 'q'; /* stdin closed */
    }
    return -1;
}

/* ------------------------------------------------------------------ canary / sweep */
int plat_create_canary(const char *dir, char *path_out, size_t outsz)
{
    /* Starts with "AAAA_" so it sorts first (ransomware usually walks in directory order) and ends in .docx. */
    static const char name[] = "AAAA_clamrt_canary_do_not_edit.docx";
    char text[4096];
    size_t n = 0;
    int fd;
    struct stat st;
    if (snprintf(path_out, outsz, "%s/%s", dir, name) >= (int)outsz) return -1;
    fd = open(path_out, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) { /* exists from an earlier run: accept only an untouched regular file of ours */
        int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() && st.st_size > 0;
        close(fd);
        return ok ? 0 : -1;
    }
    while (n + 64 < sizeof text) n += (size_t)snprintf(text + n, sizeof text - n, "clamrt canary file - low entropy by design %ld\n", (long)(n / 50));
    fd = open(path_out, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    if (write(fd, text, n) != (ssize_t)n) { close(fd); unlink(path_out); return -1; }
    close(fd);
    return 0;
}

static void sweep_dir(const char *dir, long long since, int depth)
{
    DIR *d;
    struct dirent *de;
    char path[PATH_MAX];
    struct stat st;
    if (depth > 128 || RT_STOPPING() || rt_excluded(dir)) return;
    d = opendir(dir);
    if (!d) return;
    while ((de = readdir(d)) != NULL && !RT_STOPPING()) {
        int n;
        if (de->d_name[0] == '.' && (!de->d_name[1] || (de->d_name[1] == '.' && !de->d_name[2]))) continue;
        n = snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        if (n < 0 || (size_t)n >= sizeof path) continue;
        if (lstat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) { if (g_cfg.recursive) sweep_dir(path, since, depth + 1); }
        else if (S_ISREG(st.st_mode) && (st.st_mtime >= since || st.st_ctime >= since)) rt_emit(path);
    }
    closedir(d);
}

void plat_sweep(long long since)
{
    int i;
    for (i = 0; i < g_cfg.npaths && !RT_STOPPING(); i++) sweep_dir(g_cfg.paths[i], since, 0);
}
