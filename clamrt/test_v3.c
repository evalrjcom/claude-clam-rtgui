/* test_v3.c -- clamrt v4 unit tests: SHA-256, subprocess runner, process control guards, canary, sweep, JSON-ish helpers.
 * build: gcc -std=gnu99 -g -fsanitize=address,undefined -pthread -I. test_v3.c clamrt_sha256.c -lm -o test_v3 && ./test_v3 */
#define _GNU_SOURCE
#include "clamrt.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

volatile sig_atomic_t g_stop;
rt_config g_cfg;
rt_stats g_st;
static int emitted;
static char last_emit[4096];
void rt_log(int l, const char *f, ...) { (void)l; (void)f; }
void rt_emit(const char *p) { emitted++; snprintf(last_emit, sizeof last_emit, "%s", p); }
int rt_excluded(const char *p) { (void)p; return 0; }
#include "clamrt_linux_ext.c"

int plat_rewind(rt_fh *fh) { return lseek(fh->fd, 0, SEEK_SET) == 0 ? 0 : -1; }
long plat_read(rt_fh *fh, void *b, size_t n) { return read(fh->fd, b, n); }

static int pass, fail;
#define CHECK(name, cond) do { if (cond) { pass++; printf("PASS: %s\n", name); } else { fail++; printf("FAIL: %s\n", name); } } while (0)

int main(void)
{
    char T[] = "/tmp/clamrt_v3_unitXXXXXX", p[600], out[4096], hex[65];
    rt_sha256 c;
    rt_fh fh;
    if (!mkdtemp(T)) return 2;

    /* SHA-256 known answers (FIPS 180-4) */
    rt_sha256_init(&c); rt_sha256_update(&c, "abc", 3); rt_sha256_hex(&c, hex);
    CHECK("sha256(abc)", !strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    rt_sha256_init(&c); rt_sha256_hex(&c, hex);
    CHECK("sha256(empty)", !strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    rt_sha256_init(&c);
    rt_sha256_update(&c, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56); /* two-block message, padding edge */
    rt_sha256_hex(&c, hex);
    CHECK("sha256(56-byte message, padding spills into 2nd block)", !strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    {
        char *m = malloc(1000000);
        int i;
        memset(m, 'a', 1000000);
        rt_sha256_init(&c);
        for (i = 0; i < 1000000; i += 4093) rt_sha256_update(&c, m + i, (size_t)(1000000 - i < 4093 ? 1000000 - i : 4093));
        rt_sha256_hex(&c, hex);
        CHECK("sha256(1M x 'a') streamed in odd chunks", !strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
        free(m);
    }
    snprintf(p, sizeof p, "%s/f.bin", T);
    { FILE *f = fopen(p, "w"); fputs("abc", f); fclose(f); }
    fh.fd = open(p, O_RDONLY);
    (void)read(fh.fd, hex, 2); /* file offset not at 0: rt_hash_handle must rewind */
    CHECK("rt_hash_handle rewinds and hashes the whole file", rt_hash_handle(&fh, hex) == 0 && !strncmp(hex, "ba7816bf", 8));
    close(fh.fd);

    /* subprocess runner */
    { const char *a[] = {"/bin/echo", "hello  world", NULL}; int rc = plat_run_capture(a, NULL, out, sizeof out, 3000);
      CHECK("run_capture: exit code 0 + stdout", rc == 0 && !strcmp(out, "hello  world\n")); }
    { const char *a[] = {"/bin/cat", NULL}; int rc = plat_run_capture(a, "piped stdin data", out, sizeof out, 3000);
      CHECK("run_capture: stdin is delivered (config-on-stdin transport)", rc == 0 && !strcmp(out, "piped stdin data")); }
    { const char *a[] = {"/bin/sh", "-c", "exit 7", NULL}; CHECK("run_capture: exit status propagated", plat_run_capture(a, NULL, out, sizeof out, 3000) == 7); }
    { const char *a[] = {"/bin/sleep", "10", NULL}; time_t t0 = time(NULL); int rc = plat_run_capture(a, NULL, out, sizeof out, 400);
      CHECK("run_capture: hung child killed at the timeout (< 3 s)", time(NULL) - t0 < 3 && rc != 0); }
    { const char *a[] = {"/nonexistent/prog", NULL}; CHECK("run_capture: missing program -> -1", plat_run_capture(a, NULL, out, sizeof out, 1000) < 0); }
    { const char *a[] = {"/bin/sh", "-c", "head -c 3000000 /dev/zero | tr '\\0' x", NULL}; char small[1024];
      plat_run_capture(a, NULL, small, sizeof small, 5000);
      CHECK("run_capture: output capped at the buffer size, no overflow", strlen(small) < sizeof small); }
    { const char *a[] = {"/bin/echo", "$(touch /tmp/clamrt_inj_marker); `id`; |&", NULL};
      unlink("/tmp/clamrt_inj_marker"); plat_run_capture(a, NULL, out, sizeof out, 3000);
      CHECK("run_capture: no shell -> metacharacters are literal", access("/tmp/clamrt_inj_marker", F_OK) != 0 && strstr(out, "$(touch")); }

    /* process control guards */
    CHECK("suspend: pid 1 refused", plat_suspend_pid(1, 0) != 0);
    CHECK("suspend: pid 0 / negative refused", plat_suspend_pid(0, 0) != 0 && plat_suspend_pid(-5, 1) != 0);
    CHECK("suspend: own pid refused", plat_suspend_pid((long)getpid(), 1) != 0);
    CHECK("suspend: kernel thread (kthreadd, pid 2) refused", plat_suspend_pid(2, 1) != 0);
    { char comm[64]; CHECK("pid_comm: own comm readable", plat_pid_comm((long)getpid(), comm, sizeof comm) == 0 && comm[0]);
      char info[600]; plat_pid_info((long)getpid(), info, sizeof info); CHECK("pid_info: has exe=", strstr(info, "exe=") != NULL);
      CHECK("pid_comm: nonexistent pid -> error", plat_pid_comm(999999999L, comm, sizeof comm) != 0); }
    /* v4 NEW: executable path of a process (used by --tripwire-ignore-exe) */
    { char exe[4096], self[4096]; ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1); if (n > 0) self[n] = 0;
      CHECK("pid_exe: own image path equals /proc/self/exe", n > 0 && plat_pid_exe((long)getpid(), exe, sizeof exe) == 0 && !strcmp(exe, self));
      CHECK("pid_exe: nonexistent pid -> error and empty string", plat_pid_exe(999999999L, exe, sizeof exe) != 0 && exe[0] == 0); }
    {   /* real stop + kill of a throw-away child */
        pid_t ch = fork();
        if (ch == 0) { for (;;) pause(); }
        usleep(100000);
        CHECK("suspend: SIGSTOP a child", plat_suspend_pid((long)ch, 0) == 0);
        usleep(150000); /* SIGSTOP takes effect asynchronously */
        { char st[64]; snprintf(st, sizeof st, "/proc/%d/stat", (int)ch); char b[512]; read_small(st, b, sizeof b); CHECK("suspend: child is in state T", strstr(b, ") T ") != NULL); }
        CHECK("kill: SIGKILL a child", plat_suspend_pid((long)ch, 1) == 0);
        { int s; waitpid(ch, &s, 0); CHECK("kill: child really died", WIFSIGNALED(s)); }
    }

    /* canary */
    snprintf(p, sizeof p, "%s/can", T); mkdir(p, 0755);
    CHECK("canary: created", plat_create_canary(p, out, sizeof out) == 0 && access(out, F_OK) == 0);
    { struct stat st; stat(out, &st); CHECK("canary: non-empty, mode 0644", st.st_size > 1000 && (st.st_mode & 0777) == 0644); }
    CHECK("canary: second call reuses the existing file", plat_create_canary(p, out, sizeof out) == 0);
    { char out2[700]; snprintf(out2, sizeof out2, "%s/AAAA_clamrt_canary_do_not_edit.docx", p); unlink(out2); symlink("/etc/passwd", out2);
      CHECK("canary: a SYMLINK planted at the canary path is refused (O_NOFOLLOW)", plat_create_canary(p, out, sizeof out) != 0); unlink(out2); }

    /* sweep: mtime/ctime windows, recursion, no symlink follow */
    snprintf(p, sizeof p, "%s/sw", T); mkdir(p, 0755);
    g_cfg.npaths = 1; { static char root[600]; snprintf(root, sizeof root, "%s", p); g_cfg.paths[0] = root; } g_cfg.recursive = 1;
    { char q[700]; FILE *f;
      snprintf(q, sizeof q, "%s/old.txt", p); f = fopen(q, "w"); fclose(f);
      { struct timespec ts[2] = {{1000000000, 0}, {1000000000, 0}}; utimensat(AT_FDCWD, q, ts, 0); } /* old mtime, but ctime = now */
      snprintf(q, sizeof q, "%s/sub", p); mkdir(q, 0755); snprintf(q, sizeof q, "%s/sub/new.txt", p); f = fopen(q, "w"); fclose(f);
      snprintf(q, sizeof q, "%s/lnk", p); symlink("/etc/passwd", q);
      emitted = 0; plat_sweep((long long)time(NULL) - 60);
      CHECK("sweep: finds files by ctime too (old mtime, fresh ctime) + recursion = 2, symlink ignored", emitted == 2);
      emitted = 0; plat_sweep((long long)time(NULL) + 3600);
      CHECK("sweep: nothing newer than the future", emitted == 0);
      g_cfg.recursive = 0; emitted = 0; plat_sweep(0);
      CHECK("sweep: --no-recursive honoured (only top-level file)", emitted == 1 && strstr(last_emit, "old.txt")); }

    printf("\nRESULT: %d passed, %d failed\n", pass, fail);
    snprintf(out, sizeof out, "rm -rf %s", T); (void)!system(out);
    return fail != 0;
}
