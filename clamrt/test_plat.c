/* test_plat.c -- clamrt v4 unit tests for the Linux platform layer (no clamd needed).
 * build: gcc -std=gnu99 -g -fsanitize=address,undefined -pthread test_plat.c -o test_plat && ./test_plat */
#define _GNU_SOURCE
#include "clamrt.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

volatile sig_atomic_t g_stop;
rt_config g_cfg;
void rt_log(int l, const char *f, ...) { (void)l; (void)f; }
void rt_emit(const char *p) { (void)p; }
int rt_excluded(const char *p) { (void)p; return 0; }
void rt_note_overflow(void) {}
/* v3: stubs for the symbols clamrt_linux.c now references (tripwire hooks, fanotify back-end) */
int rt_trip_is_canary(const char *p) { (void)p; return 0; }
void rt_trip_canary_event(const char *p, long pid, const char *w) { (void)p; (void)pid; (void)w; }
int plat_fan_run(void) { return 1; }
int plat_fan_available(void) { return 0; } /* v4: referenced by the auto-mode selection */
#include "clamrt_linux.c" /* include the unit under test so static helpers/globals are reachable */

static int pass, fail;
#define CHECK(name, cond) do { if (cond) { pass++; printf("PASS: %s\n", name); } else { fail++; printf("FAIL: %s\n", name); } } while (0)
static void put(const char *p, const char *s) { FILE *f = fopen(p, "w"); if (!f) { perror(p); exit(2); } fputs(s, f); fclose(f); }

static void run(int use_openat2, const char *T)
{
    char p[512], q[512], qd[512], out[1024];
    rt_fh fh;
    char tag[96];
    g_openat2_ok = use_openat2;
#define T_(s) (snprintf(tag, sizeof tag, "[%s] %s", use_openat2 ? "openat2" : "walk", s), tag)

    snprintf(p, sizeof p, "%s/w/real/a.txt", T);
    CHECK(T_("plain file opens"), plat_open(p, &fh) == RT_OK && fh.size == 6); plat_close(&fh);

    snprintf(p, sizeof p, "%s/w/linkdir/b.txt", T); /* parent directory is a symlink -> must be refused */
    CHECK(T_("file below a SYMLINKED PARENT dir is refused"), plat_open(p, &fh) == RT_SKIP);

    snprintf(p, sizeof p, "%s/w/linkfile", T);
    CHECK(T_("symlink as final component refused"), plat_open(p, &fh) == RT_SKIP);

    snprintf(p, sizeof p, "%s/w/fifo", T);
    CHECK(T_("FIFO skipped without blocking"), plat_open(p, &fh) == RT_SKIP);

    snprintf(p, sizeof p, "%s/w/real/missing", T);
    CHECK(T_("missing file -> SKIP"), plat_open(p, &fh) == RT_SKIP);

    /* identity swap: scanned file A, then path replaced by innocent file B */
    snprintf(p, sizeof p, "%s/w/real/victim.bin", T); snprintf(qd, sizeof qd, "%s/q", T);
    put(p, "EVIL-A"); CHECK(T_("open victim"), plat_open(p, &fh) == RT_OK);
    snprintf(q, sizeof q, "%s/w/real/other.bin", T); put(q, "innocent");
    rename(q, p); /* B replaces A at the same path */
    CHECK(T_("still_same detects swap"), !plat_still_same(&fh, p));
    CHECK(T_("quarantine refuses swapped file"), plat_quarantine(&fh, p, qd, "Sig", out, sizeof out) == -1);
    CHECK(T_("innocent file untouched after refused quarantine"), access(p, F_OK) == 0);
    CHECK(T_("remove refuses swapped file"), plat_remove(&fh, p) == -1 && access(p, F_OK) == 0);
    plat_close(&fh);

    /* collision: same path quarantined twice in the same second */
    put(p, "EVIL-1"); plat_open(p, &fh);
    CHECK(T_("1st quarantine ok"), plat_quarantine(&fh, p, qd, "Sig", out, sizeof out) == 0 && access(p, F_OK) != 0); plat_close(&fh);
    put(p, "EVIL-2"); plat_open(p, &fh);
    CHECK(T_("2nd quarantine (same name+second) ok -- was a v1 bug"), plat_quarantine(&fh, p, qd, "Sig", out, sizeof out) == 0 && access(p, F_OK) != 0); plat_close(&fh);

    /* sidecar sanitises newline in the path */
    snprintf(p, sizeof p, "%s/w/real/evil\noriginal=_etc_passwd", T); put(p, "EVIL-3"); plat_open(p, &fh);
    CHECK(T_("quarantine path with newline"), plat_quarantine(&fh, p, qd, "Sig", out, sizeof out) == 0); plat_close(&fh);
    {
        char cmd[1200]; snprintf(cmd, sizeof cmd, "cat '%s'/*.info | grep -c '^original=' | grep -qx %d", qd, use_openat2 ? 3 : 6); /* cumulative: both passes share the quarantine dir */
        CHECK(T_("sidecar: exactly one 'original=' line per .info (no injected line)"), system(cmd) == 0);
    }
}

int main(void)
{
    char T[] = "/tmp/clamrt_unit_XXXXXX";
    char b[600];
    struct stat st;
    if (!mkdtemp(T)) return 2;
    snprintf(b, sizeof b, "mkdir -p %s/w/real %s/w/outside %s/q && chmod 700 %s/q && echo secret > %s/w/outside/b.txt && ln -s %s/w/outside %s/w/linkdir && ln -s %s/w/real/a.txt %s/w/linkfile && mkfifo %s/w/fifo",
             T, T, T, T, T, T, T, T, T, T);
    if (system(b) != 0) return 2;
    snprintf(b, sizeof b, "%s/w/real/a.txt", T); put(b, "hello\n");

    run(1, T);
    run(0, T);

    /* quarantine dir hardening */
    {
        char o[600], d[600];
        snprintf(d, sizeof d, "%s/qopen", T); mkdir(d, 0777); chmod(d, 0777);
        CHECK("world-writable quarantine dir is refused (v1 accepted it)", plat_prepare_dir(d, o, sizeof o) != 0);
        snprintf(d, sizeof d, "%s/qgood", T);
        CHECK("private quarantine dir accepted + created 0700", plat_prepare_dir(d, o, sizeof o) == 0 && stat(d, &st) == 0 && (st.st_mode & 0777) == 0700);
    }
    snprintf(b, sizeof b, "rm -rf %s", T); if (system(b)) {}
    printf("\nunit tests: %d passed, %d failed\n", pass, fail);
    return fail != 0;
}
