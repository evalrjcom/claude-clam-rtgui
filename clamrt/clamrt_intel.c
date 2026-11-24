/*
 * clamrt_intel.c -- clamrt v3 NEW: hash-only threat-intelligence enrichment of detections.
 *
 * On every detection clamrt computes the file's SHA-256 and asks MalwareBazaar (abuse.ch) or VirusTotal whether
 * the hash is known.  ONLY the 64-hex-digit hash leaves the machine: no file content, no path, no host name.
 * The answer (family / detection ratio / first seen) is logged next to the detection ("INTEL: ...").
 *
 * Transport: the curl executable is run WITHOUT a shell (no injection surface); the API key travels on curl's stdin as
 * a config file, so it never appears on a command line (ps) and is read from an environment variable
 * (--intel-key-env), never from argv.  Requests are HTTPS-only (--proto =https) unless --intel-url overrides the base
 * URL (testing / internal mirror), have a 15 s limit and a 1 MiB response cap, are rate-limited (MalwareBazaar 1/s,
 * VirusTotal 1 per 15 s = the free-tier quota of 4/min) and de-duplicated.  A background thread does the work, so a
 * slow or unreachable API can never delay scanning.
 */
#define _GNU_SOURCE
#include "clamrt.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <process.h>
typedef CRITICAL_SECTION im_mu;
#define IM_INIT(m) InitializeCriticalSection(m)
#define IM_LOCK(m) EnterCriticalSection(m)
#define IM_UNLOCK(m) LeaveCriticalSection(m)
#define MSLEEP(ms) Sleep(ms)
typedef HANDLE im_thr;
#else
#include <pthread.h>
#include <unistd.h>
typedef pthread_mutex_t im_mu;
#define IM_INIT(m) pthread_mutex_init(m, NULL)
#define IM_LOCK(m) pthread_mutex_lock(m)
#define IM_UNLOCK(m) pthread_mutex_unlock(m)
#define MSLEEP(ms) usleep((ms) * 1000u)
typedef pthread_t im_thr;
#endif

#define QN 64
#define SEEN 256

typedef struct { char path[1024]; char sig[256]; char sha[65]; } ijob;
static ijob g_q[QN];
static unsigned g_qh, g_qn;
static char g_seen[SEEN][65];
static unsigned g_seen_n;
static im_mu g_imu;
static im_thr g_thr;
static int g_started;
static char g_key[256];

void rt_intel_submit(const char *path, const char *sig, const char *sha)
{
    unsigned i;
    if (!g_started) return;
    IM_LOCK(&g_imu);
    for (i = 0; i < SEEN && i < g_seen_n; i++)
        if (strcmp(g_seen[i], sha) == 0) { IM_UNLOCK(&g_imu); return; } /* already asked about this hash */
    if (g_qn < QN) {
        ijob *j = &g_q[(g_qh + g_qn) % QN];
        snprintf(j->path, sizeof j->path, "%s", path);
        snprintf(j->sig, sizeof j->sig, "%s", sig);
        snprintf(j->sha, sizeof j->sha, "%s", sha);
        g_qn++;
        snprintf(g_seen[g_seen_n++ % SEEN], 65, "%s", sha);
    }
    IM_UNLOCK(&g_imu);
}

/* minimal JSON value extractor: finds "key" : "string" | number | true/false; returns 1 when found */
static int jget(const char *text, const char *key, char *out, size_t outsz)
{
    char pat[96];
    const char *p;
    size_t n = 0;
    snprintf(pat, sizeof pat, "\"%s\"", key);
    p = strstr(text, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != ':') return 0;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '"') {
        p++;
        while (*p && *p != '"' && n + 1 < outsz) {
            if (*p == '\\' && p[1]) p++;
            out[n++] = (unsigned char)*p < 0x20 ? '?' : *p;
            p++;
        }
    } else {
        while (*p && *p != ',' && *p != '}' && *p != ' ' && *p != '\n' && *p != '\r' && n + 1 < outsz) out[n++] = *p++;
    }
    out[n] = '\0';
    return n > 0;
}

static void lookup(const ijob *j)
{
    static char out[1 << 20]; /* v3 FIX: static (single intel thread): 1 MiB on the stack overflows the 1 MiB default Windows thread stack */
    char cfg[1024], url[512], a1[64], fam[200] = "", fs[64] = "", ft[64] = "", mal[32] = "", lab[128] = "";
    const char *argv[16];
    int n = 0, rc, known = 0;
    const char *base;
    int mb = g_cfg.intel == RT_INTEL_MB;

    if (mb) {
        base = g_cfg.intel_url ? g_cfg.intel_url : "https://mb-api.abuse.ch/api/v1/";
        snprintf(url, sizeof url, "%s", base);
    } else {
        base = g_cfg.intel_url ? g_cfg.intel_url : "https://www.virustotal.com/api/v3";
        snprintf(url, sizeof url, "%s/files/%s", base, j->sha);
    }
    /* curl config on stdin: key never reaches argv.  All inserted values are validated (hex / key charset / URL). */
    n = snprintf(cfg, sizeof cfg, "url = \"%s\"\n", url);
    if (g_key[0]) n += snprintf(cfg + n, sizeof cfg - (size_t)n, "header = \"%s: %s\"\n", mb ? "Auth-Key" : "x-apikey", g_key);
    if (mb) snprintf(cfg + n, sizeof cfg - (size_t)n, "data = \"query=get_info&hash=%s\"\n", j->sha);

    n = 0;
    argv[n++] = g_cfg.curl_path;
    argv[n++] = "--silent";
    argv[n++] = "--show-error";
    argv[n++] = "--max-time";
    argv[n++] = "15";
    argv[n++] = "--max-filesize";
    argv[n++] = "1048576";
    argv[n++] = "--proto";
    argv[n++] = g_cfg.intel_url ? "=http,https" : "=https";
    argv[n++] = "--config";
    argv[n++] = "-";
    argv[n] = NULL;
    (void)a1;
    RT_INC(intel_queries);
    rc = plat_run_capture(argv, cfg, out, sizeof out, 20000);
    memset(cfg, 0, sizeof cfg); /* the key was in there */
    if (rc != 0 || !out[0]) {
        RT_INC(intel_errors);
        rt_log(RT_LOG_WARN, "intel: lookup failed for sha256 %.16s... (curl exit %d)", j->sha, rc);
        return;
    }
    if (mb) {
        char st[64] = "";
        jget(out, "query_status", st, sizeof st);
        if (!strcmp(st, "ok")) {
            known = 1;
            jget(out, "signature", fam, sizeof fam);
            jget(out, "first_seen", fs, sizeof fs);
            jget(out, "file_type", ft, sizeof ft);
        } else if (strcmp(st, "hash_not_found") != 0 && strcmp(st, "no_results") != 0) {
            RT_INC(intel_errors);
            rt_log(RT_LOG_WARN, "intel: MalwareBazaar answered '%.40s' for %.16s...", st[0] ? st : "unparseable", j->sha);
            return;
        }
    } else {
        if (jget(out, "malicious", mal, sizeof mal)) {
            known = 1;
            jget(out, "suggested_threat_label", lab, sizeof lab);
            jget(out, "first_submission_date", fs, sizeof fs);
            snprintf(fam, sizeof fam, "%s", lab);
        } else if (!strstr(out, "NotFoundError")) {
            RT_INC(intel_errors);
            rt_log(RT_LOG_WARN, "intel: unexpected VirusTotal answer for %.16s...", j->sha);
            return;
        }
    }
    {
        char msg[1500], line[600];
        const char *src = mb ? "malwarebazaar" : "virustotal";
        if (known) {
            RT_INC(intel_hits);
            snprintf(msg, sizeof msg, "INTEL: %s knows sha256 %s: family=%s%s%s%s%s [%s]", src, j->sha, fam[0] ? fam : "?",
                     mal[0] ? " engines_malicious=" : "", mal, fs[0] ? " first_seen=" : "", fs, j->path);
        } else {
            snprintf(msg, sizeof msg, "INTEL: %s has never seen sha256 %s (clamd said %s) [%s]", src, j->sha, j->sig, j->path);
        }
        snprintf(line, sizeof line, "%.590s", msg + 7);
        rt_obs_event("intel", line);
        rt_log_kv(known ? RT_LOG_WARN : RT_LOG_INFO, msg, "event", "intel", "source", src, "sha256", j->sha, "known", known ? "yes" : "no",
                  "family", fam, "malicious_engines", mal, "first_seen", fs, "ft", ft, "path", j->path, NULL);
    }
}

#ifdef _WIN32
static unsigned __stdcall intel_main(void *arg)
#else
static void *intel_main(void *arg)
#endif
{
    uint64_t next_ok = 0;
    (void)arg;
    while (!RT_STOPPING()) {
        ijob j;
        int have = 0;
        uint64_t now = plat_now_ms();
        if (now >= next_ok) {
            IM_LOCK(&g_imu);
            if (g_qn) { j = g_q[g_qh]; g_qh = (g_qh + 1) % QN; g_qn--; have = 1; }
            IM_UNLOCK(&g_imu);
        }
        if (have) {
            lookup(&j);
            next_ok = plat_now_ms() + (g_cfg.intel == RT_INTEL_VT ? 15000u : 1000u); /* free-tier friendly */
        } else {
            MSLEEP(200);
        }
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

int rt_intel_start(void)
{
    const char *k = NULL;
    size_t i;
    IM_INIT(&g_imu);
    if (g_cfg.intel_key_env) k = getenv(g_cfg.intel_key_env);
    if (k) {
        snprintf(g_key, sizeof g_key, "%s", k);
        for (i = 0; g_key[i]; i++)
            if (!isalnum((unsigned char)g_key[i]) && g_key[i] != '-' && g_key[i] != '_') { /* config-injection guard */
                rt_log(RT_LOG_ERR, "intel: the API key in $%s contains characters outside [A-Za-z0-9_-]; refusing", g_cfg.intel_key_env);
                return -1;
            }
    }
    if (!g_key[0] && !g_cfg.intel_url) {
        rt_log(RT_LOG_ERR, "--intel needs the API key in an environment variable: --intel-key-env VAR (keys on the command line leak via ps)");
        return -1;
    }
    if (g_cfg.intel_url && strchr(g_cfg.intel_url, '"')) { rt_log(RT_LOG_ERR, "bad --intel-url"); return -1; }
#ifdef _WIN32
    { uintptr_t h = _beginthreadex(NULL, 0, intel_main, NULL, 0, NULL); if (!h) return -1; g_thr = (HANDLE)h; }
#else
    if (pthread_create(&g_thr, NULL, intel_main, NULL) != 0) return -1;
#endif
    g_started = 1;
    rt_log(RT_LOG_INFO, "intel: hash-only lookups via %s (only SHA-256 hashes leave this host)", g_cfg.intel == RT_INTEL_MB ? "MalwareBazaar" : "VirusTotal");
    return 0;
}

void rt_intel_stop(void)
{
    if (!g_started) return;
#ifdef _WIN32
    WaitForSingleObject(g_thr, 30000);
    CloseHandle(g_thr);
#else
    pthread_join(g_thr, NULL);
#endif
    g_started = 0;
}
