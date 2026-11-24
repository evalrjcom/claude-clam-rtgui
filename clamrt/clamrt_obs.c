/*
 * clamrt_obs.c -- clamrt v3 NEW (v4 revised): observability.
 *   - HTTP endpoint (--metrics [HOST:]PORT):  /metrics (Prometheus / OpenMetrics text), /status.json, /events, /healthz
 *   - recent-events ring shown by /events and the dashboard
 *   - --tui [HOST:]PORT : live terminal dashboard that polls such an endpoint (Linux terminal, Windows 10+ console)
 *
 * The server is deliberately tiny: GET only, one request at a time, 2 KiB request cap, 2 s read timeout, no keep-alive.
 * It binds to 127.0.0.1 unless told otherwise and warns when bound elsewhere (the endpoint has no authentication;
 * it exposes file paths of detections -- front it with a reverse proxy / firewall if you expose it).
 */
#define _GNU_SOURCE
#include "clamrt.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <process.h>
typedef CRITICAL_SECTION obs_mu;
#define OM_INIT(m) InitializeCriticalSection(m)
#define OM_LOCK(m) EnterCriticalSection(m)
#define OM_UNLOCK(m) LeaveCriticalSection(m)
#define sclose closesocket
#define spoll WSAPoll
typedef HANDLE obs_thr;
#else
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
typedef pthread_mutex_t obs_mu;
#define OM_INIT(m) pthread_mutex_init(m, NULL)
#define OM_LOCK(m) pthread_mutex_lock(m)
#define OM_UNLOCK(m) pthread_mutex_unlock(m)
#define sclose close
#define spoll poll
typedef pthread_t obs_thr;
#endif

#define RING 32
#define LINE 300
#if defined(MSG_NOSIGNAL) && !defined(_WIN32)
#define SENDF MSG_NOSIGNAL /* v4 FIX: a scraper that disconnects mid-response must never raise SIGPIPE in the daemon */
#else
#define SENDF 0
#endif

static struct { time_t t; char kind[16]; char line[LINE]; } g_ring[RING];
static unsigned g_ring_n;
static obs_mu g_omu;
static int g_omu_init;
static time_t g_start;

void rt_obs_event(const char *kind, const char *line)
{
    unsigned i;
    size_t k;
    if (!g_omu_init) return;
    OM_LOCK(&g_omu);
    i = g_ring_n++ % RING;
    g_ring[i].t = time(NULL);
    snprintf(g_ring[i].kind, sizeof g_ring[i].kind, "%s", kind);
    snprintf(g_ring[i].line, sizeof g_ring[i].line, "%s", line);
    for (k = 0; g_ring[i].line[k]; k++) if ((unsigned char)g_ring[i].line[k] < 0x20 || g_ring[i].line[k] == 0x7f) g_ring[i].line[k] = '?';
    OM_UNLOCK(&g_omu);
}

/* ---------------------------------------------------------------- server */
static rt_sock g_ls = RT_BADSOCK;
static obs_thr g_thr;
static int g_thr_started;

static size_t body_metrics(char *o, size_t cap)
{
    size_t n = 0;
    uint64_t cnt = RT_GET(scan_count_timed), ns = RT_GET(scan_ns_total);
#define C(name, help, v) n += (size_t)snprintf(o + n, cap - n, "# HELP clamrt_%s %s\n# TYPE clamrt_%s counter\nclamrt_%s %llu\n", name, help, name, name, (unsigned long long)(v))
#define G(name, help, v) n += (size_t)snprintf(o + n, cap - n, "# HELP clamrt_%s %s\n# TYPE clamrt_%s gauge\nclamrt_%s %llu\n", name, help, name, name, (unsigned long long)(v))
    n += (size_t)snprintf(o + n, cap - n, "# HELP clamrt_build_info clamrt version\n# TYPE clamrt_build_info gauge\nclamrt_build_info{version=\"" CLAMRT_VERSION "\"} 1\n");
    C("files_scanned_total", "Files scanned", RT_GET(scanned));
    C("files_clean_total", "Files found clean", RT_GET(clean));
    C("detections_total", "Infected files and blocked executions", RT_GET(infected));
    C("files_skipped_total", "Files skipped", RT_GET(skipped));
    C("errors_total", "Scan errors (gave up)", RT_GET(errors));
    C("events_dropped_total", "Events dropped (queue full)", RT_GET(dropped));
    C("overflows_total", "OS event-queue overflows", RT_GET(overflows));
    C("action_failures_total", "Quarantine/remove failures", RT_GET(actions_failed));
    C("verdict_cache_hits_total", "Scans avoided by the clean-verdict cache", RT_GET(verdict_cache_hits));
    C("exec_checked_total", "Executions held for a verdict (fanotify)", RT_GET(exec_checked));
    C("exec_denied_total", "Executions denied", RT_GET(exec_denied));
    C("exec_cache_hits_total", "Execution verdicts served from cache", RT_GET(exec_cache_hits));
    C("tripwire_alerts_total", "Ransomware tripwire alerts", RT_GET(tripwire_alerts));
    C("tripwire_actions_total", "Processes suspended/killed by the tripwire", RT_GET(tripwire_actions));
    C("canary_hits_total", "Canary file touches", RT_GET(canary_hits));
    C("intel_queries_total", "Threat-intel lookups sent", RT_GET(intel_queries));
    C("intel_hits_total", "Threat-intel lookups that knew the hash", RT_GET(intel_hits));
    C("intel_errors_total", "Threat-intel lookup failures", RT_GET(intel_errors));
    G("queue_depth", "Paths waiting to be scanned", RT_GET(queue_depth));
    n += (size_t)snprintf(o + n, cap - n, "# HELP clamrt_scan_seconds_avg Average clamd scan latency\n# TYPE clamrt_scan_seconds_avg gauge\nclamrt_scan_seconds_avg %.6f\n",
                          cnt ? (double)ns / 1e9 / (double)cnt : 0.0);
    G("uptime_seconds", "Seconds since start", (uint64_t)(time(NULL) - g_start));
#undef C
#undef G
    return n;
}

static size_t body_events(char *o, size_t cap)
{
    size_t n = 0;
    unsigned total, i, shown;
    OM_LOCK(&g_omu);
    total = g_ring_n;
    shown = total < RING ? total : RING;
    for (i = 0; i < shown; i++) { /* newest first */
        unsigned idx = (total - 1 - i) % RING;
        n += (size_t)snprintf(o + n, cap - n, "%lld %s %s\n", (long long)g_ring[idx].t, g_ring[idx].kind, g_ring[idx].line);
    }
    OM_UNLOCK(&g_omu);
    return n;
}

static size_t body_json(char *o, size_t cap)
{
    return (size_t)snprintf(o, cap,
        "{\"version\":\"" CLAMRT_VERSION "\",\"uptime_s\":%lld,\"scanned\":%llu,\"clean\":%llu,\"infected\":%llu,\"skipped\":%llu,"
        "\"errors\":%llu,\"dropped\":%llu,\"overflows\":%llu,\"queue_depth\":%llu,\"exec_checked\":%llu,\"exec_denied\":%llu,"
        "\"tripwire_alerts\":%llu,\"canary_hits\":%llu,\"intel_hits\":%llu}\n",
        (long long)(time(NULL) - g_start), (unsigned long long)RT_GET(scanned), (unsigned long long)RT_GET(clean),
        (unsigned long long)RT_GET(infected), (unsigned long long)RT_GET(skipped), (unsigned long long)RT_GET(errors),
        (unsigned long long)RT_GET(dropped), (unsigned long long)RT_GET(overflows), (unsigned long long)RT_GET(queue_depth),
        (unsigned long long)RT_GET(exec_checked), (unsigned long long)RT_GET(exec_denied),
        (unsigned long long)RT_GET(tripwire_alerts), (unsigned long long)RT_GET(canary_hits), (unsigned long long)RT_GET(intel_hits));
}

static void serve_one(rt_sock c)
{
    char req[2048], head[256];
    static char body[16384];
    size_t rl = 0, bl = 0;
    const char *status = "200 OK", *ctype = "text/plain; version=0.0.4; charset=utf-8";
    uint64_t end = plat_now_ms() + 2000;
    char *sp, *sp2;

    while (rl < sizeof req - 1 && plat_now_ms() < end) {
        struct pollfd pf;
        long r;
        pf.fd = c; pf.events = POLLIN; pf.revents = 0;
        if (spoll(&pf, 1, 200) <= 0) continue;
        r = (long)recv(c, req + rl, (int)(sizeof req - 1 - rl), 0);
        if (r <= 0) return;
        rl += (size_t)r;
        req[rl] = '\0';
        if (strstr(req, "\r\n\r\n") || strstr(req, "\n\n")) break;
    }
    req[rl] = '\0';
    if (strncmp(req, "GET ", 4) != 0) { status = "405 Method Not Allowed"; bl = (size_t)snprintf(body, sizeof body, "GET only\n"); goto send; }
    sp = req + 4;
    sp2 = strpbrk(sp, " \r\n?");
    if (sp2) *sp2 = '\0';
    if (!strcmp(sp, "/metrics")) bl = body_metrics(body, sizeof body);
    else if (!strcmp(sp, "/events")) bl = body_events(body, sizeof body);
    else if (!strcmp(sp, "/status.json")) { ctype = "application/json"; bl = body_json(body, sizeof body); }
    else if (!strcmp(sp, "/healthz")) bl = (size_t)snprintf(body, sizeof body, "ok\n");
    else { status = "404 Not Found"; bl = (size_t)snprintf(body, sizeof body, "try /metrics /status.json /events /healthz\n"); }
send:
    if (bl >= sizeof body) bl = sizeof body - 1;
    {
        int hl = snprintf(head, sizeof head, "HTTP/1.0 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", status, ctype, bl);
        if (send(c, head, hl, SENDF) >= 0) send(c, body, (int)bl, SENDF);
    }
}

#ifdef _WIN32
static unsigned __stdcall srv_main(void *arg)
#else
static void *srv_main(void *arg)
#endif
{
    (void)arg;
    while (!RT_STOPPING()) {
        struct pollfd pf;
        rt_sock c;
        pf.fd = g_ls; pf.events = POLLIN; pf.revents = 0;
        if (spoll(&pf, 1, 500) <= 0) continue;
        c = accept(g_ls, NULL, NULL);
        if (c == RT_BADSOCK) continue;
        serve_one(c);
        sclose(c);
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

int rt_metrics_start(void)
{
    struct addrinfo hints, *ai = NULL, *p;
    int yes = 1;
    OM_INIT(&g_omu);
    g_omu_init = 1;
    g_start = time(NULL);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(g_cfg.metrics_host, g_cfg.metrics_port, &hints, &ai) != 0) {
        rt_log(RT_LOG_ERR, "metrics: cannot resolve %s:%s", g_cfg.metrics_host, g_cfg.metrics_port);
        return -1;
    }
    for (p = ai; p; p = p->ai_next) {
        g_ls = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (g_ls == RT_BADSOCK) continue;
        setsockopt(g_ls, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof yes);
        if (bind(g_ls, p->ai_addr, (socklen_t)p->ai_addrlen) == 0 && listen(g_ls, 16) == 0) break;
        sclose(g_ls);
        g_ls = RT_BADSOCK;
    }
    freeaddrinfo(ai);
    if (g_ls == RT_BADSOCK) { rt_log(RT_LOG_ERR, "metrics: cannot listen on %s:%s: %s", g_cfg.metrics_host, g_cfg.metrics_port, strerror(errno)); return -1; }
#ifdef _WIN32
    { uintptr_t h = _beginthreadex(NULL, 0, srv_main, NULL, 0, NULL); if (!h) return -1; g_thr = (HANDLE)h; }
#else
    if (pthread_create(&g_thr, NULL, srv_main, NULL) != 0) { sclose(g_ls); g_ls = RT_BADSOCK; return -1; }
#endif
    g_thr_started = 1;
    if (strcmp(g_cfg.metrics_host, "127.0.0.1") && strcmp(g_cfg.metrics_host, "localhost") && strcmp(g_cfg.metrics_host, "::1"))
        rt_log(RT_LOG_WARN, "metrics endpoint %s:%s is NOT loopback and has no authentication", g_cfg.metrics_host, g_cfg.metrics_port);
    rt_log(RT_LOG_INFO, "metrics: http://%s:%s/metrics", g_cfg.metrics_host, g_cfg.metrics_port);
    return 0;
}

void rt_metrics_stop(void)
{
    if (g_thr_started) {
#ifdef _WIN32
        WaitForSingleObject(g_thr, 3000);
        CloseHandle(g_thr);
#else
        pthread_join(g_thr, NULL);
#endif
        g_thr_started = 0;
    }
    if (g_ls != RT_BADSOCK) { sclose(g_ls); g_ls = RT_BADSOCK; }
}

/* ================================================================ TUI client */
/* One HTTP/1.0 GET; returns bytes of body in out (NUL-terminated) or -1. */
static int http_get(const char *host, const char *port, const char *path, char *out, size_t outsz)
{
    struct addrinfo hints, *ai = NULL, *p;
    rt_sock s = RT_BADSOCK;
    char req[256];
    size_t len = 0;
    char *body;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &ai) != 0) return -1;
    for (p = ai; p && s == RT_BADSOCK; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == RT_BADSOCK) continue;
        {   /* bounded connect: 2 s */
            struct timeval tv = {2, 0};
#ifdef _WIN32
            DWORD ms = 2000;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms);
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof ms);
#else
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#endif
            (void)tv;
        }
        if (connect(s, p->ai_addr, (socklen_t)p->ai_addrlen) != 0) { sclose(s); s = RT_BADSOCK; }
    }
    freeaddrinfo(ai);
    if (s == RT_BADSOCK) return -1;
    snprintf(req, sizeof req, "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
    if (send(s, req, (int)strlen(req), SENDF) < 0) { sclose(s); return -1; }
    while (len < outsz - 1) {
        long r = (long)recv(s, out + len, (int)(outsz - 1 - len), 0);
        if (r <= 0) break;
        len += (size_t)r;
    }
    sclose(s);
    out[len] = '\0';
    body = strstr(out, "\r\n\r\n");
    /* v4 FIX: check the STATUS LINE (v3 searched the whole response for " 200 ", which a 404 body could contain) */
    if (!body || strncmp(out, "HTTP/1.", 7) != 0 || strncmp(out + 8, " 200", 4) != 0) return -1;
    body += 4;
    memmove(out, body, strlen(body) + 1);
    return 0;
}

static double metric(const char *text, const char *name)
{
    size_t nl = strlen(name);
    const char *p = text;
    while ((p = strstr(p, name)) != NULL) {
        if ((p == text || p[-1] == '\n') && (p[nl] == ' ')) return strtod(p + nl + 1, NULL);
        p += nl;
    }
    return 0;
}

static void bar(char *o, size_t osz, double v, double max, int width)
{
    int fill = max > 0 ? (int)(v / max * width) : 0, i;
    if (fill > width) fill = width;
    if (fill < 0) fill = 0;
    if ((size_t)width + 3 > osz) return;
    for (i = 0; i < width; i++) o[i] = i < fill ? '#' : '.';
    o[width] = '\0';
}

int rt_tui_main(const char *addr)
{
    char host[256], *colon, *port;
    static char m[24576], ev[16384];
    double prev_scanned = -1, prev_t = 0, rate = 0, peak = 1;
    int connected = 0, key;
    snprintf(host, sizeof host, "%s", addr);
    colon = strrchr(host, ':');
    if (!colon) return 2;
    *colon = '\0';
    port = colon + 1;
    plat_tui_init();
    while (1) {
        char line[512], b1[40];
        double now = (double)time(NULL), q, up;
        char *p, *nl;
        connected = http_get(host, port, "/metrics", m, sizeof m) == 0;
        if (connected && http_get(host, port, "/events", ev, sizeof ev) != 0) ev[0] = '\0';
        printf("\033[H\033[2J");
        printf("\033[1;36m clamrt v" CLAMRT_VERSION " dashboard\033[0m   %s:%s   %s\n", host, port,
               connected ? "\033[32mconnected\033[0m" : "\033[1;31mDISCONNECTED - retrying\033[0m");
        printf(" ------------------------------------------------------------------------------\n");
        if (connected) {
            double sc = metric(m, "clamrt_files_scanned_total");
            up = metric(m, "clamrt_uptime_seconds");
            q = metric(m, "clamrt_queue_depth");
            if (prev_scanned >= 0 && now > prev_t) rate = (sc - prev_scanned) / (now - prev_t);
            prev_scanned = sc;
            prev_t = now;
            if (q > peak) peak = q;
            printf(" uptime %.0fs    scan rate %.1f files/s    avg latency %.1f ms    cache hits %.0f\n", up, rate,
                   metric(m, "clamrt_scan_seconds_avg") * 1000.0, metric(m, "clamrt_verdict_cache_hits_total"));
            bar(b1, sizeof b1, q, peak < 10 ? 10 : peak, 30);
            printf(" queue  [%s] %.0f\n\n", b1, q);
            printf(" scanned %-10.0f clean %-10.0f skipped %-8.0f errors %-6.0f dropped %-6.0f overflows %.0f\n",
                   sc, metric(m, "clamrt_files_clean_total"), metric(m, "clamrt_files_skipped_total"), metric(m, "clamrt_errors_total"),
                   metric(m, "clamrt_events_dropped_total"), metric(m, "clamrt_overflows_total"));
            printf(" \033[%sm DETECTIONS %.0f\033[0m   exec checked %.0f   exec DENIED %.0f   action failures %.0f\n",
                   metric(m, "clamrt_detections_total") > 0 ? "1;31" : "32", metric(m, "clamrt_detections_total"),
                   metric(m, "clamrt_exec_checked_total"), metric(m, "clamrt_exec_denied_total"), metric(m, "clamrt_action_failures_total"));
            printf(" \033[%sm TRIPWIRE alerts %.0f\033[0m   canary hits %.0f   processes stopped %.0f\n",
                   metric(m, "clamrt_tripwire_alerts_total") > 0 ? "1;31" : "32", metric(m, "clamrt_tripwire_alerts_total"),
                   metric(m, "clamrt_canary_hits_total"), metric(m, "clamrt_tripwire_actions_total"));
            printf(" intel: queries %.0f  known %.0f  errors %.0f\n\n", metric(m, "clamrt_intel_queries_total"),
                   metric(m, "clamrt_intel_hits_total"), metric(m, "clamrt_intel_errors_total"));
            printf(" recent events (newest first)\n");
            p = ev;
            for (int i = 0; i < 12 && p && *p; i++) {
                long long t;
                nl = strchr(p, '\n');
                if (nl) *nl = '\0';
                t = strtoll(p, NULL, 10);
                {
                    struct tm tmv;
                    char ts[16] = "??:??:??";
                    time_t tt = (time_t)t;
#ifdef _WIN32
                    localtime_s(&tmv, &tt);
#else
                    localtime_r(&tt, &tmv);
#endif
                    strftime(ts, sizeof ts, "%H:%M:%S", &tmv);
                    const char *rest = strchr(p, ' ');
                    snprintf(line, sizeof line, "%s %.480s", ts, rest ? rest + 1 : p);
                }
                printf("  %.100s\n", line);
                p = nl ? nl + 1 : NULL;
            }
        } else {
            printf("\n  cannot reach http://%s:%s/metrics -- is clamrt running with --metrics %s ?\n", host, port, port);
        }
        printf("\n [q] quit\n");
        fflush(stdout);
        key = plat_tui_key(1000);
        if (key == 'q' || key == 'Q' || key == 3) break;
        if (RT_STOPPING()) break;
    }
    plat_tui_done();
    return 0;
}
