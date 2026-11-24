// clamgui_v3.cpp - ClamGUI v3: a ClamWin-style graphical front-end for ClamAV (FLTK 1.3, Linux + Windows).
//
// Scans files/folders with clamscan (or a managed clamd via clamdscan), updates signatures with freshclam, keeps a quarantine, schedules scans
// and updates (Task Scheduler / cron), keeps scan reports, and can start real-time protection (clamd + clamrt).
// v2 adds: tray icon, USB/download auto-scan, hash-only lookup, signed quarantine export, background service, fleet policy.
// v3 (audit release): every change is marked "v3 FIX" / "v3" in-line.  Bounded helper runs (no UI hangs), uninitialised-variable fixes, systemd unit path,
//   curl hardening (-q -g), PowerShell notification injection fix, newline-named files reported instead of silently skipped.
// It does NOT contain a scan engine: it drives the official ClamAV command-line tools.
//
// Build (Linux):   g++ -std=gnu++17 -O2 -Wall -Wextra -o clamgui_v3 clamgui_v3.cpp $(fltk-config --cxxflags --ldstaticflags) -pthread
// Build (Windows): x86_64-w64-mingw32-g++-posix -std=gnu++17 -O2 -mwindows -static -o clamgui_v3_win64.exe clamgui_v3.cpp  (add the include/lib paths:)
//                    -I<fltk>/include <fltk>/lib/libfltk.a -lcomctl32 -lole32 -luuid -lgdi32 -lws2_32 -lshell32 -ladvapi32 -lcomdlg32 -lwinspool
//
// Command line:  clamgui_v3 [PATH ...]            open the GUI and scan PATH(s) (Explorer/Files context menu)
//                clamgui_v3 --scan PATH ...       headless scan, prints results, exit 0 clean / 1 infected / 2 error
//                clamgui_v3 --scheduled-scan | --scheduled-update   headless runs used by the scheduler
//                clamgui_v3 --install-schedule | --remove-schedule  apply / remove the stored schedule
//                clamgui_v3 --quarantine-list | --restore ID | --delete ID | --version | --help
// Environment:   CLAMGUI_HOME=DIR keeps config+data under DIR (portable mode / tests)
//
// VERSIONING: CLAMGUI_VERSION is the single source of truth for every in-file version reference (title, about
// box, usage, report headers).  The file name, guide name and guide title carry the same number.
#define CLAMGUI_VERSION "3"
#define CLAMGUI_NAME "ClamGUI"

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  define WIN32_LEAN_AND_MEAN
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0600
#  endif
#  include <windows.h>
#  include <shellapi.h>
#else
#  include <unistd.h>
#  include <spawn.h>
#  include <sys/wait.h>
#  include <sys/file.h>
#  include <sys/stat.h>
#  include <fcntl.h>
#  include <signal.h>
extern char **environ;
#endif
#include <csignal>

#include <FL/Fl.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Tabs.H>
#include <FL/Fl_Group.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Int_Input.H>
#include <FL/Fl_Multiline_Input.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Check_Button.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Progress.H>
#include <FL/Fl_Multi_Browser.H>
#include <FL/Fl_Hold_Browser.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Native_File_Chooser.H>
#include <FL/fl_ask.H>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <set>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

// ============================================================================================ small utilities
static std::string u8(const fs::path &p) { auto s = p.u8string(); return std::string(s.begin(), s.end()); }
static fs::path P(const std::string &s) { return fs::u8path(s); }
static bool ends_with(const std::string &s, const char *suf) { size_t n = strlen(suf); return s.size() >= n && s.compare(s.size() - n, n, suf) == 0; }
static bool starts_with(const std::string &s, const char *pre) { return s.compare(0, strlen(pre), pre) == 0; }
static std::string trim(const std::string &s) { size_t a = 0, b = s.size(); while (a < b && isspace((unsigned char)s[a])) a++; while (b > a && isspace((unsigned char)s[b - 1])) b--; return s.substr(a, b - a); }
static std::vector<std::string> split(const std::string &s, char d) { std::vector<std::string> v; size_t a = 0; for (;;) { size_t b = s.find(d, a); if (b == std::string::npos) { v.push_back(s.substr(a)); break; } v.push_back(s.substr(a, b - a)); a = b + 1; } return v; }
static std::string tstamp(const char *fmt, time_t t) {
    struct tm tmv; char b[64];
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    strftime(b, sizeof b, fmt, &tmv); return b;
}

#ifdef _WIN32
static std::wstring u2w(const std::string &s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n > 0 ? n : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}
static std::string w2u(const std::wstring &w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? n : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}
static std::string env(const char *n) { const wchar_t *v = _wgetenv(u2w(n).c_str()); return v ? w2u(v) : ""; }
#else
static std::string env(const char *n) { const char *v = getenv(n); return v ? v : ""; }
#endif

// Escape %, TAB, CR, LF and control chars so a value is safe on one line of a TSV / key=value file.
static std::string esc(const std::string &s) {
    std::string o; char b[4];
    for (unsigned char c : s) { if (c == '%' || c < 0x20 || c == 0x7f) { snprintf(b, sizeof b, "%%%02X", c); o += b; } else o += (char)c; }
    return o;
}
static std::string unesc(const std::string &s) {
    std::string o;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i + 2 < s.size() + 0 && isxdigit((unsigned char)s[i + 1]) && isxdigit((unsigned char)s[i + 2])) { o += (char)strtol(s.substr(i + 1, 2).c_str(), nullptr, 16); i += 2; }
        else o += s[i];
    }
    return o;
}
// Make arbitrary bytes (file names, tool output) safe for FLTK text widgets: valid UTF-8, no control chars, bounded.
static std::string sane(const std::string &s, size_t maxlen = 4096) {
    std::string o; o.reserve(std::min(s.size(), maxlen));
    for (size_t i = 0; i < s.size() && o.size() < maxlen;) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x80) { o += (c >= 0x20 || c == '\t') ? (char)c : '?'; i++; continue; }
        int n = c >= 0xf5 ? 0 : c >= 0xf0 ? 3 : c >= 0xe0 ? 2 : c >= 0xc2 ? 1 : 0;
        bool ok = n > 0 && i + (size_t)n < s.size();      // need n continuation bytes available (index i+n must exist)
        for (int k = 1; ok && k <= n; k++) ok = (((unsigned char)s[i + k]) & 0xc0) == 0x80;
        if (ok) {
            unsigned char c1 = (unsigned char)s[i + 1];
            if ((c == 0xe0 && c1 < 0xa0) || (c == 0xed && c1 > 0x9f) || (c == 0xf0 && c1 < 0x90) || (c == 0xf4 && c1 > 0x8f)) ok = false;   // overlong / surrogate / > U+10FFFF
        }
        if (ok) { o.append(s, i, (size_t)n + 1); i += (size_t)n + 1; } else { o += '?'; i++; }
    }
    return o;
}
static std::string at_esc(const std::string &s) { std::string o; for (char c : s) { o += c; if (c == '@') o += '@'; } return o; }   // FLTK browser format codes
static std::string human(unsigned long long b) { char t[32]; const char *u[] = {"B", "KB", "MB", "GB", "TB"}; double v = (double)b; int i = 0; while (v >= 1024 && i < 4) { v /= 1024; i++; } snprintf(t, sizeof t, i ? "%.1f %s" : "%.0f %s", v, u[i]); return t; }

// ============================================================================================ locations + config
static std::string home_dir() {
#ifdef _WIN32
    std::string h = env("USERPROFILE"); return h.empty() ? "C:\\" : h;
#else
    std::string h = env("HOME"); return h.empty() ? "/" : h;
#endif
}
static std::string config_dir() {
    std::string o = env("CLAMGUI_HOME"); if (!o.empty()) return o + "/config";
#ifdef _WIN32
    std::string a = env("APPDATA"); return (a.empty() ? home_dir() : a) + "\\clamgui";
#else
    std::string x = env("XDG_CONFIG_HOME"); return (x.empty() ? home_dir() + "/.config" : x) + "/clamgui";
#endif
}
static std::string data_dir() {
    std::string o = env("CLAMGUI_HOME"); if (!o.empty()) return o + "/data";
#ifdef _WIN32
    std::string a = env("LOCALAPPDATA"); return (a.empty() ? home_dir() : a) + "\\clamgui";
#else
    std::string x = env("XDG_DATA_HOME"); return (x.empty() ? home_dir() + "/.local/share" : x) + "/clamgui";
#endif
}
static void make_private_dir(const std::string &d) {
    std::error_code ec; fs::create_directories(P(d), ec);
#ifndef _WIN32
    chmod(d.c_str(), 0700);    // quarantine / config must not be readable by other users
#endif
}
// Atomic replace so a crash or concurrent reader never sees a half-written file.
static bool write_file_atomic(const std::string &path, const std::string &data) {
    std::string tmp = path + ".tmp"; std::error_code ec;
    {
#ifdef _WIN32
        FILE *f = _wfopen(u2w(tmp).c_str(), L"wb");
#else
        FILE *f = fopen(tmp.c_str(), "wb");
#endif
        if (!f) return false;
        bool ok = fwrite(data.data(), 1, data.size(), f) == data.size();
        ok = (fflush(f) == 0) && ok;
        ok = (fclose(f) == 0) && ok;
        if (!ok) { fs::remove(P(tmp), ec); return false; }
    }
#ifndef _WIN32
    chmod(tmp.c_str(), 0600);
#endif
    fs::rename(P(tmp), P(path), ec);
    if (ec) { fs::remove(P(tmp), ec); return false; }
    return true;
}
static bool read_file(const std::string &path, std::string &out, size_t maxb = 64u << 20) {
#ifdef _WIN32
    FILE *f = _wfopen(u2w(path).c_str(), L"rb");
#else
    FILE *f = fopen(path.c_str(), "rb");
#endif
    if (!f) return false;
    out.clear(); char b[65536]; size_t n;
    while ((n = fread(b, 1, sizeof b, f)) > 0) { out.append(b, n); if (out.size() > maxb) break; }
    fclose(f); return true;
}

// ---- executable discovery
static std::string exe_path() {
#ifdef _WIN32
    wchar_t b[32768]; DWORD n = GetModuleFileNameW(nullptr, b, 32768); return n ? w2u(std::wstring(b, n)) : "";
#else
    char b[4096]; ssize_t n = readlink("/proc/self/exe", b, sizeof b - 1); if (n <= 0) return ""; b[n] = 0; return b;
#endif
}
static bool is_exec_file(const std::string &p) {
    std::error_code ec; if (!fs::is_regular_file(P(p), ec)) return false;
#ifdef _WIN32
    return true;
#else
    return access(p.c_str(), X_OK) == 0;
#endif
}
static std::string find_tool(const std::string &base) {
#ifdef _WIN32
    std::string name = base + ".exe"; const char sep = ';';
#else
    std::string name = base; const char sep = ':';
#endif
    std::vector<std::string> dirs; std::string ed = u8(P(exe_path()).parent_path());
    if (!ed.empty()) { dirs.push_back(ed); dirs.push_back(ed + "/ClamAV"); }
#ifdef _WIN32
    dirs.push_back("C:\\Program Files\\ClamAV"); dirs.push_back("C:\\Program Files (x86)\\ClamAV"); dirs.push_back("C:\\ClamAV");
#else
    dirs.push_back("/usr/bin"); dirs.push_back("/usr/local/bin"); dirs.push_back("/usr/sbin"); dirs.push_back("/opt/clamav/bin");
#endif
    for (auto &d : split(env("PATH"), sep)) if (!d.empty()) dirs.push_back(d);
    for (auto &d : dirs) { std::string c = u8(P(d) / P(name)); if (is_exec_file(c)) return c; }
    return "";
}

// ---- config (key=value, values escaped, atomic save)
struct Config {
    std::map<std::string, std::string> kv, shadow;      // shadow = the user's own value of a key while a fleet policy overrides it
    std::set<std::string> managed;                       // keys currently controlled by the policy
    std::string get(const std::string &k) const { auto i = kv.find(k); return i == kv.end() ? "" : i->second; }
    int geti(const std::string &k, int d = 0) const { std::string v = get(k); if (v.empty()) return d; char *e; long x = strtol(v.c_str(), &e, 10); return (*e || x < -2000000000 || x > 2000000000) ? d : (int)x; }
    void set(const std::string &k, const std::string &v) { kv[k] = v; }
    std::string path() const { return config_dir() + "/clamgui.conf"; }
    void defaults() {
        std::string dd = data_dir();
        const std::pair<const char *, std::string> d[] = {
            {"clamscan", ""}, {"freshclam", ""}, {"clamd", ""}, {"clamrt", ""},
            {"db_dir", dd + "/db"}, {"quarantine_dir", dd + "/quarantine"}, {"certs_dir", ""},
            {"scan_archives", "1"}, {"scan_pua", "0"}, {"max_file_mb", "100"}, {"action", "0"}, {"excludes", ""},
            {"proxy_host", ""}, {"proxy_port", ""}, {"scan_path", home_dir()},
            {"sched_update_on", "0"}, {"sched_update_time", "03:00"},
            {"sched_scan_on", "0"}, {"sched_scan_path", home_dir()}, {"sched_scan_time", "02:00"}, {"sched_scan_days", "1111111"},
            {"rt_paths", home_dir()}, {"rt_action", "0"}, {"rt_blockexec", "0"},
            // v2
            {"clamdscan", ""}, {"engine", "0"}, {"usb_autoscan", "0"}, {"dl_watch", "0"}, {"dl_dir", home_dir() +
#ifdef _WIN32
                "\\Downloads"},
#else
                "/Downloads"},
#endif
            {"recent_days", "14"}, {"notify", "1"}, {"close_to_tray", "1"}, {"intel_provider", "0"}, {"intel_key_env", ""}, {"intel_url", ""},
            {"policy_src", ""}, {"report_url", ""}, {"report_paths", "1"}};
        for (auto &p : d) if (!kv.count(p.first)) kv[p.first] = p.second;
    }
    void load() {
        kv.clear(); std::string t;
        if (read_file(path(), t, 1u << 20))
            for (auto &l : split(t, '\n')) { size_t e = l.find('='); if (e == std::string::npos || l[0] == '#') continue; kv[trim(l.substr(0, e))] = unesc(l.substr(e + 1)); }
        defaults();
        for (const char *tool : {"clamscan", "freshclam", "clamd", "clamrt", "clamdscan"})      // auto-detect any tool path that is empty or has vanished
            if (get(tool).empty() || !is_exec_file(get(tool))) kv[tool] = find_tool(tool);
        if (get("certs_dir").empty() && !get("clamscan").empty()) {      // official Windows/portable layouts keep the root cert in a "certs" folder next to the tools
            fs::path d = P(get("clamscan")).parent_path();
            for (const fs::path &c : {d / "certs", d.parent_path() / "certs", d.parent_path() / "share" / "clamav" / "certs"}) { std::error_code ec; if (fs::is_directory(c, ec)) { kv["certs_dir"] = u8(c); break; } }
        }
    }
    bool save() const {
        make_private_dir(config_dir()); std::string o = "# ClamGUI v" CLAMGUI_VERSION " settings\n";
        for (auto &p : kv) o += p.first + "=" + esc(managed.count(p.first) && shadow.count(p.first) ? shadow.at(p.first) : p.second) + "\n";     // never persist policy-forced values over the user's own
        return write_file_atomic(path(), o);
    }
};
static Config g_cfg;
static std::string db_dir() { return g_cfg.get("db_dir"); }
static std::string reports_dir() { return data_dir() + "/reports"; }

// ============================================================================================ child processes
struct Msg { int type; std::string s; int code; };    // type 0 = output line, 1 = process exited (code)

#ifdef _WIN32
static std::wstring quote_w(const std::wstring &a) {   // CommandLineToArgvW-compatible quoting
    if (!a.empty() && a.find_first_of(L" \t\n\v\"") == std::wstring::npos) return a;
    std::wstring r = L"\"";
    for (size_t i = 0;; i++) {
        size_t bs = 0; while (i < a.size() && a[i] == L'\\') { bs++; i++; }
        if (i == a.size()) { r.append(bs * 2, L'\\'); break; }
        if (a[i] == L'"') { r.append(bs * 2 + 1, L'\\'); r += L'"'; } else { r.append(bs, L'\\'); r += a[i]; }
    }
    return r + L"\"";
}
#endif

// A child process whose stdout+stderr are merged and delivered as lines through a thread-safe queue.
// No shell is ever involved: arguments are passed as an array (posix_spawn / CreateProcessW).
class Proc {
public:
    Proc() {}
    ~Proc() { kill(); if (th_.joinable()) th_.join(); }
    Proc(const Proc &) = delete; Proc &operator=(const Proc &) = delete;

    bool start(const std::vector<std::string> &argv, std::string &err) {
        if (argv.empty()) { err = "empty command"; return false; }
#ifdef _WIN32
        SECURITY_ATTRIBUTES sa{sizeof sa, nullptr, TRUE};
        HANDLE rd = nullptr, wr = nullptr;
        if (!CreatePipe(&rd, &wr, &sa, 0)) { err = "pipe failed"; return false; }
        SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
        HANDLE nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
        std::wstring cl; for (size_t i = 0; i < argv.size(); i++) { if (i) cl += L' '; cl += quote_w(u2w(argv[i])); }
        STARTUPINFOW si{}; si.cb = sizeof si; si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
        si.hStdInput = nul; si.hStdOutput = wr; si.hStdError = wr;
        PROCESS_INFORMATION pi{};
        std::vector<wchar_t> buf(cl.begin(), cl.end()); buf.push_back(0);
        BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        DWORD le = GetLastError();
        CloseHandle(wr); if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
        if (!ok) { CloseHandle(rd); err = "cannot start " + argv[0] + " (error " + std::to_string(le) + ")"; return false; }
        { static HANDLE job = [] { HANDLE j = CreateJobObjectW(nullptr, nullptr); if (j) { JOBOBJECT_EXTENDED_LIMIT_INFORMATION li{}; li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; SetInformationJobObject(j, JobObjectExtendedLimitInformation, &li, sizeof li); } return j; }();
          if (job) AssignProcessToJobObject(job, pi.hProcess); }     // children die with the GUI, even if it is killed
        CloseHandle(pi.hThread); hproc_ = pi.hProcess; hrd_ = rd;
#else
        int pf[2]; if (pipe2(pf, O_CLOEXEC) != 0) { err = "pipe failed"; return false; }
        posix_spawn_file_actions_t fa; posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
        posix_spawn_file_actions_adddup2(&fa, pf[1], 1);
        posix_spawn_file_actions_adddup2(&fa, pf[1], 2);
        std::vector<char *> av; for (auto &a : argv) av.push_back(const_cast<char *>(a.c_str())); av.push_back(nullptr);
        // v3 FIX: the child gets its own process group so kill() can take down grandchildren too (a wrapper script whose child keeps the
        // output pipe open made the reader thread - and therefore ~Proc - hang forever).
        posix_spawnattr_t at; posix_spawnattr_init(&at); posix_spawnattr_setpgroup(&at, 0); posix_spawnattr_setflags(&at, POSIX_SPAWN_SETPGROUP);
        pid_t pid = 0; int rc = posix_spawnp(&pid, av[0], &fa, &at, av.data(), environ);
        posix_spawnattr_destroy(&at);
        posix_spawn_file_actions_destroy(&fa);
        close(pf[1]);
        if (rc != 0) { close(pf[0]); err = "cannot start " + argv[0] + ": " + strerror(rc); return false; }
        pid_ = pid; fdr_ = pf[0];
#endif
        started_ = true;
        th_ = std::thread([this] { reader(); });
        return true;
    }
    // Pop the next message.  block=false returns immediately.  Returns false when nothing is available.
    bool pop(Msg &m, bool block) {
        std::unique_lock<std::mutex> lk(mu_);
        if (block) cv_.wait(lk, [this] { return !q_.empty(); });
        if (q_.empty()) return false;
        m = std::move(q_.front()); q_.pop_front(); return true;
    }
    // v3 FIX: timed pop so callers on the UI thread can never block forever on a hung child.  Returns false on timeout/empty.
    bool pop_for(Msg &m, int ms) {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait_for(lk, std::chrono::milliseconds(ms), [this] { return !q_.empty(); });
        if (q_.empty()) return false;
        m = std::move(q_.front()); q_.pop_front(); return true;
    }
    void kill() {
        std::lock_guard<std::mutex> lk(pm_);
#ifdef _WIN32
        if (hproc_) TerminateProcess(hproc_, 1);
#else
        if (pid_ > 0) { ::kill(-pid_, SIGTERM); ::kill(pid_, SIGTERM); }   // pid_ is only reset after the child was reaped, so no PID-reuse race; v3: whole group
#endif
    }
    // v3: SIGKILL the whole group (used when a helper ignores SIGTERM or hangs past its timeout).
    void kill_hard() {
        std::lock_guard<std::mutex> lk(pm_);
#ifdef _WIN32
        if (hproc_) TerminateProcess(hproc_, 1);
#else
        if (pid_ > 0) { ::kill(-pid_, SIGKILL); ::kill(pid_, SIGKILL); }
#endif
    }
    bool started() const { return started_; }
private:
    void push(Msg m) { { std::lock_guard<std::mutex> lk(mu_); q_.push_back(std::move(m)); } cv_.notify_all(); }
    void reader() {
        std::string part; char b[8192];
        for (;;) {
#ifdef _WIN32
            DWORD n = 0; if (!ReadFile(hrd_, b, sizeof b, &n, nullptr) || n == 0) break;
#else
            ssize_t n = read(fdr_, b, sizeof b); if (n < 0 && errno == EINTR) continue; if (n <= 0) break;
#endif
            for (size_t i = 0; i < (size_t)n; i++) {
                if (b[i] == '\n') { if (!part.empty() && part.back() == '\r') part.pop_back(); push({0, part, 0}); part.clear(); }
                else { part += b[i]; if (part.size() >= 16384) { push({0, part, 0}); part.clear(); } }   // bound a runaway line
            }
        }
        if (!part.empty()) push({0, part, 0});
        int code = -1;
#ifdef _WIN32
        CloseHandle(hrd_);
        WaitForSingleObject(hproc_, INFINITE);
        DWORD ec = 0; GetExitCodeProcess(hproc_, &ec); code = (int)ec;
        { std::lock_guard<std::mutex> lk(pm_); CloseHandle(hproc_); hproc_ = nullptr; }
#else
        close(fdr_);
        siginfo_t si; memset(&si, 0, sizeof si);
        while (waitid(P_PID, (id_t)pid_, &si, WEXITED | WNOWAIT) < 0 && errno == EINTR) {}
        { std::lock_guard<std::mutex> lk(pm_); int st = 0; while (waitpid(pid_, &st, 0) < 0 && errno == EINTR) {}
          code = WIFEXITED(st) ? WEXITSTATUS(st) : (WIFSIGNALED(st) ? 128 + WTERMSIG(st) : -1); pid_ = -1; }
#endif
        push({1, "", code});
    }
    std::thread th_; std::mutex mu_, pm_; std::condition_variable cv_; std::deque<Msg> q_; bool started_ = false;
#ifdef _WIN32
    HANDLE hproc_ = nullptr, hrd_ = nullptr;
#else
    pid_t pid_ = -1; int fdr_ = -1;
#endif
};

// Run a short command to completion and capture its output (used for crontab/schtasks/--version).
// v3 FIX: run_capture had no timeout - a hung helper (notify-send without a bus, openssl waiting on stdin, sc.exe) froze the UI thread forever.
// Now bounded by timeout_s (default 60 s); on expiry the child is killed and -2 returned.
static int run_capture(const std::vector<std::string> &argv, std::string &out, int timeout_s = 60) {
    Proc p; std::string err; out.clear();
    if (const char *e = getenv("CLAMGUI_HELPER_TIMEOUT")) { int v = atoi(e); if (v > 0) timeout_s = v; }   // v3: test hook
    if (!p.start(argv, err)) { out = err; return -1; }
    Msg m; auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
    for (;;) {
        if (!p.pop_for(m, 200)) {
            if (std::chrono::steady_clock::now() > deadline) { p.kill_hard(); out += "timed out\n"; return -2; }
            continue;
        }
        if (m.type == 1) return m.code;
        if (out.size() < (1u << 20)) out += m.s + "\n";
    }
}

static std::string new_id() {
    static std::random_device rd; static std::mutex m; std::lock_guard<std::mutex> lk(m);
    unsigned long long x = ((unsigned long long)rd() << 32) ^ rd() ^ (unsigned long long)std::chrono::steady_clock::now().time_since_epoch().count();
    char b[20]; snprintf(b, sizeof b, "%016llx", x); return b;
}
// ============================================================================================ v2 NEW: hashing, curl, notifications, risk scoring
// SHA-256 (FIPS 180-4) and HMAC-SHA256, used for the quarantine vault, signed exports and hash-only threat lookups.
struct Sha256 {
    uint32_t h[8]; uint64_t len = 0; unsigned char buf[64]; size_t n = 0;
    Sha256() { static const uint32_t i[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}; memcpy(h, i, sizeof h); }
    static uint32_t rr(uint32_t x, int k) { return (x >> k) | (x << (32 - k)); }
    void block(const unsigned char *p) {
        static const uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        uint32_t w[64], a, b, c, d, e, f, g, hh;
        for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 | (uint32_t)p[i * 4 + 2] << 8 | p[i * 4 + 3];
        for (int i = 16; i < 64; i++) { uint32_t s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >> 3), s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >> 10); w[i] = w[i - 16] + s0 + w[i - 7] + s1; }
        a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i], t2 = (rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    void update(const void *d, size_t l) {
        const unsigned char *p = (const unsigned char *)d; len += l;
        while (l) { size_t t = std::min(l, 64 - n); memcpy(buf + n, p, t); n += t; p += t; l -= t; if (n == 64) { block(buf); n = 0; } }
    }
    void final(unsigned char out[32]) {
        uint64_t bits = len * 8; unsigned char pad = 0x80; update(&pad, 1); pad = 0; while (n != 56) update(&pad, 1);
        unsigned char lb[8]; for (int i = 0; i < 8; i++) lb[i] = (unsigned char)(bits >> (56 - 8 * i)); update(lb, 8);
        for (int i = 0; i < 8; i++) { out[i * 4] = (unsigned char)(h[i] >> 24); out[i * 4 + 1] = (unsigned char)(h[i] >> 16); out[i * 4 + 2] = (unsigned char)(h[i] >> 8); out[i * 4 + 3] = (unsigned char)h[i]; }
    }
};
static std::string hex(const unsigned char *p, size_t n) { static const char *d = "0123456789abcdef"; std::string o; for (size_t i = 0; i < n; i++) { o += d[p[i] >> 4]; o += d[p[i] & 15]; } return o; }
[[maybe_unused]] static std::string sha256_str(const std::string &s) { Sha256 c; c.update(s.data(), s.size()); unsigned char o[32]; c.final(o); return hex(o, 32); }
static bool sha256_file(const std::string &path, std::string &out) {
#ifdef _WIN32
    FILE *f = _wfopen(u2w(path).c_str(), L"rb");
#else
    FILE *f = fopen(path.c_str(), "rb");
#endif
    if (!f) return false;
    Sha256 c; std::vector<unsigned char> b(1 << 20); size_t n;
    while ((n = fread(b.data(), 1, b.size(), f)) > 0) c.update(b.data(), n);
    bool ok = !ferror(f); fclose(f); unsigned char o[32]; c.final(o); out = hex(o, 32); return ok;
}
static std::string hmac_sha256(const std::string &key, const std::string &msg) {
    unsigned char k[64] = {0}; if (key.size() > 64) { Sha256 c; c.update(key.data(), key.size()); c.final(k); } else memcpy(k, key.data(), key.size());
    unsigned char ip[64], op[64]; for (int i = 0; i < 64; i++) { ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
    Sha256 in; in.update(ip, 64); in.update(msg.data(), msg.size()); unsigned char ih[32]; in.final(ih);
    Sha256 out; out.update(op, 64); out.update(ih, 32); unsigned char oh[32]; out.final(oh); return hex(oh, 32);
}
static bool ct_equal(const std::string &a, const std::string &b) { if (a.size() != b.size()) return false; unsigned char d = 0; for (size_t i = 0; i < a.size(); i++) d |= (unsigned char)(a[i] ^ b[i]); return d == 0; }
static std::string json_esc(const std::string &s) {
    std::string o; char b[8];
    for (unsigned char c : s) { if (c == '"' || c == '\\') { o += '\\'; o += (char)c; } else if (c < 0x20) { snprintf(b, sizeof b, "\\u%04x", c); o += b; } else o += (char)c; }
    return o;
}
static bool is_hex_n(const std::string &s, size_t n) { if (s.size() != n) return false; for (char c : s) if (!isxdigit((unsigned char)c)) return false; return true; }
static time_t file_mtime(const std::string &p) {
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA d; if (!GetFileAttributesExW(u2w(p).c_str(), GetFileExInfoStandard, &d)) return 0;
    ULARGE_INTEGER u; u.LowPart = d.ftLastWriteTime.dwLowDateTime; u.HighPart = d.ftLastWriteTime.dwHighDateTime; return (time_t)(u.QuadPart / 10000000ULL - 11644473600ULL);
#else
    struct stat st; return lstat(p.c_str(), &st) == 0 ? st.st_mtime : 0;
#endif
}
static std::string host_name() {
#ifdef _WIN32
    return env("COMPUTERNAME");
#else
    char b[256] = {0}; gethostname(b, sizeof b - 1); return b;
#endif
}
static std::string user_name() { std::string u = env("USERNAME"); if (u.empty()) u = env("USER"); return u; }

// ---- curl: HTTP without linking a TLS library.  Secrets (API keys, tokens) go through a 0600 curl config file, never argv.
struct CurlReq { std::string url, method = "GET", body; std::vector<std::string> headers, secret_headers; };
static bool url_ok(const std::string &u, std::string &err) {
    if (starts_with(u, "https://")) return true;
    for (const char *h : {"http://127.0.0.1", "http://localhost", "http://[::1]"}) if (starts_with(u, h)) { char c = u[strlen(h)]; if (c == 0 || c == ':' || c == '/') return true; }
    err = "only https:// URLs are allowed (plain http only for localhost)"; return false;
}
static std::string curl_bin() { std::string c = find_tool("curl"); return c.empty() ? "curl" : c; }
static std::vector<std::string> curl_args(const CurlReq &r, std::string &cfgfile, std::string &bodyfile, std::string &err) {
    cfgfile.clear(); bodyfile.clear();
    if (!url_ok(r.url, err)) return {};
    make_private_dir(data_dir() + "/tmp");
    std::vector<std::string> a = {curl_bin(), "-q", "-sS", "-g", "--connect-timeout", "10", "--max-time", "30", "-w", "\n%{http_code}", "--proto", starts_with(r.url, "https://") ? "=https" : "=http,https", "--proto-redir", "=https", "--max-filesize", "4194304"};
    std::string cfg;
    for (auto &h : r.secret_headers) { std::string v; for (char c : h) { if (c == '"' || c == '\\') v += '\\'; if (c != '\n' && c != '\r') v += c; } cfg += "header = \"" + v + "\"\n"; }
    if (!cfg.empty()) { cfgfile = data_dir() + "/tmp/curl-" + new_id() + ".cfg"; if (!write_file_atomic(cfgfile, cfg)) { err = "cannot write curl config"; return {}; } a.push_back("-K"); a.push_back(cfgfile); }
    for (auto &h : r.headers) { a.push_back("-H"); a.push_back(h); }
    if (r.method != "GET") {
        a.push_back("-X"); a.push_back(r.method);
        bodyfile = data_dir() + "/tmp/body-" + new_id() + ".dat"; if (!write_file_atomic(bodyfile, r.body)) { err = "cannot write request body"; return {}; }
        a.push_back("--data-binary"); a.push_back("@" + bodyfile);
    }
    a.push_back("--"); a.push_back(r.url); return a;
}
static void curl_cleanup(const std::string &cfg, const std::string &body) { std::error_code ec; if (!cfg.empty()) fs::remove(P(cfg), ec); if (!body.empty()) fs::remove(P(body), ec); }
static bool curl_parse(int rc, std::string out, int &http, std::string &body, std::string &err) {
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ')) out.pop_back();       // tolerate trailing whitespace after the status marker
    size_t p = out.rfind('\n'); http = 0;
    if (p != std::string::npos) { http = atoi(out.c_str() + p + 1); body = out.substr(0, p); } else body = out;
    if (rc != 0 || http == 0) { err = "network error" + (body.empty() ? std::string() : ": " + trim(body.substr(0, 200))); return false; }
    return true;
}
static bool curl_sync(const CurlReq &r, int &http, std::string &body, std::string &err) {
    std::string cfg, bf; auto a = curl_args(r, cfg, bf, err); if (a.empty()) return false;
    std::string out; int rc = run_capture(a, out); curl_cleanup(cfg, bf); return curl_parse(rc, out, http, body, err);
}
struct CurlJob { std::unique_ptr<Proc> p; std::string out, cfg, body; std::function<void(bool, int, const std::string &, const std::string &)> done; };
static std::vector<std::unique_ptr<CurlJob>> g_curl;
static bool curl_async(const CurlReq &r, std::function<void(bool, int, const std::string &, const std::string &)> done, std::string &err) {
    auto j = std::make_unique<CurlJob>(); auto a = curl_args(r, j->cfg, j->body, err); if (a.empty()) return false;
    j->p = std::make_unique<Proc>(); if (!j->p->start(a, err)) { curl_cleanup(j->cfg, j->body); return false; }
    j->done = std::move(done); g_curl.push_back(std::move(j)); return true;
}
static void curl_pump() {
    for (size_t i = 0; i < g_curl.size();) {
        auto &j = *g_curl[i]; Msg m; bool fin = false; int rc = 0;
        while (j.p->pop(m, false)) { if (m.type == 0) { if (j.out.size() < (5u << 20)) j.out += m.s + "\n"; } else { fin = true; rc = m.code; break; } }
        if (!fin) { i++; continue; }
        if (!j.out.empty()) j.out.pop_back();                 // the -w marker line is the last line; drop the trailing newline we added
        int http = 0; std::string body, err; bool ok = curl_parse(rc, j.out, http, body, err); curl_cleanup(j.cfg, j.body);
        auto cb = std::move(j.done); g_curl.erase(g_curl.begin() + (long)i); if (cb) cb(ok, http, body, err);
    }
}
// minimal JSON field extraction (flat search; only used on small, trusted-format API replies)
static bool jfind_num(const std::string &b, const char *key, long &v) { size_t p = b.find(std::string("\"") + key + "\""); if (p == std::string::npos) return false; p = b.find(':', p); if (p == std::string::npos) return false; p++; while (p < b.size() && isspace((unsigned char)b[p])) p++; if (p >= b.size() || !isdigit((unsigned char)b[p])) return false; v = atol(b.c_str() + p); return true; }
static std::string jfind_str(const std::string &b, const char *key) { size_t p = b.find(std::string("\"") + key + "\""); if (p == std::string::npos) return ""; p = b.find(':', p); if (p == std::string::npos) return ""; p++; while (p < b.size() && isspace((unsigned char)b[p])) p++; if (p >= b.size() || b[p] != '"') return ""; size_t e = b.find('"', p + 1); return e == std::string::npos ? "" : sane(b.substr(p + 1, std::min<size_t>(e - p - 1, 120))); }

// ---- hash-only threat lookup (MalwareBazaar / VirusTotal): only the SHA-256 ever leaves the machine
static bool intel_build(const std::string &sha, CurlReq &r, std::string &err) {
    int prov = g_cfg.geti("intel_provider", 0); if (prov != 1 && prov != 2) { err = "Hash lookup is off - choose a provider on the Advanced tab."; return false; }
    if (!is_hex_n(sha, 64)) { err = "bad hash"; return false; }
    std::string ke = g_cfg.get("intel_key_env"); if (ke.empty()) ke = prov == 1 ? "ABUSECH_AUTH_KEY" : "VT_API_KEY";
    std::string key = env(ke.c_str()); if (key.empty()) { err = "Set the environment variable " + ke + " to your API key and restart ClamGUI."; return false; }
    for (char c : key) if (c < 0x21 || c > 0x7e) { err = "API key contains invalid characters"; return false; }
    std::string base = g_cfg.get("intel_url");
    if (prov == 1) { r.url = base.empty() ? "https://mb-api.abuse.ch/api/v1/" : base; r.method = "POST"; r.body = "query=get_info&hash=" + sha; r.headers = {"Content-Type: application/x-www-form-urlencoded"}; r.secret_headers = {"Auth-Key: " + key}; }
    else { r.url = (base.empty() ? "https://www.virustotal.com/api/v3" : base) + "/files/" + sha; r.secret_headers = {"x-apikey: " + key}; }
    return url_ok(r.url, err);
}
static std::string intel_summary(int prov, int http, const std::string &b) {
    if (prov == 1) {
        std::string st = jfind_str(b, "query_status");
        if (st == "ok") { std::string sig = jfind_str(b, "signature"), ft = jfind_str(b, "file_type"); return "KNOWN to MalwareBazaar" + (sig.empty() ? std::string() : ", family: " + sig) + (ft.empty() ? std::string() : ", type: " + ft); }
        if (st == "hash_not_found") return "Not known to MalwareBazaar (the hash was never submitted).";
        if (http == 401 || http == 403) return "MalwareBazaar rejected the API key.";
        return "Unexpected MalwareBazaar reply (HTTP " + std::to_string(http) + ")" + (st.empty() ? "" : ": " + st);
    }
    long mal = 0, sus = 0;
    if (http == 200 && jfind_num(b, "malicious", mal)) { jfind_num(b, "suspicious", sus); std::string nm = jfind_str(b, "meaningful_name"); return std::to_string(mal) + " engine(s) flag it malicious, " + std::to_string(sus) + " suspicious on VirusTotal" + (nm.empty() ? "" : " (" + nm + ")"); }
    if (http == 404) return "Not known to VirusTotal.";
    if (http == 401 || http == 403) return "VirusTotal rejected the API key.";
    return "Unexpected VirusTotal reply (HTTP " + std::to_string(http) + ")";
}

// ---- desktop notifications
static bool tray_balloon(const std::string &title, const std::string &body);     // defined with the tray code
static void notify(const std::string &title, const std::string &body) {
    if (!g_cfg.geti("notify", 1)) return;
    if (tray_balloon(title, body)) return;
#ifdef _WIN32
    // v3 FIX: title/body were spliced into the PowerShell script with only ' -> '' escaping, so typographic quotes (U+2018/2019, which
    // PowerShell also treats as quotes) in a detected file name could break out and run code.  Text now travels in env vars and is read as data.
    _wputenv_s(L"CLAMGUI_NT", u2w(title.substr(0, 200)).c_str()); _wputenv_s(L"CLAMGUI_NB", u2w(body.substr(0, 400)).c_str());
    std::string ps = "Add-Type -AssemblyName System.Windows.Forms; $n=New-Object System.Windows.Forms.NotifyIcon; $n.Icon=[System.Drawing.SystemIcons]::Shield; $n.Visible=$true; $n.ShowBalloonTip(10000,$env:CLAMGUI_NT,$env:CLAMGUI_NB,[System.Windows.Forms.ToolTipIcon]::Warning); Start-Sleep -Seconds 11; $n.Dispose()";
    std::string out; run_capture({"powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps}, out, 30);
#else
    if (env("DBUS_SESSION_BUS_ADDRESS").empty()) { std::string s = "/run/user/" + std::to_string(getuid()) + "/bus"; std::error_code ec; if (fs::exists(P(s), ec)) setenv("DBUS_SESSION_BUS_ADDRESS", ("unix:path=" + s).c_str(), 1); }   // cron has no session bus variable
    std::string out; run_capture({"notify-send", "-a", "ClamGUI", "-u", "critical", "-i", "dialog-warning", title, body}, out);
#endif
}

// ---- download / recent-file triage: score files by how dangerous their type is so the riskiest are scanned first
static int risk_score(const std::string &path) {
    std::string name = u8(P(path).filename()), low; for (char c : name) low += (char)tolower((unsigned char)c);
    auto ext_of = [](const std::string &n) { size_t d = n.rfind('.'); return d == std::string::npos ? std::string() : n.substr(d + 1); };
    static const char *exe[] = {"exe", "scr", "com", "pif", "bat", "cmd", "msi", "dll", "jar", "js", "jse", "vbs", "vbe", "ps1", "wsf", "hta", "lnk", "sh", "run", "appimage", "deb", "rpm", "apk", "py", "reg", "cpl"};
    static const char *doc[] = {"docm", "xlsm", "pptm", "doc", "xls", "ppt", "rtf", "pdf", "odt", "dotm", "xlam"};
    static const char *arc[] = {"zip", "rar", "7z", "iso", "img", "gz", "tgz", "tar", "cab", "xz", "bz2", "dmg"};
    std::string e = ext_of(low); int s = 5;
    for (auto x : exe) if (e == x) s = 100;
    for (auto x : doc) if (e == x) s = std::max(s, 60);
    for (auto x : arc) if (e == x) s = std::max(s, 50);
    if (s == 100) {                                   // "invoice.pdf.exe": a document extension in front of an executable one
        std::string rest = low.substr(0, low.size() - e.size() - 1), e2 = ext_of(rest);
        for (const char *x : {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "mp3", "mp4", "zip"}) if (e2 == x) s += 60;
    }
#ifdef _WIN32
    FILE *f = _wfopen(u2w(path).c_str(), L"rb");
#else
    FILE *f = fopen(path.c_str(), "rb");
#endif
    if (f) {
        unsigned char m[4] = {0}; size_t n = fread(m, 1, 4, f); fclose(f);
        if (n >= 2 && m[0] == 'M' && m[1] == 'Z') s += 80; else if (n >= 4 && m[0] == 0x7f && m[1] == 'E' && m[2] == 'L' && m[3] == 'F') s += 80;
        else if (n >= 2 && m[0] == '#' && m[1] == '!') s += 50; else if (n >= 4 && m[0] == 0xd0 && m[1] == 0xcf && m[2] == 0x11 && m[3] == 0xe0) s += 40;
        else if (n >= 4 && m[0] == '%' && m[1] == 'P' && m[2] == 'D' && m[3] == 'F') s += 30; else if (n >= 4 && m[0] == 'P' && m[1] == 'K' && m[2] == 3 && m[3] == 4) s += 10;
    }
    return s;
}
static bool temp_download_name(const std::string &n) { std::string l; for (char c : n) l += (char)tolower((unsigned char)c); for (const char *x : {".part", ".crdownload", ".tmp", ".download", ".partial", ".opdownload"}) if (ends_with(l, x)) return true; return false; }
// Files under `dir` changed in the last `days` days, riskiest first (ties: newest first).  Bounded depth and count.
// v3 FIX: files whose names contain a newline cannot be expressed in a one-path-per-line --file-list.  They used to vanish silently
// (an attacker-controlled name could hide a file from recent/download scans).  They are now counted and reported to the user.
static std::atomic<int> g_nl_skipped{0};
static std::vector<std::string> recent_files(const std::string &dir, int days, size_t maxn = 5000, int maxdepth = 4) {
    g_nl_skipped = 0;
    std::vector<std::pair<std::pair<int, time_t>, std::string>> v; time_t now = time(nullptr), lim = now - (time_t)days * 86400; std::error_code ec;
    fs::recursive_directory_iterator it(P(dir), fs::directory_options::skip_permission_denied, ec), end;
    for (; !ec && it != end && v.size() < maxn * 4; it.increment(ec)) {
        if (it.depth() >= maxdepth) it.disable_recursion_pending();
        std::error_code e2; auto st = it->symlink_status(e2); if (e2 || st.type() != fs::file_type::regular) continue;
        std::string p = u8(it->path()); if (p.find('\n') != std::string::npos) { g_nl_skipped++; continue; }
        if (temp_download_name(u8(it->path().filename()))) continue;
        time_t mt = file_mtime(p); if (mt < lim) continue;
        v.push_back({{risk_score(p), mt}, p});
    }
    std::sort(v.begin(), v.end(), [](const auto &a, const auto &b) { return a.first != b.first ? a.first > b.first : a.second < b.second; });
    std::vector<std::string> o; for (auto &x : v) { if (o.size() >= maxn) break; o.push_back(x.second); } return o;
}
static std::string write_listfile(const std::vector<std::string> &files) {
    make_private_dir(data_dir() + "/tmp"); std::string p = data_dir() + "/tmp/list-" + new_id() + ".txt", body;
    for (auto &f : files) body += f + "\n";
    return write_file_atomic(p, body) ? p : "";
}

// ---- v2 NEW: fleet mode.  A policy file (local path or https URL) overrides a whitelist of settings; if CLAMGUI_POLICY_KEY is set the
// policy must carry a valid "hmac=" line (HMAC-SHA256 of all other lines).  Policy values are never written into the user's own settings.
static std::map<std::string, std::string> g_policy;
static const char *POLICY_KEYS[] = {"action", "scan_archives", "scan_pua", "max_file_mb", "excludes", "engine", "sched_update_on", "sched_update_time", "sched_scan_on", "sched_scan_time",
                                    "sched_scan_days", "sched_scan_path", "usb_autoscan", "dl_watch", "dl_dir", "recent_days", "notify", "intel_provider", "report_url", "report_paths"};
static std::string policy_hmac_for(const std::string &text, const std::string &key) {
    std::string o; auto lines = split(text, '\n'); if (!lines.empty() && lines.back().empty()) lines.pop_back();
    for (auto &l : lines) { std::string t = l; if (!t.empty() && t.back() == '\r') t.pop_back(); if (!starts_with(t, "hmac=")) o += t + "\n"; }
    return hmac_sha256(key, o);
}
static void overlay_policy() {                          // (re)apply g_policy on top of g_cfg
    for (auto &p : g_policy) { if (!g_cfg.managed.count(p.first)) g_cfg.shadow[p.first] = g_cfg.get(p.first); g_cfg.managed.insert(p.first); g_cfg.kv[p.first] = p.second; }
}
static bool apply_policy(std::string &msg) {
    std::string src = g_cfg.get("policy_src"); if (src.empty()) src = env("CLAMGUI_POLICY"); if (src.empty()) return true;
    std::string text, cache = data_dir() + "/policy.cache";
    if (starts_with(src, "http://") || starts_with(src, "https://")) {
        CurlReq r; r.url = src; int http = 0; std::string body, err;   // v3 FIX: was uninitialised
        if (curl_sync(r, http, body, err) && http == 200 && body.size() < (1u << 20)) { text = body; make_private_dir(data_dir()); write_file_atomic(cache, text); }
        else { msg = "policy download failed (" + (err.empty() ? "HTTP " + std::to_string(http) : err) + "); using the cached policy if any."; read_file(cache, text, 1u << 20); }
    } else if (!read_file(src, text, 1u << 20)) { msg = "cannot read policy file " + src; return false; }
    if (text.empty()) return false;
    std::string key = env("CLAMGUI_POLICY_KEY");
    if (!key.empty()) {
        std::string want; for (auto &l : split(text, '\n')) { std::string t = trim(l); if (starts_with(t, "hmac=")) want = t.substr(5); }
        if (!is_hex_n(want, 64) || !ct_equal(want, policy_hmac_for(text, key))) { msg = "policy REJECTED: missing or invalid hmac signature"; return false; }
    }
    g_policy.clear();
    for (auto &l : split(text, '\n')) {
        std::string t = trim(l); if (t.empty() || t[0] == '#') continue; size_t e = t.find('='); if (e == std::string::npos) continue;
        std::string k = trim(t.substr(0, e)), v = unesc(t.substr(e + 1)); if (v.size() > 4096) continue;
        for (const char *ok : POLICY_KEYS) if (k == ok) { for (char &c : v) if (c == '\r') c = ' '; g_policy[k] = v; }
    }
    overlay_policy(); msg = "policy applied: " + std::to_string(g_policy.size()) + " setting(s) managed" + (key.empty() ? " (unsigned)" : " (signature verified)"); return true;
}

// ============================================================================================ virus database info
struct DbInfo { std::string name; long ver = 0, sigs = 0; time_t built = 0; bool ok = false; };
static time_t parse_vdb_time(const std::string &s) {     // "14 Oct 2024 09-34 +0000"
    static const char *mon[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    int d, y, hh, mm; char m[8] = {0};
    if (sscanf(s.c_str(), "%d %3s %d %d-%d", &d, m, &y, &hh, &mm) != 5) return 0;
    int mi = -1; for (int i = 0; i < 12; i++) if (!strcmp(m, mon[i])) mi = i;
    if (mi < 0 || d < 1 || d > 31 || y < 1970 || y > 2200) return 0;
    long long yy = y - (mi < 2), era = yy / 400, yoe = yy - era * 400, mp = (mi + 9) % 12;
    long long doy = (153 * mp + 2) / 5 + d - 1, doe = yoe * 365 + yoe / 4 - yoe / 100 + doy, days = era * 146097 + doe - 719468;
    return (time_t)(days * 86400 + hh * 3600 + mm * 60);
}
static DbInfo read_db(const std::string &dir, const std::string &base) {
    DbInfo best; best.name = base;
    for (const char *ext : {".cld", ".cvd"}) {
        std::string t; std::string p = dir + "/" + base + ext;
        FILE *f =
#ifdef _WIN32
            _wfopen(u2w(p).c_str(), L"rb");
#else
            fopen(p.c_str(), "rb");
#endif
        if (!f) continue;
        char h[512]; size_t n = fread(h, 1, sizeof h - 1, f); fclose(f); h[n] = 0;
        auto fld = split(std::string(h, strnlen(h, 256)), ':');       // ClamAV-VDB:time:version:sigs:...
        if (fld.size() < 4 || fld[0] != "ClamAV-VDB") continue;
        long v = atol(fld[2].c_str());
        if (!best.ok || v > best.ver) { best.ok = true; best.ver = v; best.sigs = atol(fld[3].c_str()); best.built = parse_vdb_time(fld[1]); }
    }
    return best;
}
static bool has_any_db(const std::string &dir) {
    static const char *ex[] = {".cvd", ".cld", ".cud", ".ndb", ".hdb", ".hsb", ".ldb", ".ldu", ".cdb", ".mdb", ".msb", ".hdu", ".ndu", ".pdb", ".gdb", ".wdb", ".idb", ".cbc", ".yar", ".yara", ".fp", ".sfp", ".ftm", ".crb", ".cat"};
    std::error_code ec;
    for (fs::directory_iterator it(P(dir), ec), end; !ec && it != end; it.increment(ec)) {
        std::string e = u8(it->path().extension());
        for (auto x : ex) if (e == x) return true;
    }
    return false;
}

// ============================================================================================ quarantine
struct QItem { std::string id, threat, path, sha; time_t when = 0; unsigned long long size = 0; };   // v2: sha = SHA-256 of the stored file
static std::string qdir() { return g_cfg.get("quarantine_dir"); }

// Cross-process lock around index rewrites (GUI + scheduled scan may run at the same time).
class FileLock {
public:
    explicit FileLock(const std::string &p) {
#ifdef _WIN32
        h_ = CreateFileW(u2w(p).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h_ != INVALID_HANDLE_VALUE) { OVERLAPPED o{}; LockFileEx(h_, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &o); }
#else
        fd_ = open(p.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600); if (fd_ >= 0) while (flock(fd_, LOCK_EX) < 0 && errno == EINTR) {}
#endif
    }
    ~FileLock() {
#ifdef _WIN32
        if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_);
#else
        if (fd_ >= 0) close(fd_);
#endif
    }
private:
#ifdef _WIN32
    HANDLE h_ = INVALID_HANDLE_VALUE;
#else
    int fd_ = -1;
#endif
};
static std::vector<QItem> q_list() {
    std::vector<QItem> v; std::string t;
    if (!read_file(qdir() + "/index.tsv", t, 32u << 20)) return v;
    for (auto &l : split(t, '\n')) {
        auto f = split(l, '\t'); if (f.size() < 5) continue;
        QItem q; q.id = unesc(f[0]); q.when = (time_t)atoll(f[1].c_str()); q.threat = unesc(f[2]); q.path = unesc(f[3]); q.size = strtoull(f[4].c_str(), nullptr, 10);
        if (f.size() > 5 && is_hex_n(f[5], 64)) q.sha = f[5];
        bool idok = q.id.size() == 16; for (char c : q.id) if (!isxdigit((unsigned char)c)) idok = false;   // ids become file names: accept only 16 hex digits
        if (idok) v.push_back(q);
    }
    return v;
}
static bool q_write_index(const std::vector<QItem> &v) {
    std::string o; for (auto &q : v) o += esc(q.id) + "\t" + std::to_string((long long)q.when) + "\t" + esc(q.threat) + "\t" + esc(q.path) + "\t" + std::to_string(q.size) + "\t" + q.sha + "\n";
    return write_file_atomic(qdir() + "/index.tsv", o);
}
static bool move_or_copy(const fs::path &from, const fs::path &to, std::string &err) {
    std::error_code ec; fs::rename(from, to, ec);
    if (!ec) return true;
    ec.clear(); fs::copy_file(from, to, fs::copy_options::none, ec);          // cross-device: copy, then remove the original
    if (ec) { err = ec.message(); return false; }
    fs::remove(from, ec);
    if (ec) { std::error_code e2; fs::remove(to, e2); err = "copied but cannot remove original: " + ec.message(); return false; }
    return true;
}
// Only regular files are acted on (lstat semantics): a symlink swapped in after the scan is never followed.
static bool is_plain_file(const std::string &p, unsigned long long &size) {
    std::error_code ec; auto st = fs::symlink_status(P(p), ec);
    if (ec || st.type() != fs::file_type::regular) return false;
    size = (unsigned long long)fs::file_size(P(p), ec); if (ec) size = 0; return true;
}
static bool q_add(const std::string &path, const std::string &threat, std::string &err) {
    unsigned long long sz; if (!is_plain_file(path, sz)) { err = "not a regular file (already removed or replaced)"; return false; }
    make_private_dir(qdir()); FileLock lk(qdir() + "/.lock");
    std::string id = new_id(); fs::path dest = P(qdir()) / P(id + ".quar");
    if (!move_or_copy(P(path), dest, err)) return false;
#ifndef _WIN32
    chmod(u8(dest).c_str(), 0400);        // quarantined file: not writable, not executable
#endif
    std::string sha; sha256_file(u8(dest), sha);      // v2: hash the stored copy (not the original) so the vault records exactly what it holds
    auto v = q_list(); v.push_back({id, threat, path, sha, time(nullptr), sz});
    if (!q_write_index(v)) { err = "quarantine index could not be written (file is stored as " + id + ".quar)"; return false; }
    return true;
}
// Restore.  v2: the stored file's SHA-256 is verified first (refuse on mismatch unless force).  With `sandbox` set the file is COPIED
// into that folder as "<name>.infected" (never overwriting) and stays in the vault, for safe analysis.
static bool q_restore(const std::string &id, std::string &outpath, std::string &err, const std::string &sandbox = "", bool force = false) {
    FileLock lk(qdir() + "/.lock"); auto v = q_list();
    for (size_t i = 0; i < v.size(); i++) if (v[i].id == id) {
        fs::path src = P(qdir()) / P(id + ".quar"), dst; std::error_code ec;
        if (!fs::exists(symlink_status(src, ec))) { err = "quarantined file is missing"; return false; }
        if (!v[i].sha.empty() && !force) { std::string h; if (!sha256_file(u8(src), h) || h != v[i].sha) { err = "INTEGRITY CHECK FAILED: the stored file no longer matches its recorded SHA-256 (use --force to override)"; return false; } }
        std::string want = sandbox.empty() ? v[i].path : u8(P(sandbox) / P(v[i].path).filename()) + ".infected";
        dst = P(want);
        for (int n = 0; fs::exists(fs::symlink_status(dst, ec)); n++) { dst = P(want + ".restored" + (n ? std::to_string(n) : "")); if (n > 50) { err = "cannot find a free file name"; return false; } }   // never overwrite
        fs::create_directories(dst.parent_path(), ec);
        if (!sandbox.empty()) {
            fs::copy_file(src, dst, fs::copy_options::none, ec); if (ec) { err = ec.message(); return false; }
#ifndef _WIN32
            chmod(u8(dst).c_str(), 0400);       // analysis copy: read-only, never executable
#endif
            outpath = u8(dst); return true;
        }
        if (!move_or_copy(src, dst, err)) return false;
#ifndef _WIN32
        chmod(u8(dst).c_str(), 0600);
#endif
        outpath = u8(dst); v.erase(v.begin() + (long)i); q_write_index(v); return true;
    }
    err = "no such quarantine item"; return false;
}
static bool q_delete(const std::string &id, std::string &err) {
    FileLock lk(qdir() + "/.lock"); auto v = q_list();
    for (size_t i = 0; i < v.size(); i++) if (v[i].id == id) {
        std::error_code ec; fs::remove(P(qdir()) / P(id + ".quar"), ec);
        if (ec) { err = ec.message(); return false; }
        v.erase(v.begin() + (long)i); return q_write_index(v);
    }
    err = "no such quarantine item"; return false;
}

// ---- v2 NEW: tamper-evident evidence export.  A JSON manifest of the vault is signed with an Ed25519 key (via the openssl CLI) so a
// third party holding the .pub.pem can verify it; where openssl is missing it falls back to an HMAC-SHA256 that only this machine can verify.
static std::string vault_hmac_key() {
    std::string kf = config_dir() + "/vault.key", k; read_file(kf, k, 4096); k = trim(k);
    if (is_hex_n(k, 64)) return k;
    std::random_device rd; unsigned char b[32]; for (auto &c : b) c = (unsigned char)(rd() & 0xff);
    make_private_dir(config_dir()); k = hex(b, 32); write_file_atomic(kf, k + "\n"); return k;
}
static std::string iso_time(time_t t) { struct tm g;
#ifdef _WIN32
    gmtime_s(&g, &t);
#else
    gmtime_r(&t, &g);
#endif
    char b[40]; strftime(b, sizeof b, "%Y-%m-%dT%H:%M:%SZ", &g); return b; }
static bool q_export(const std::string &out, std::string &msg) {
    FileLock lk(qdir() + "/.lock"); auto v = q_list();
    std::string j = "{\n \"generator\": \"ClamGUI v" CLAMGUI_VERSION "\",\n \"created\": \"" + iso_time(time(nullptr)) + "\",\n \"host\": \"" + json_esc(host_name()) + "\",\n \"user\": \"" + json_esc(user_name()) + "\",\n \"items\": [";
    for (size_t i = 0; i < v.size(); i++) {
        std::string sha = v[i].sha; if (sha.empty()) sha256_file(qdir() + "/" + v[i].id + ".quar", sha);
        j += std::string(i ? "," : "") + "\n  {\"id\": \"" + v[i].id + "\", \"time\": \"" + iso_time(v[i].when) + "\", \"threat\": \"" + json_esc(v[i].threat) + "\", \"path\": \"" + json_esc(v[i].path) + "\", \"size\": " + std::to_string(v[i].size) + ", \"sha256\": \"" + sha + "\"}";
    }
    j += "\n ]\n}\n";
    if (!write_file_atomic(out, j)) { msg = "cannot write " + out; return false; }
    std::string ossl = find_tool("openssl"), cap;
    if (!ossl.empty()) {
        std::string key = config_dir() + "/vault_ed25519.pem"; std::error_code ec;
        make_private_dir(config_dir());
        if (!fs::exists(P(key), ec) && run_capture({ossl, "genpkey", "-algorithm", "ED25519", "-out", key}, cap) != 0) ossl.clear();
#ifndef _WIN32
        else chmod(key.c_str(), 0600);
#endif
        if (!ossl.empty() && run_capture({ossl, "pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", out, "-out", out + ".sig"}, cap) == 0 &&
            run_capture({ossl, "pkey", "-in", key, "-pubout", "-out", out + ".pub.pem"}, cap) == 0) {
            std::string fp; sha256_file(out + ".pub.pem", fp);
            msg = "Exported " + std::to_string(v.size()) + " item(s) to " + out + "\nSigned with Ed25519: " + out + ".sig\nPublic key: " + out + ".pub.pem (fingerprint " + fp.substr(0, 16) + ")\nGive the public key to the verifier through a separate channel.";
            return true;
        }
    }
    std::string h = hmac_sha256(vault_hmac_key(), j);
    if (!write_file_atomic(out + ".hmac", "hmac-sha256=" + h + "\n")) { msg = "cannot write signature"; return false; }
    msg = "Exported " + std::to_string(v.size()) + " item(s) to " + out + "\nopenssl was not available: signed with HMAC-SHA256 (" + out + ".hmac), verifiable only on this machine.";
    return true;
}
static bool q_verify_export(const std::string &file, std::string &msg) {
    std::string j; if (!read_file(file, j, 64u << 20)) { msg = "cannot read " + file; return false; }
    std::error_code ec; bool sig_ok = false; std::string how;
    if (fs::exists(P(file + ".sig"), ec) && fs::exists(P(file + ".pub.pem"), ec)) {
        std::string ossl = find_tool("openssl"), cap; if (ossl.empty()) { msg = "openssl is needed to verify an Ed25519 signature"; return false; }
        sig_ok = run_capture({ossl, "pkeyutl", "-verify", "-pubin", "-inkey", file + ".pub.pem", "-rawin", "-in", file, "-sigfile", file + ".sig"}, cap) == 0;
        std::string fp; sha256_file(file + ".pub.pem", fp); how = "Ed25519, key fingerprint " + fp.substr(0, 16) + " (compare it with the one you were given)";
    } else if (fs::exists(P(file + ".hmac"), ec)) {
        std::string t; read_file(file + ".hmac", t, 4096); t = trim(t); std::string want = starts_with(t, "hmac-sha256=") ? t.substr(12) : "";
        sig_ok = is_hex_n(want, 64) && ct_equal(want, hmac_sha256(vault_hmac_key(), j)); how = "HMAC-SHA256 (local key)";
    } else { msg = "no signature file (.sig/.pub.pem or .hmac) next to the manifest"; return false; }
    if (!sig_ok) { msg = "SIGNATURE INVALID - the manifest was modified or signed with a different key. (" + how + ")"; return false; }
    // cross-check the vault against the manifest
    auto v = q_list(); int match = 0, bad = 0, missing = 0; size_t pos = 0;
    while ((pos = j.find("\"id\": \"", pos)) != std::string::npos) {
        pos += 7; std::string id = j.substr(pos, 16); size_t sp = j.find("\"sha256\": \"", pos); if (sp == std::string::npos) break; std::string want = j.substr(sp + 11, 64);
        std::string h; if (!is_hex_n(id, 16) || !sha256_file(qdir() + "/" + id + ".quar", h)) { missing++; continue; } if (h == want) match++; else bad++;
    }
    (void)v;
    msg = "Signature valid: " + how + "\nVault check: " + std::to_string(match) + " file(s) match, " + std::to_string(bad) + " CHANGED, " + std::to_string(missing) + " no longer in this vault.";
    return bad == 0;
}

// ============================================================================================ scan session (GUI-independent)
struct Threat { std::string name, path, action, sha; };

// ---- managed clamd (v2): a long-lived daemon makes GUI scans start instantly (signatures load once) and also backs real-time protection
static bool g_daemon_ready = false;                      // set by the GUI when clamd printed its "ready" line
static std::string daemon_conf() { return data_dir() + "/clamd.conf"; }
[[maybe_unused]] static std::string daemon_sock() { return data_dir() + "/clamd.sock"; }
static bool write_daemon_conf(std::string &err) {
    make_private_dir(data_dir());
    auto clean = [](std::string x) { for (char &c : x) if (c == '\n' || c == '\r') c = ' '; return x; };
    int mb = g_cfg.geti("max_file_mb", 100); if (mb < 1 || mb > 4000) mb = 100;
    std::string o = "# generated by ClamGUI v" CLAMGUI_VERSION "\nDatabaseDirectory " + clean(db_dir()) + "\n";
    if (!g_cfg.get("certs_dir").empty()) o += "CVDCertsDirectory " + clean(g_cfg.get("certs_dir")) + "\n";
    o += "Foreground yes\nLogTime yes\nMaxThreads 4\nStreamMaxLength " + std::to_string(mb) + "M\nMaxFileSize " + std::to_string(mb) + "M\nFollowFileSymlinks no\nFollowDirectorySymlinks no\n";
    o += std::string("ScanArchive ") + (g_cfg.geti("scan_archives", 1) ? "yes" : "no") + "\nDetectPUA " + (g_cfg.geti("scan_pua", 0) ? "yes" : "no") + "\n";
    for (auto &l : split(g_cfg.get("excludes"), '\n')) { std::string r = trim(clean(l)); if (!r.empty()) o += "ExcludePath " + r + "\n"; }
#ifdef _WIN32
    o += "TCPSocket 3310\nTCPAddr 127.0.0.1\n";
#else
    o += "LocalSocket " + daemon_sock() + "\nLocalSocketMode 600\n"; if (geteuid() == 0) o += "User root\n";
#endif
    if (!write_file_atomic(daemon_conf(), o)) { err = "cannot write " + daemon_conf(); return false; }
    return true;
}

struct ScanSession {
    std::vector<std::string> targets; std::vector<Threat> threats;
    long scanned = 0, infected = 0, errors = 0, skipped = 0; std::string summary, repPath, current, listfile, reason, engine; int code = -1; bool finished = false; size_t nlist = 0;
    Proc proc; FILE *rep = nullptr; time_t t0 = 0;
    std::function<void(int, const std::string &)> sink;       // kind: 0 log line, 1 threat, 2 error line
    ~ScanSession() { if (rep) fclose(rep); drop_listfile(); }
    void drop_listfile() { if (!listfile.empty()) { std::error_code ec; fs::remove(P(listfile), ec); listfile.clear(); } }

    static std::vector<std::string> base_args() {
        std::vector<std::string> a = {g_cfg.get("clamscan"), "--stdout", "--database=" + db_dir(), "--follow-dir-symlinks=0", "--follow-file-symlinks=0", "--recursive=yes"};
        if (!g_cfg.get("certs_dir").empty()) a.push_back("--cvdcertsdir=" + g_cfg.get("certs_dir"));   // portable / custom builds have no compiled-in certs path
        a.push_back(std::string("--scan-archive=") + (g_cfg.geti("scan_archives", 1) ? "yes" : "no"));
        if (g_cfg.geti("scan_pua", 0)) a.push_back("--detect-pua=yes");
        int mb = g_cfg.geti("max_file_mb", 100); if (mb < 1 || mb > 4000) mb = 100;
        a.push_back("--max-filesize=" + std::to_string(mb) + "M");
        for (auto &l : split(g_cfg.get("excludes"), '\n')) { std::string r = trim(l); if (r.empty()) continue; a.push_back("--exclude=" + r); a.push_back("--exclude-dir=" + r); }
        return a;
    }
    // v2: if the managed clamd is ready (GUI, engine = fast) scans go through clamdscan; otherwise the classic clamscan path is used.
    bool use_daemon() const { std::string c = g_cfg.get("clamdscan"); return g_cfg.geti("engine", 0) == 1 && g_daemon_ready && !c.empty() && is_exec_file(c); }
    bool begin(const std::vector<std::string> &t, std::string &err) {
        targets = t;
        bool daemon = use_daemon();
        if (!daemon && (g_cfg.get("clamscan").empty() || !is_exec_file(g_cfg.get("clamscan")))) { err = "clamscan was not found - set its path on the Settings tab."; return false; }
        if (!has_any_db(db_dir())) { err = "There is no virus database in " + db_dir() + ".\nUse the Update tab to download one first."; return false; }
        if (targets.empty() && listfile.empty()) { err = "Nothing to scan."; return false; }
        std::vector<std::string> a;
        if (daemon) {
            a = {g_cfg.get("clamdscan"), "--config-file=" + daemon_conf(),
#ifdef _WIN32
                 "--stream",
#else
                 "--fdpass", "--multiscan",
#endif
                 "--stdout"};
            engine = "clamd (fast)";
        } else { a = base_args(); engine = "clamscan"; }
        if (!listfile.empty()) a.push_back("--file-list=" + listfile);
        else for (auto &x : targets) a.push_back(!x.empty() && x[0] == '-' ? "./" + x : x);     // a path can never be parsed as an option
        make_private_dir(reports_dir()); t0 = time(nullptr);
        repPath = reports_dir() + "/scan-" + tstamp("%Y%m%d-%H%M%S", t0) + ".log";
        std::string rp = repPath;
#ifdef _WIN32
        rep = _wfopen(u2w(rp).c_str(), L"wb");
#else
        rep = fopen(rp.c_str(), "wb");
#endif
        if (rep) {
            fprintf(rep, "ClamGUI v" CLAMGUI_VERSION " scan report\nStarted: %s\nEngine: %s\n", tstamp("%Y-%m-%d %H:%M:%S", t0).c_str(), engine.c_str());
            if (!reason.empty()) fprintf(rep, "Reason: %s\n", reason.c_str());
            if (!listfile.empty()) fprintf(rep, "File list: %zu file(s), riskiest first\n\n", nlist); else { fprintf(rep, "Targets:\n"); for (auto &x : targets) fprintf(rep, "  %s\n", x.c_str()); fprintf(rep, "\n"); }
        }
        if (!proc.start(a, err)) { if (rep) { fclose(rep); rep = nullptr; } std::error_code ec; fs::remove(P(rp), ec); return false; }
        return true;
    }
    std::string act_on(Threat &t) {
        int mode = g_cfg.geti("action", 0); std::string e; unsigned long long sz = 0;
        if (is_plain_file(t.path, sz) && sz <= (512ull << 20)) sha256_file(t.path, t.sha);       // v2: hash before any action, for reports and lookups
        if (mode == 1) return q_add(t.path, t.name, e) ? "quarantined" : "FAILED: " + e;
        if (mode == 2) { if (!is_plain_file(t.path, sz)) return "FAILED: not a regular file"; std::error_code ec; fs::remove(P(t.path), ec); return ec ? "FAILED: " + ec.message() : "deleted"; }
        return "reported";
    }
    void emit(int kind, const std::string &s) { if (rep && kind != 3) fprintf(rep, "%s\n", s.c_str()); if (sink && kind != 3) sink(kind, s); }
    void handle(const std::string &raw) {
        std::string line = sane(raw); if (line.empty()) return;
        if (ends_with(line, " FOUND")) {
            size_t c = line.rfind(": "); if (c == std::string::npos) { emit(0, line); return; }
            Threat t; t.path = raw.substr(0, raw.rfind(": ")); t.name = line.substr(c + 2, line.size() - c - 2 - 6);     // raw path is kept unsanitised so the file can be found again
            if (!t.path.empty() && t.path.size() > 16384) t.path.clear();
            infected++; scanned++; t.action = t.path.empty() ? "FAILED: path too long" : act_on(t); threats.push_back(t);
            emit(1, t.name + "\t" + sane(t.path) + "\t" + t.action); return;
        }
        if (ends_with(line, ": OK")) { scanned++; current = line.substr(0, line.size() - 4); return; }
        if (ends_with(line, ": Empty file")) { skipped++; return; }
        if (ends_with(line, " ERROR") || starts_with(line, "ERROR") || line.find("Can't access file") != std::string::npos || line.find("Access denied") != std::string::npos) { errors++; emit(2, line); return; }
        if (starts_with(line, "Scanned files:") || starts_with(line, "Infected files:") || starts_with(line, "Data scanned:") || starts_with(line, "Time:") || starts_with(line, "Known viruses:") || starts_with(line, "Engine version:")) { summary += line + "\n"; }
        emit(0, line);
    }
    void finish(int c) {
        code = c; finished = true; time_t t1 = time(nullptr);
        const char *res = (c == 0 && !errors) ? "clean" : (infected ? "infected" : (c == 0 ? "clean" : "error"));
        if (c == 1 && !infected) res = "infected";
        if (rep) { fprintf(rep, "\nFinished: %s (exit code %d)\nScanned %ld, infected %ld, errors %ld\n", tstamp("%Y-%m-%d %H:%M:%S", t1).c_str(), c, scanned, infected, errors); fclose(rep); rep = nullptr;
            std::string fin = repPath.substr(0, repPath.size() - 4) + "-" + res + ".log"; std::error_code ec; fs::rename(P(repPath), P(fin), ec); if (!ec) repPath = fin; }
        drop_listfile();
    }
};

// ---- v2 NEW: fleet report upload (JSON over HTTPS, bearer token from CLAMGUI_REPORT_TOKEN) and desktop alerts, run after every scan
static std::string report_json(const ScanSession &s) {
    bool paths = g_cfg.geti("report_paths", 1) != 0;
    std::string j = "{\n \"generator\": \"ClamGUI v" CLAMGUI_VERSION "\",\n \"host\": \"" + json_esc(host_name()) + "\",\n \"user\": \"" + json_esc(user_name()) + "\",\n \"started\": \"" + iso_time(s.t0) + "\",\n \"reason\": \"" + json_esc(s.reason) +
                    "\",\n \"engine\": \"" + json_esc(s.engine) + "\",\n \"scanned\": " + std::to_string(s.scanned) + ", \"infected\": " + std::to_string(s.infected) + ", \"errors\": " + std::to_string(s.errors) + ", \"exit_code\": " + std::to_string(s.code) + ",\n \"threats\": [";
    for (size_t i = 0; i < s.threats.size(); i++) { auto &t = s.threats[i]; j += std::string(i ? "," : "") + "\n  {\"name\": \"" + json_esc(t.name) + "\", \"path\": \"" + json_esc(paths ? t.path : u8(P(t.path).filename())) + "\", \"sha256\": \"" + t.sha + "\", \"action\": \"" + json_esc(t.action) + "\"}"; }
    return j + "\n ]\n}\n";
}
static bool report_request(const ScanSession &s, CurlReq &r, std::string &err) {
    std::string url = g_cfg.get("report_url"); if (url.empty()) return false;
    r.url = url; r.method = "POST"; r.body = report_json(s); r.headers = {"Content-Type: application/json"};
    std::string tok = env("CLAMGUI_REPORT_TOKEN"); for (char c : tok) if (c < 0x21 || c > 0x7e) { err = "invalid CLAMGUI_REPORT_TOKEN"; return false; }
    if (!tok.empty()) r.secret_headers = {"Authorization: Bearer " + tok};
    return url_ok(url, err);
}
// sync = headless runs (wait for the upload); otherwise fire-and-forget through the pump
static std::string post_scan(const ScanSession &s, bool sync) {
    std::string note;
    if (s.infected > 0 && (!s.reason.empty() || sync)) {
        std::string first = s.threats.empty() ? "" : s.threats[0].name + " in " + sane(u8(P(s.threats[0].path).filename()), 80);
        notify("ClamGUI: " + std::to_string(s.infected) + " threat(s) found", first + (s.infected > 1 ? " (+" + std::to_string(s.infected - 1) + " more)" : "") + (s.reason.empty() ? "" : " - " + s.reason));
    }
    CurlReq r; std::string err; if (!report_request(s, r, err)) { if (!err.empty()) note = "report upload skipped: " + err; return note; }
    if (sync) { int http = 0; std::string body;   /* v3 FIX: init */ if (!curl_sync(r, http, body, err)) note = "report upload failed: " + err; else if (http < 200 || http > 299) note = "report upload rejected (HTTP " + std::to_string(http) + ")"; else note = "report uploaded"; }
    else if (!curl_async(r, [](bool ok, int http, const std::string &, const std::string &e) { (void)ok; (void)http; (void)e; }, err)) note = "report upload failed: " + err;
    return note;
}
static void prune_reports(size_t keep = 200) {
    std::vector<std::string> v; std::error_code ec;
    for (fs::directory_iterator it(P(reports_dir()), ec), end; !ec && it != end; it.increment(ec)) if (it->path().extension() == ".log") v.push_back(u8(it->path()));
    std::sort(v.begin(), v.end());
    for (size_t i = 0; i + keep < v.size(); i++) fs::remove(P(v[i]), ec);
}

// ============================================================================================ update (freshclam)
static bool write_freshclam_conf(std::string &path, std::string &err) {
    make_private_dir(config_dir()); make_private_dir(db_dir());
    auto clean = [](std::string s) { for (char &c : s) if (c == '\n' || c == '\r') c = ' '; return s; };
    std::string o = "# generated by ClamGUI v" CLAMGUI_VERSION "\nDatabaseDirectory " + clean(db_dir()) + "\nDatabaseMirror database.clamav.net\nConnectTimeout 30\nReceiveTimeout 120\nScriptedUpdates yes\n";
#ifndef _WIN32
    if (geteuid() == 0) o += "DatabaseOwner root\n";       // as root freshclam would otherwise try to drop to a "clamav" user that may not exist
#endif
    if (!g_cfg.get("certs_dir").empty()) o += "CVDCertsDirectory " + clean(g_cfg.get("certs_dir")) + "\n";
    std::string h = trim(clean(g_cfg.get("proxy_host"))), pt = trim(g_cfg.get("proxy_port"));
    if (!h.empty()) { o += "HTTPProxyServer " + h + "\n"; if (!pt.empty()) { int p = atoi(pt.c_str()); if (p < 1 || p > 65535) { err = "invalid proxy port"; return false; } o += "HTTPProxyPort " + std::to_string(p) + "\n"; } }
    path = config_dir() + "/freshclam.conf";
    if (!write_file_atomic(path, o)) { err = "cannot write " + path; return false; }
    return true;
}
static std::vector<std::string> update_args(std::string &err) {
    if (g_cfg.get("freshclam").empty() || !is_exec_file(g_cfg.get("freshclam"))) { err = "freshclam was not found - set its path on the Settings tab."; return {}; }
    std::string conf; if (!write_freshclam_conf(conf, err)) return {};
    return {g_cfg.get("freshclam"), "--config-file=" + conf, "--datadir=" + db_dir(), "--stdout"};
}

// ============================================================================================ scheduling (Task Scheduler / cron)
static bool valid_hhmm(const std::string &s) { int h, m; char x; return s.size() == 5 && sscanf(s.c_str(), "%d:%d%c", &h, &m, &x) == 2 && s[2] == ':' && h >= 0 && h < 24 && m >= 0 && m < 60; }
#ifndef _WIN32
static std::string sq(const std::string &s) { std::string o = "'"; for (char c : s) { if (c == '\'') o += "'\\''"; else o += c; } return o + "'"; }
#endif
#ifndef _WIN32
static const char *CRON_BEGIN = "# BEGIN clamgui", *CRON_END = "# END clamgui";
#endif

static bool sched_apply(bool upd_on, const std::string &upd_time, bool scan_on, const std::string &scan_time, const std::string &days, std::string &msg) {
    if (upd_on && !valid_hhmm(upd_time)) { msg = "Update time must be HH:MM (24 h)."; return false; }
    if (scan_on && !valid_hhmm(scan_time)) { msg = "Scan time must be HH:MM (24 h)."; return false; }
    if (scan_on && days.find('1') == std::string::npos) { msg = "Select at least one day for the scheduled scan."; return false; }
    std::string exe = exe_path(); if (exe.empty()) { msg = "Cannot determine the program path."; return false; }
#ifdef _WIN32
    static const char *dn[] = {"MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"}; std::string out;
    auto del = [&](const char *name) { run_capture({"schtasks", "/Delete", "/TN", name, "/F"}, out); };
    del("ClamGUI Update"); del("ClamGUI Scan");
    if (upd_on) { if (run_capture({"schtasks", "/Create", "/F", "/TN", "ClamGUI Update", "/TR", "\"" + exe + "\" --scheduled-update", "/SC", "DAILY", "/ST", upd_time}, out) != 0) { msg = "schtasks failed:\n" + out; return false; } }
    if (scan_on) {
        std::string d; for (int i = 0; i < 7 && i < (int)days.size(); i++) if (days[i] == '1') { if (!d.empty()) d += ","; d += dn[i]; }
        if (run_capture({"schtasks", "/Create", "/F", "/TN", "ClamGUI Scan", "/TR", "\"" + exe + "\" --scheduled-scan", "/SC", "WEEKLY", "/D", d, "/ST", scan_time}, out) != 0) { msg = "schtasks failed:\n" + out; return false; }
    }
    msg = std::string("Scheduled tasks updated (") + (upd_on ? "update on" : "update off") + ", " + (scan_on ? "scan on" : "scan off") + ").";
    return true;
#else
    std::string cur, cleaned; int rc = run_capture({"crontab", "-l"}, cur);
    if (rc < 0) { msg = "crontab is not available on this system."; return false; }
    bool skip = false;
    if (rc == 0) { auto lines = split(cur, '\n'); if (!lines.empty() && lines.back().empty()) lines.pop_back();
        for (auto &l : lines) { if (l == CRON_BEGIN) { skip = true; continue; } if (l == CRON_END) { skip = false; continue; } if (!skip) cleaned += l + "\n"; } }
    std::string blk;
    if (upd_on) blk += std::to_string(atoi(upd_time.c_str() + 3)) + " " + std::to_string(atoi(upd_time.c_str())) + " * * * " + sq(exe) + " --scheduled-update >/dev/null 2>&1\n";
    if (scan_on) { std::string d; for (int i = 0; i < 7 && i < (int)days.size(); i++) if (days[i] == '1') { if (!d.empty()) d += ","; d += std::to_string(i + 1 == 7 ? 0 : i + 1); }
        blk += std::to_string(atoi(scan_time.c_str() + 3)) + " " + std::to_string(atoi(scan_time.c_str())) + " * * " + d + " " + sq(exe) + " --scheduled-scan >/dev/null 2>&1\n"; }
    if (!blk.empty()) cleaned += std::string(CRON_BEGIN) + "\n" + blk + CRON_END + "\n";
    make_private_dir(config_dir()); std::string tmp = config_dir() + "/crontab.tmp";
    if (!write_file_atomic(tmp, cleaned)) { msg = "cannot write temporary crontab"; return false; }
    std::string out; rc = run_capture({"crontab", tmp}, out); std::error_code ec; fs::remove(P(tmp), ec);
    if (rc != 0) { msg = "crontab failed:\n" + out; return false; }
    msg = std::string("Crontab updated (") + (upd_on ? "update on" : "update off") + ", " + (scan_on ? "scan on" : "scan off") + ").";
    return true;
#endif
}
static std::string sched_status() {
    std::string out;
#ifdef _WIN32
    std::string r;
    for (const char *n : {"ClamGUI Update", "ClamGUI Scan"}) { run_capture({"schtasks", "/Query", "/TN", n, "/FO", "LIST"}, out); r += std::string(n) + ": " + (out.find("Next Run Time") != std::string::npos ? "installed\n" : "not installed\n"); }
    return r;
#else
    if (run_capture({"crontab", "-l"}, out) != 0) return "No crontab entries (or crontab unavailable).";
    std::string r; bool in = false; for (auto &l : split(out, '\n')) { if (l == CRON_BEGIN) { in = true; continue; } if (l == CRON_END) in = false; else if (in) r += l + "\n"; }
    return r.empty() ? "No ClamGUI schedule installed." : r;
#endif
}

// ============================================================================================ headless modes
#ifdef _WIN32
static void attach_console() { if (AttachConsole(ATTACH_PARENT_PROCESS)) { freopen("CONOUT$", "w", stdout); freopen("CONOUT$", "w", stderr); } }
#else
static void attach_console() {}
#endif

// v2: optional file list (risk-ordered), reason (used for notifications / reports), report upload + desktop alert after the scan
static int cli_scan(const std::vector<std::string> &targets, bool quiet, const std::string &listfile = "", size_t nlist = 0, const std::string &reason = "") {
    ScanSession s; s.listfile = listfile; s.nlist = nlist; s.reason = reason;
    s.sink = [&](int k, const std::string &t) { if (quiet && k == 0) return; if (k == 1) { auto f = split(t, '\t'); printf("FOUND: %s: %s [%s]\n", f.size() > 1 ? f[1].c_str() : "?", f[0].c_str(), f.size() > 2 ? f[2].c_str() : ""); } else printf("%s\n", t.c_str()); fflush(stdout); };
    std::string err; if (!s.begin(targets, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 2; }
    Msg m; for (;;) { s.proc.pop(m, true); if (m.type == 1) { s.finish(m.code); break; } s.handle(m.s); }
    printf("Scanned %ld files, %ld infected, %ld errors (report: %s)\n", s.scanned, s.infected, s.errors, s.repPath.c_str());
    std::string note = post_scan(s, true); if (!note.empty()) printf("%s\n", note.c_str());
    prune_reports();
    return s.code == 1 || s.infected ? 1 : (s.code == 0 && !s.errors ? 0 : 2);
}
static int cli_scan_recent(const std::string &dir, int days) {
    auto files = recent_files(dir, days); if (g_nl_skipped > 0) fprintf(stderr, "warning: %d file(s) with a newline in the name could not be listed and were NOT scanned\n", g_nl_skipped.load());   // v3
    if (files.empty()) { printf("No files changed in the last %d day(s) under %s\n", days, dir.c_str()); return 0; }
    std::string lf = write_listfile(files); if (lf.empty()) { fprintf(stderr, "error: cannot write the file list\n"); return 2; }
    printf("Scanning %zu recent file(s) under %s, riskiest first\n", files.size(), dir.c_str());
    return cli_scan({}, false, lf, files.size(), "recent files");
}
static int cli_lookup(const std::string &sha) {
    CurlReq r; std::string err; if (!intel_build(sha, r, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 2; }
    int http = 0; std::string body; if (!curl_sync(r, http, body, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 2; }
    printf("%s\n", intel_summary(g_cfg.geti("intel_provider", 0), http, body).c_str()); return 0;
}
static int cli_update() {
    std::string err; auto a = update_args(err); if (a.empty()) { fprintf(stderr, "error: %s\n", err.c_str()); return 2; }
    Proc p; if (!p.start(a, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 2; }
    make_private_dir(reports_dir()); std::string rp = reports_dir() + "/update-" + tstamp("%Y%m%d-%H%M%S", time(nullptr)) + ".log", body; Msg m; int code;
    for (;;) { p.pop(m, true); if (m.type == 1) { code = m.code; break; } std::string l = sane(m.s); printf("%s\n", l.c_str()); body += l + "\n"; if (body.size() > (4u << 20)) body.resize(4u << 20); }
    write_file_atomic(rp.substr(0, rp.size() - 4) + (code == 0 ? "-clean" : "-error") + ".log", "ClamGUI v" CLAMGUI_VERSION " update report\n\n" + body + "\nExit code " + std::to_string(code) + "\n");
    return code == 0 ? 0 : 2;
}
static int cli_quarantine(const std::string &op, const std::string &id, const std::string &to = "", bool force = false) {
    std::string err, out;
    if (op == "list") { for (auto &q : q_list()) printf("%s\t%s\t%s\t%s\t%s\t%s\n", q.id.c_str(), tstamp("%Y-%m-%d %H:%M:%S", q.when).c_str(), q.threat.c_str(), q.path.c_str(), human(q.size).c_str(), q.sha.c_str()); return 0; }
    if (op == "restore") { if (!q_restore(id, out, err, to, force)) { fprintf(stderr, "error: %s\n", err.c_str()); return 2; } printf("%s to %s\n", to.empty() ? "restored" : "analysis copy written", out.c_str()); return 0; }
    if (op == "export") { if (!q_export(id, out)) { fprintf(stderr, "error: %s\n", out.c_str()); return 2; } printf("%s\n", out.c_str()); return 0; }
    if (op == "verify") { bool ok = q_verify_export(id, out); printf("%s\n", out.c_str()); return ok ? 0 : 2; }
    if (!q_delete(id, err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 2; } printf("deleted\n"); return 0;
}
static void usage() {
    printf("ClamGUI v" CLAMGUI_VERSION " - graphical front-end for ClamAV\n\nUsage: clamgui [options] [PATH ...]\n"
           "  PATH ...               open the GUI and scan these files/folders\n"
           "  --scan PATH ...        headless scan (exit 0 clean, 1 infected, 2 error)\n"
           "  --scheduled-scan       headless scan of the folder set on the Schedule tab\n"
           "  --scheduled-update     headless signature update\n"
           "  --install-schedule | --remove-schedule   apply / remove the schedule stored in the settings\n"
           "  --scan-recent [DIR] [--days N]   scan files changed in the last N days (default 14) under DIR (default: Downloads), riskiest first\n"
           "  --quarantine-list | --restore ID [--to DIR] [--force] | --delete ID\n"
           "      --restore ID --to DIR writes a read-only analysis copy (name.infected) and keeps the item in the vault\n"
           "  --export-evidence FILE | --verify-export FILE   signed (Ed25519 via openssl, else HMAC) manifest of the quarantine vault\n"
           "  --lookup SHA256        hash-only lookup (MalwareBazaar / VirusTotal; configure on the Advanced tab)\n"
           "  --sha256 FILE...       print SHA-256 hashes;  --policy-sign FILE  append an hmac= line (key in CLAMGUI_POLICY_KEY)\n"
           "  --service              run clamd + clamrt in the background without the GUI (systemd / Windows service)\n"
           "  --print-systemd-unit   (Linux) print a hardened systemd unit for --service\n"
           "  --install-service | --remove-service   (Windows) register / remove the background service (asks for administrator rights)\n"
           "  --install-filemanager | --remove-filemanager   (Linux) add / remove Nautilus, Dolphin, Thunar menu entries\n"
           "  --home DIR             store config and data under DIR (portable mode)\n"
           "  --version | --help\nEnvironment: CLAMGUI_HOME=DIR stores config and data under DIR\n");
}

// ============================================================================================ v2 NEW: real-time arguments, supervisor / service, file-manager menus, watchers
// clamd's stdout is a pipe, so its "ready" line can be delayed by buffering: also ask the daemon itself (clamdscan --ping, exit 0 on PONG).
static bool clamd_ping() {
    std::string c = g_cfg.get("clamdscan"); if (c.empty() || !is_exec_file(c)) return false;
    std::string out; return run_capture({c, "--config-file=" + daemon_conf(), "--ping", "1:1"}, out) == 0;
}
static bool clamd_ready_line(const std::string &l) { return l.find("Self checking every") != std::string::npos || l.find("Listening daemon") != std::string::npos || l.find("Bound to") != std::string::npos; }
// clamrt command line from the settings (shared by the GUI Real-time tab and the background service)
static std::vector<std::string> build_clamrt_args(std::string &err) {
    std::string rt = g_cfg.get("clamrt"); if (rt.empty() || !is_exec_file(rt)) { err = "clamrt was not found - set its path on the Settings tab."; return {}; }
    std::vector<std::string> a = {rt};
    for (auto &l : split(g_cfg.get("rt_paths"), '\n')) { std::string t = trim(l); if (!t.empty()) { a.push_back("--path"); a.push_back(t); } }
    if (a.size() == 1) { err = "No folders to watch - add at least one."; return {}; }
#ifdef _WIN32
    a.push_back("--clamd-host"); a.push_back("127.0.0.1"); a.push_back("--clamd-port"); a.push_back("3310");
#else
    a.push_back("--clamd-socket"); a.push_back(daemon_sock());
#endif
    if (g_cfg.geti("rt_action", 0) == 1) { std::string qd = data_dir() + "/rt-quarantine"; make_private_dir(qd); a.push_back("--action"); a.push_back("quarantine"); a.push_back("--quarantine-dir"); a.push_back(qd); }
    else { a.push_back("--action"); a.push_back("report"); }
    if (g_cfg.geti("rt_blockexec", 0)) a.push_back("--block-exec");
    return a;
}

// ---- supervisor: keeps clamd + clamrt running (restart with back-off).  Used by `--service` (systemd unit or Windows service).
static std::atomic<bool> g_svc_stop(false);
static void svc_log(const std::string &s) {
    std::string line = tstamp("%Y-%m-%d %H:%M:%S", time(nullptr)) + " " + sane(s) + "\n"; fputs(line.c_str(), stdout); fflush(stdout);
    make_private_dir(data_dir()); std::string lf = data_dir() + "/service.log"; std::error_code ec;
    if (fs::exists(P(lf), ec) && fs::file_size(P(lf), ec) > (5u << 20)) fs::rename(P(lf), P(lf + ".1"), ec);       // simple rotation
#ifdef _WIN32
    FILE *f = _wfopen(u2w(lf).c_str(), L"ab");
#else
    FILE *f = fopen(lf.c_str(), "ab");
#endif
    if (f) { fputs(line.c_str(), f); fclose(f); }
}
static bool svc_sleep(int ms) { for (int i = 0; i < ms / 50 && !g_svc_stop; i++) std::this_thread::sleep_for(std::chrono::milliseconds(50)); return !g_svc_stop; }
static int run_supervisor() {
    int backoff = 1; svc_log("ClamGUI v" CLAMGUI_VERSION " supervisor starting");
    while (!g_svc_stop) {
        std::string err; std::string cd = g_cfg.get("clamd");
        if (cd.empty() || !is_exec_file(cd)) { svc_log("clamd not found - set it in the settings"); if (!svc_sleep(30000)) break; continue; }
        if (!has_any_db(db_dir())) { svc_log("no virus database in " + db_dir() + " - waiting"); if (!svc_sleep(30000)) break; continue; }
        auto ra = build_clamrt_args(err); if (ra.empty()) { svc_log(err); if (!svc_sleep(30000)) break; continue; }
        if (!write_daemon_conf(err)) { svc_log(err); if (!svc_sleep(30000)) break; continue; }
        Proc clamd, rt; time_t started = time(nullptr); bool ready = false, rt_on = false;
        if (!clamd.start({cd, "--config-file=" + daemon_conf()}, err)) { svc_log(err); if (!svc_sleep(backoff * 1000)) break; backoff = std::min(backoff * 2, 60); continue; }
        svc_log("clamd started, loading signatures");
        bool dead = false; Msg m; bool ready_now = false; time_t last_ping = 0;
        while (!g_svc_stop && !dead) {
            bool any = false;
            while (clamd.pop(m, false)) { any = true; if (m.type == 1) { svc_log("clamd exited (code " + std::to_string(m.code) + ")"); dead = true; break; } if (!ready && clamd_ready_line(m.s)) ready_now = true; }
            if (!ready && !dead && !ready_now && time(nullptr) != last_ping) { last_ping = time(nullptr); if (clamd_ping()) ready_now = true; }
            if (ready_now && !ready && !dead) { ready = true; svc_log("clamd ready"); if (!rt.start(ra, err)) { svc_log("clamrt: " + err); dead = true; } else { rt_on = true; svc_log("clamrt started"); } }
            while (!dead && rt_on && rt.pop(m, false)) { any = true; if (m.type == 1) { svc_log("clamrt exited (code " + std::to_string(m.code) + ")"); dead = true; break; } svc_log("clamrt: " + m.s); }
            if (!ready && time(nullptr) - started > 600) { svc_log("clamd did not become ready in 10 minutes"); dead = true; }
            if (!any) std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        clamd.kill(); if (rt_on) rt.kill();
        for (int i = 0; i < 100; i++) { Msg x; bool c = false; while (clamd.pop(x, false)) if (x.type == 1) c = true; bool r = !rt_on; while (rt_on && rt.pop(x, false)) if (x.type == 1) r = true; if (c && r) break; std::this_thread::sleep_for(std::chrono::milliseconds(50)); }
        if (g_svc_stop) break;
        if (time(nullptr) - started > 60) backoff = 1;
        svc_log("restarting in " + std::to_string(backoff) + " s"); if (!svc_sleep(backoff * 1000)) break; backoff = std::min(backoff * 2, 60);
    }
    svc_log("supervisor stopped"); return 0;
}
[[maybe_unused]] static void print_systemd_unit() {
    std::string exe = exe_path();
    printf("# /etc/systemd/system/clamgui.service   (generated by ClamGUI v" CLAMGUI_VERSION ")\n"
           "# Install:  sudo install -m 0755 clamgui_v" CLAMGUI_VERSION "_linux_x86_64 /usr/local/sbin/clamgui\n"
           "#           sudo mkdir -p /var/lib/clamgui/config && sudo cp ~/.config/clamgui/clamgui.conf /var/lib/clamgui/config/\n"
           "#           sudo systemctl daemon-reload && sudo systemctl enable --now clamgui\n"
           "[Unit]\nDescription=ClamGUI real-time protection (clamd + clamrt)\nAfter=network.target\n\n"
           "[Service]\nExecStart=%s --home /var/lib/clamgui --service\nRestart=always\nRestartSec=2\nOOMScoreAdjust=-900\n"
           "NoNewPrivileges=yes\nProtectSystem=full\nProtectKernelModules=yes\nProtectKernelTunables=yes\nProtectControlGroups=yes\nLockPersonality=yes\nPrivateTmp=yes\n\n"
           "[Install]\nWantedBy=multi-user.target\n", (starts_with(exe, "/usr/") || starts_with(exe, "/opt/")) ? exe.c_str() : "/usr/local/sbin/clamgui");   // v3 FIX: ternary had identical branches; an already-installed binary under /usr or /opt now keeps its own path, anything else uses the documented install target
}

#ifdef _WIN32
static SERVICE_STATUS_HANDLE g_ssh = nullptr;
static void svc_report(DWORD state, DWORD wait = 0) { SERVICE_STATUS st{}; st.dwServiceType = SERVICE_WIN32_OWN_PROCESS; st.dwCurrentState = state; st.dwControlsAccepted = state == SERVICE_START_PENDING ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN); st.dwWaitHint = wait; if (g_ssh) SetServiceStatus(g_ssh, &st); }
static DWORD WINAPI svc_ctrl(DWORD c, DWORD, LPVOID, LPVOID) { if (c == SERVICE_CONTROL_STOP || c == SERVICE_CONTROL_SHUTDOWN) { svc_report(SERVICE_STOP_PENDING, 15000); g_svc_stop = true; return NO_ERROR; } return c == SERVICE_CONTROL_INTERROGATE ? NO_ERROR : ERROR_CALL_NOT_IMPLEMENTED; }
static void WINAPI svc_main(DWORD, LPWSTR *) { g_ssh = RegisterServiceCtrlHandlerExW(L"ClamGUI", svc_ctrl, nullptr); svc_report(SERVICE_START_PENDING, 5000); svc_report(SERVICE_RUNNING); run_supervisor(); svc_report(SERVICE_STOPPED); }
static int run_service_dispatcher() { SERVICE_TABLE_ENTRYW t[] = {{(LPWSTR)L"ClamGUI", svc_main}, {nullptr, nullptr}}; return StartServiceCtrlDispatcherW(t) ? 0 : 2; }
static bool is_admin() { BOOL a = FALSE; PSID g = nullptr; SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY; if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &g)) { CheckTokenMembership(nullptr, g, &a); FreeSid(g); } return a != FALSE; }
// Elevated installer: runs only with administrator rights.  Creates a machine-wide home under ProgramData (config not writable by normal
// users), copies the current settings + virus database, registers an auto-start service with restart-on-failure and starts it.
static bool service_install_now(std::string &msg) {
    std::string home = env("ProgramData"); if (home.empty()) home = "C:\\ProgramData"; home += "\\clamgui"; std::error_code ec;
    fs::create_directories(P(home + "\\config"), ec); fs::create_directories(P(home + "\\data\\db"), ec);
    std::string out; run_capture({"icacls", home, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX"}, out);   // SYSTEM, Administrators full; Users read-only
    Config c = g_cfg; for (auto &m : c.managed) if (c.shadow.count(m)) c.kv[m] = c.shadow[m];
    c.kv["db_dir"] = home + "\\data\\db"; c.kv["quarantine_dir"] = home + "\\data\\quarantine";
    std::string old_db = g_cfg.get("db_dir"); for (fs::directory_iterator it(P(old_db), ec), end; !ec && it != end; it.increment(ec)) { std::string e = u8(it->path().extension()); if (e == ".cvd" || e == ".cld" || e == ".cud") fs::copy_file(it->path(), P(home + "\\data\\db") / it->path().filename(), fs::copy_options::overwrite_existing, ec); }
    std::string o = "# ClamGUI service settings\n"; for (auto &p : c.kv) o += p.first + "=" + esc(p.second) + "\n";
    if (!write_file_atomic(home + "\\config\\clamgui.conf", o)) { msg = "cannot write the service settings"; return false; }
    SC_HANDLE m = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS); if (!m) { msg = "cannot open the service manager (run as administrator)"; return false; }
    std::wstring cmd = L"\"" + u2w(exe_path()) + L"\" --home \"" + u2w(home) + L"\" --service";
    SC_HANDLE sv = OpenServiceW(m, L"ClamGUI", SERVICE_ALL_ACCESS);
    if (!sv) sv = CreateServiceW(m, L"ClamGUI", L"ClamGUI Real-time Protection", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    else ChangeServiceConfigW(sv, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!sv) { msg = "CreateService failed (error " + std::to_string(GetLastError()) + ")"; CloseServiceHandle(m); return false; }
    SC_ACTION acts[3] = {{SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 15000}, {SC_ACTION_RESTART, 60000}}; SERVICE_FAILURE_ACTIONSW fa{}; fa.dwResetPeriod = 86400; fa.cActions = 3; fa.lpsaActions = acts; ChangeServiceConfig2W(sv, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
    StartServiceW(sv, 0, nullptr); CloseServiceHandle(sv); CloseServiceHandle(m);
    msg = "Service \"ClamGUI Real-time Protection\" installed and started.\nSettings and database were copied to " + home + ".\nRe-run Install after changing settings or updating the database."; return true;
}
static bool service_remove_now(std::string &msg) {
    SC_HANDLE m = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS); if (!m) { msg = "cannot open the service manager (run as administrator)"; return false; }
    SC_HANDLE sv = OpenServiceW(m, L"ClamGUI", SERVICE_ALL_ACCESS); if (!sv) { CloseServiceHandle(m); msg = "service is not installed"; return false; }
    SERVICE_STATUS st; ControlService(sv, SERVICE_CONTROL_STOP, &st); Sleep(1500); bool ok = DeleteService(sv) != 0; CloseServiceHandle(sv); CloseServiceHandle(m); msg = ok ? "Service removed." : "DeleteService failed"; return ok;
}
// Non-elevated caller: relaunch ourselves with "runas" (UAC prompt) and wait.
static bool service_elevated(const wchar_t *flag, std::string &msg) {
    SHELLEXECUTEINFOW sei{}; sei.cbSize = sizeof sei; sei.fMask = SEE_MASK_NOCLOSEPROCESS; sei.lpVerb = L"runas"; std::wstring exe = u2w(exe_path()); sei.lpFile = exe.c_str(); sei.lpParameters = flag; sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei)) { msg = "elevation was cancelled or failed"; return false; }
    WaitForSingleObject(sei.hProcess, 120000); DWORD ec = 1; GetExitCodeProcess(sei.hProcess, &ec); CloseHandle(sei.hProcess); msg = ec == 0 ? "done" : "the elevated helper reported an error"; return ec == 0;
}
#endif

// ---- Linux file-manager integration (Nautilus script, Dolphin service menu, Thunar custom action, application launcher)
#ifndef _WIN32
static std::string xdg_data() { std::string x = env("XDG_DATA_HOME"); return x.empty() ? home_dir() + "/.local/share" : x; }
static std::string xdg_conf() { std::string x = env("XDG_CONFIG_HOME"); return x.empty() ? home_dir() + "/.config" : x; }
static std::string desktop_exec(const std::string &exe) {      // Exec= value: double-quote, escape specials, then double every backslash (string layer)
    std::string q = "\""; for (char c : exe) { if (c == '"' || c == '\\' || c == '$' || c == '`') q += '\\'; if (c == '%') q += '%'; q += c; }
    q += "\""; std::string o; for (char c : q) { o += c; if (c == '\\') o += '\\'; } return o;
}
static std::string xml_esc(const std::string &s) { std::string o; for (char c : s) { if (c == '&') o += "&amp;"; else if (c == '<') o += "&lt;"; else if (c == '>') o += "&gt;"; else if (c == '\'') o += "&apos;"; else o += c; } return o; }
static bool fm_write(const std::string &path, const std::string &data, bool exec) {
    std::error_code ec; fs::create_directories(P(path).parent_path(), ec);
    std::string tmp = path + ".tmp"; FILE *f = fopen(tmp.c_str(), "wb"); if (!f) return false; bool ok = fwrite(data.data(), 1, data.size(), f) == data.size(); ok = fclose(f) == 0 && ok;
    if (!ok) return false;
    chmod(tmp.c_str(), exec ? 0755 : 0644); fs::rename(P(tmp), P(path), ec); return !ec;
}
static const char *THUNAR_MARK = "clamgui-scan-1";
static bool fm_install(std::string &msg) {
    std::string exe = exe_path(); if (exe.empty()) { msg = "cannot determine the program path"; return false; }
    bool ok = true; std::string d = xdg_data();
    ok &= fm_write(d + "/nautilus/scripts/Scan with ClamGUI", "#!/bin/sh\n# ClamGUI v" CLAMGUI_VERSION " file-manager script\nIFS='\n'\nset -f\n[ -n \"$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS\" ] || exit 0\nexec " + sq(exe) + " $NAUTILUS_SCRIPT_SELECTED_FILE_PATHS\n", true);
    ok &= fm_write(d + "/kio/servicemenus/clamgui-scan.desktop", "[Desktop Entry]\nType=Service\nMimeType=all/all;inode/directory;\nActions=clamguiscan;\nX-KDE-Priority=TopLevel\nX-KDE-ServiceTypes=KonqPopupMenu/Plugin\n\n[Desktop Action clamguiscan]\nName=Scan with ClamGUI\nIcon=security-high\nExec=" + desktop_exec(exe) + " %F\n", true);
    ok &= fm_write(d + "/applications/clamgui.desktop", "[Desktop Entry]\nType=Application\nName=ClamGUI\nComment=ClamAV front-end\nExec=" + desktop_exec(exe) + " %F\nIcon=security-high\nTerminal=false\nCategories=System;Security;\nMimeType=inode/directory;application/octet-stream;\n", false);
    std::string uca = xdg_conf() + "/Thunar/uca.xml", t; read_file(uca, t, 4u << 20);
    if (t.find(THUNAR_MARK) == std::string::npos) {
        if (t.empty()) t = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<actions>\n</actions>\n";
        size_t e = t.rfind("</actions>");
        if (e == std::string::npos) { msg = "Thunar's uca.xml has an unexpected format; left untouched. "; }
        else { t.insert(e, std::string("<action>\n\t<icon>security-high</icon>\n\t<name>Scan with ClamGUI</name>\n\t<unique-id>") + THUNAR_MARK + "</unique-id>\n\t<command>" + xml_esc(sq(exe)) + " %F</command>\n\t<description>Scan the selected files with ClamGUI</description>\n\t<patterns>*</patterns>\n\t<directories/>\n\t<audio-files/>\n\t<image-files/>\n\t<other-files/>\n\t<text-files/>\n\t<video-files/>\n</action>\n"); ok &= fm_write(uca, t, false); }
    }
    msg += ok ? "Added: Nautilus script, Dolphin service menu, Thunar custom action and an application launcher.\n(Restart the file manager to see them.)" : "Some entries could not be written.";
    return ok;
}
static bool fm_remove(std::string &msg) {
    std::string d = xdg_data(); std::error_code ec;
    for (const char *f : {"/nautilus/scripts/Scan with ClamGUI", "/kio/servicemenus/clamgui-scan.desktop", "/applications/clamgui.desktop"}) fs::remove(P(d + f), ec);
    std::string uca = xdg_conf() + "/Thunar/uca.xml", t; if (read_file(uca, t, 4u << 20)) {
        size_t m = t.find(THUNAR_MARK);
        if (m != std::string::npos) { size_t a = t.rfind("<action>", m), b = t.find("</action>", m); if (a != std::string::npos && b != std::string::npos) { b += 9; if (b < t.size() && t[b] == '\n') b++; t.erase(a, b - a); fm_write(uca, t, false); } }
    }
    msg = "File-manager entries removed."; return true;
}
#endif

// ---- watchers (polled from the GUI loop): removable drives and the Downloads folder
static std::vector<std::string> removable_mounts() {
    std::vector<std::string> v;
#ifdef _WIN32
    DWORD m = GetLogicalDrives(); for (int i = 0; i < 26; i++) if (m & (1u << i)) { wchar_t r[4] = {(wchar_t)(L'A' + i), L':', L'\\', 0}; if (GetDriveTypeW(r) == DRIVE_REMOVABLE) v.push_back(w2u(r)); }
#else
    std::string mf = env("CLAMGUI_MOUNTS"), t; bool any = !mf.empty(); if (mf.empty()) mf = "/proc/mounts";     // CLAMGUI_MOUNTS lets tests fake the mount table
    if (!read_file(mf, t, 1u << 20)) return v;
    for (auto &l : split(t, '\n')) {
        auto f = split(l, ' '); if (f.size() < 3) continue; std::string mp;
        for (size_t i = 0; i < f[1].size(); i++) { if (f[1][i] == '\\' && i + 3 < f[1].size() + 0 && isdigit((unsigned char)f[1][i + 1])) { mp += (char)strtol(f[1].substr(i + 1, 3).c_str(), nullptr, 8); i += 3; } else mp += f[1][i]; }   // \040 = space
        static const char *fsx[] = {"tmpfs", "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "overlay", "squashfs", "autofs"}; bool skip = false; for (auto x : fsx) if (f[2] == x) skip = true;
        if (skip) continue;
        if (any || starts_with(mp, "/media/") || starts_with(mp, "/run/media/")) v.push_back(mp);
    }
#endif
    return v;
}
struct DlState { unsigned long long size = 0; time_t mtime = 0; int stable = 0; bool scanned = false; };
// Files that appeared in the watched folder and stopped changing between two polls (a finished download).  Riskiest first.
static std::vector<std::string> new_stable_files(const std::string &dir, std::map<std::string, DlState> &seen, bool &first) {
    std::vector<std::string> ready; std::error_code ec; std::set<std::string> present;
    for (fs::directory_iterator it(P(dir), fs::directory_options::skip_permission_denied, ec), end; !ec && it != end; it.increment(ec)) {
        std::error_code e2; auto st = it->symlink_status(e2); if (e2 || st.type() != fs::file_type::regular) continue;
        std::string p = u8(it->path()); if (p.find('\n') != std::string::npos || temp_download_name(u8(it->path().filename()))) continue;
        unsigned long long sz = (unsigned long long)fs::file_size(it->path(), e2); time_t mt = file_mtime(p); present.insert(p);
        auto f = seen.find(p);
        if (f == seen.end()) { DlState d; d.size = sz; d.mtime = mt; d.scanned = first; seen[p] = d; continue; }     // first sight: pre-existing files are never scanned, new ones wait one poll
        DlState &d = f->second;
        if (d.size != sz || d.mtime != mt) { d.size = sz; d.mtime = mt; d.stable = 0; d.scanned = false; continue; }
        if (!d.scanned && ++d.stable >= 1) { d.scanned = true; ready.push_back(p); }
    }
    for (auto it = seen.begin(); it != seen.end();) { if (!present.count(it->first)) it = seen.erase(it); else ++it; }
    first = false;
    std::sort(ready.begin(), ready.end(), [](const std::string &a, const std::string &b) { return risk_score(a) > risk_score(b); });
    return ready;
}

// ============================================================================================ GUI
static Fl_Double_Window *g_win;
static Fl_Tabs *g_tabs;
static Fl_Box *g_status;
// scan tab
static Fl_Input *in_path; static Fl_Choice *ch_quick; static Fl_Button *b_scan, *b_stop, *b_qsel, *b_dsel; static Fl_Progress *prog;
static Fl_Box *lb_count; static Fl_Multi_Browser *br_threat; static Fl_Text_Display *td_scan; static Fl_Text_Buffer *tb_scan;
// update tab
static Fl_Button *b_update; static Fl_Text_Display *td_upd; static Fl_Text_Buffer *tb_upd; static Fl_Box *lb_dbinfo;
// quarantine tab
static Fl_Multi_Browser *br_q; static std::vector<QItem> g_qitems; static Fl_Box *lb_qinfo;
// reports tab
static Fl_Hold_Browser *br_rep; static Fl_Text_Display *td_rep; static Fl_Text_Buffer *tb_rep; static std::vector<std::string> g_replist;
// real-time tab
static Fl_Multiline_Input *in_rtpaths; static Fl_Choice *ch_rtact; static Fl_Check_Button *ck_rtblock; static Fl_Button *b_rt; static Fl_Text_Display *td_rt; static Fl_Text_Buffer *tb_rt; static Fl_Box *lb_rt;
// schedule tab
static Fl_Check_Button *ck_supd, *ck_sscan, *ck_day[7]; static Fl_Input *in_supdt, *in_sscant, *in_sscanp; static Fl_Text_Display *td_sched; static Fl_Text_Buffer *tb_sched;
// settings tab
static Fl_Input *in_tool[5], *in_db, *in_qd, *in_certs, *in_phost, *in_pport; static Fl_Check_Button *ck_arch, *ck_pua; static Fl_Int_Input *in_maxmb; static Fl_Choice *ch_action; static Fl_Multiline_Input *in_excl;

// v2 widgets / state
static Fl_Button *b_lookup; static Fl_Check_Button *ck_usb, *ck_dlw, *ck_notify, *ck_tray, *ck_reppaths; static Fl_Input *in_dldir, *in_ikenv, *in_iurl, *in_policy, *in_reporturl; static Fl_Int_Input *in_recent;
static Fl_Choice *ch_engine, *ch_intel; static Fl_Box *lb_auto, *lb_adv;
struct QJob { std::vector<std::string> targets; std::string listfile, reason; size_t nlist = 0; };
static std::deque<QJob> g_jobq;                                     // scans waiting for the current one to finish (USB, downloads, recent files)
static std::set<std::string> g_usb_known; static bool g_usb_init = false;
static std::map<std::string, DlState> g_dl_seen; static bool g_dl_first = true; static std::string g_dl_dir_seen;
static int g_tick = 0, g_ping_tick = 0; static bool g_daemon_restart = false, g_quit = false;
static bool tray_active(); static void tray_refresh(); static void tray_init();
static std::unique_ptr<ScanSession> g_scan; static std::unique_ptr<Proc> g_upd, g_clamd, g_rt;
static std::vector<std::unique_ptr<Proc>> g_misc;     // fire-and-forget helpers (xdg-open ...), reaped by the pump
static int g_rtstage = 0;                               // 0 off, 1 clamd loading, 2 protecting
static bool g_dirty = false;
static volatile sig_atomic_t g_sigquit = 0;            // set by SIGINT/SIGTERM/SIGHUP: the pump stops children and exits cleanly

static void log_to(Fl_Text_Display *d, Fl_Text_Buffer *b, const std::string &s) {
    if (b->length() > (2 << 20)) b->remove(0, 1 << 20);         // bound memory: drop the oldest megabyte
    b->append(sane(s).c_str()); b->append("\n"); d->insert_position(b->length()); d->show_insert_position();
}
static void set_text(Fl_Text_Buffer *b, const std::string &s) { b->text(sane(s, 4u << 20).c_str()); }
static void open_path(const std::string &p) {
#ifdef _WIN32
    ShellExecuteW(nullptr, L"open", u2w(p).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#else
    auto pr = std::make_unique<Proc>(); std::string e; if (pr->start({"xdg-open", p}, e)) g_misc.push_back(std::move(pr)); else fl_alert("%s", e.c_str());
#endif
}
static std::string choose(bool dir, const char *title, const std::string &start = "") {
    Fl_Native_File_Chooser fc; fc.title(title); fc.type(dir ? Fl_Native_File_Chooser::BROWSE_DIRECTORY : Fl_Native_File_Chooser::BROWSE_FILE);
    if (!start.empty()) fc.directory(start.c_str());
    return fc.show() == 0 && fc.filename() ? fc.filename() : "";
}

static void refresh_db_status() {
    std::string s; time_t newest = 0; long sigs = 0;
    std::string rows;
    for (const char *b : {"main", "daily", "bytecode"}) {
        DbInfo d = read_db(db_dir(), b);
        if (d.ok) { rows += std::string(b) + ": version " + std::to_string(d.ver) + ", " + std::to_string(d.sigs) + " signatures, built " + tstamp("%Y-%m-%d %H:%M", d.built) + "\n"; if (d.built > newest) newest = d.built; if (std::string(b) != "bytecode") sigs += d.sigs; }
        else rows += std::string(b) + ": not installed\n";
    }
    if (!has_any_db(db_dir())) { s = "Virus database: NOT INSTALLED - open the Update tab and click \"Update now\""; g_status->labelcolor(FL_RED); }
    else if (newest) { long days = (long)((time(nullptr) - newest) / 86400); s = "Virus database: " + std::to_string(sigs) + " signatures, built " + tstamp("%Y-%m-%d", newest) + (days > 7 ? "  -  OUT OF DATE (" + std::to_string(days) + " days)" : ""); g_status->labelcolor(days > 7 ? FL_RED : FL_DARK_GREEN); }
    else { s = "Virus database: custom signatures loaded"; g_status->labelcolor(FL_DARK_GREEN); }
    s += std::string("   |   Real-time: ") + (g_rtstage == 2 ? "ON" : g_rtstage == 1 ? "starting..." : "off");
    if (g_cfg.geti("engine", 0) == 1) s += std::string("   |   Engine: clamd ") + (g_daemon_ready ? "ready" : g_clamd ? "loading..." : "off");
    g_status->copy_label(s.c_str());
    if (lb_dbinfo) lb_dbinfo->copy_label((rows.empty() ? std::string("") : rows).c_str());
    g_status->redraw();
}

// ---- scan tab
static void update_counts() {
    if (!g_scan) { lb_count->copy_label("Ready."); return; }
    std::string s = "Scanned: " + std::to_string(g_scan->scanned) + "    Infected: " + std::to_string(g_scan->infected) + "    Errors: " + std::to_string(g_scan->errors);
    if (!g_scan->finished && !g_scan->current.empty()) { std::string c = sane(g_scan->current, 200); if (c.size() > 90) c = "..." + c.substr(c.size() - 87); s += "    " + c; }
    if (g_scan->finished) s += g_scan->infected ? "    - FINISHED: THREATS FOUND" : (g_scan->code == 0 ? "    - FINISHED: clean" : "    - FINISHED with errors");
    lb_count->copy_label(s.c_str()); lb_count->labelcolor(g_scan->infected ? FL_RED : FL_FOREGROUND_COLOR);
    prog->value(g_scan->finished ? 100.0f : (float)(g_scan->scanned % 100)); lb_count->redraw();
}
static void scan_buttons() { bool run = g_scan && !g_scan->finished; if (run) { b_scan->deactivate(); b_stop->activate(); } else { b_scan->activate(); b_stop->deactivate(); } }
static void add_threat_row(const Threat &t, size_t idx) {
    std::string row = at_esc(t.name) + "\t" + at_esc(sane(t.path)) + "\t" + at_esc(t.action);
    br_threat->add(row.c_str(), (void *)(intptr_t)(idx + 1));
}
// v2: one entry point for manual, queued (USB / download / recent) scans.  Interactive = user clicked: show dialogs and switch to the Scan tab.
static void start_scan_job(QJob j, bool interactive) {
    if (g_scan && !g_scan->finished) { if (interactive) fl_message("%s", "A scan is already running."); else g_jobq.push_front(std::move(j)); return; }
    for (auto &t : j.targets) { std::error_code ec; if (!fs::exists(P(t), ec)) { if (interactive) fl_alert("Cannot find:\n%s", t.c_str()); else log_to(td_scan, tb_scan, "Skipped (not found): " + t); return; } }
    auto sess = std::make_unique<ScanSession>(); sess->listfile = j.listfile; sess->nlist = j.nlist; sess->reason = j.reason;
    sess->sink = [](int k, const std::string &t) {
        if (k == 1) { size_t i = g_scan ? g_scan->threats.size() : 0; if (i) add_threat_row(g_scan->threats[i - 1], i - 1); }
        log_to(td_scan, tb_scan, k == 1 ? "FOUND: " + t : t);
    };
    std::string err; if (!sess->begin(j.targets, err)) { if (interactive) fl_alert("%s", err.c_str()); else log_to(td_scan, tb_scan, "Auto-scan could not start: " + err); return; }
    std::string what = !j.listfile.empty() ? std::to_string(j.nlist) + " file(s), riskiest first" : std::to_string(j.targets.size()) + " target(s)";
    std::string eng = sess->engine; g_scan = std::move(sess); br_threat->clear(); tb_scan->text("");
    log_to(td_scan, tb_scan, (j.reason.empty() ? "Scanning " : "Scanning (" + j.reason + ") ") + what + " with " + eng + "...");
    if (interactive) g_tabs->value(g_tabs->child(0));
    scan_buttons(); update_counts(); g_dirty = true;
}
static void start_scan(const std::vector<std::string> &targets) { QJob j; j.targets = targets; start_scan_job(std::move(j), true); }
static void cb_scan(Fl_Widget *, void *) { std::string p = trim(in_path->value()); if (p.empty()) { fl_message("Enter or browse for a file or folder to scan."); return; } g_cfg.set("scan_path", p); start_scan({p}); }
static void cb_stop(Fl_Widget *, void *) { if (g_scan && !g_scan->finished) { g_scan->proc.kill(); log_to(td_scan, tb_scan, "Scan stopped by user."); } }
static void cb_file(Fl_Widget *, void *) { std::string p = choose(false, "Choose a file to scan"); if (!p.empty()) in_path->value(p.c_str()); }
static void cb_dir(Fl_Widget *, void *) { std::string p = choose(true, "Choose a folder to scan"); if (!p.empty()) in_path->value(p.c_str()); }
static void cb_quick(Fl_Widget *, void *) {
    std::string h = home_dir(), p;
#ifdef _WIN32
    const std::string root = "C:\\", sep = "\\";
#else
    const std::string root = "/", sep = "/";
#endif
    switch (ch_quick->value()) { case 0: p = h; break; case 1: p = h + sep + "Downloads"; break; case 2: p = h + sep + "Documents"; break; case 3: p = root; break; default: return; }
    in_path->value(p.c_str());
}
static void threat_act(bool del) {
    if (!g_scan) return;
    int n = 0;
    for (int i = 1; i <= br_threat->size(); i++) if (br_threat->selected(i)) {
        size_t idx = (size_t)(intptr_t)br_threat->data(i) - 1; if (idx >= g_scan->threats.size()) continue;
        Threat &t = g_scan->threats[idx]; std::string e; bool ok;
        if (del) { unsigned long long sz; std::error_code ec; ok = is_plain_file(t.path, sz) && fs::remove(P(t.path), ec) && !ec; if (!ok) e = "not a regular file or cannot delete"; } else ok = q_add(t.path, t.name, e);
        t.action = ok ? (del ? "deleted" : "quarantined") : "FAILED: " + e;
        std::string row = at_esc(t.name) + "\t" + at_esc(sane(t.path)) + "\t" + at_esc(t.action); br_threat->text(i, row.c_str()); n++;
    }
    if (!n) fl_message("Select one or more detections in the list first.");
}
static void cb_qsel(Fl_Widget *, void *) { threat_act(false); }
// v2: hash-only lookup of the selected detection (MalwareBazaar / VirusTotal).  Only the SHA-256 leaves the machine.
static void cb_lookup(Fl_Widget *, void *) {
    if (!g_scan) return;
    Threat *t = nullptr;
    for (int i = 1; i <= br_threat->size() && !t; i++) if (br_threat->selected(i)) { size_t k = (size_t)(intptr_t)br_threat->data(i) - 1; if (k < g_scan->threats.size()) t = &g_scan->threats[k]; }
    if (!t) { fl_message("Select a detection first."); return; }
    std::string sha = t->sha;
    if (sha.empty()) for (auto &q : q_list()) if (q.path == t->path && !q.sha.empty()) sha = q.sha;      // quarantined: the vault recorded the hash
    if (sha.empty()) { unsigned long long sz; if (is_plain_file(t->path, sz)) sha256_file(t->path, sha); }
    if (sha.empty()) { fl_message("The file is no longer available, so its hash is unknown."); return; }
    CurlReq r; std::string err; if (!intel_build(sha, r, err)) { fl_alert("%s", err.c_str()); return; }
    int prov = g_cfg.geti("intel_provider", 0); std::string name = t->name;
    log_to(td_scan, tb_scan, "Looking up sha256 " + sha.substr(0, 16) + "... (only the hash is sent)");
    if (!curl_async(r, [prov, sha, name](bool ok, int http, const std::string &body, const std::string &e) {
            std::string res = ok ? intel_summary(prov, http, body) : "Lookup failed: " + e;
            log_to(td_scan, tb_scan, "Lookup " + sha.substr(0, 16) + "...: " + res); fl_message("%s\n\nsha256 %s\n\n%s", name.c_str(), sha.c_str(), res.c_str()); }, err)) fl_alert("%s", err.c_str());
}
static void cb_recent(Fl_Widget *, void *) {
    int days = atoi(in_recent->value()); if (days < 1 || days > 3650) { fl_alert("Days must be 1-3650."); return; }
    std::string dir = trim(in_dldir->value()); std::error_code ec; if (!fs::is_directory(P(dir), ec)) { fl_alert("Folder not found:\n%s", dir.c_str()); return; }
    auto files = recent_files(dir, days); if (g_nl_skipped > 0) fl_alert("%d file(s) with a newline in the name cannot be scanned from a list and were skipped.", g_nl_skipped.load());   // v3
    if (files.empty()) { fl_message("No files changed in the last %d day(s).", days); return; }
    QJob j; j.listfile = write_listfile(files); j.nlist = files.size(); j.reason = "recent files"; if (j.listfile.empty()) { fl_alert("Cannot write the file list."); return; }
    start_scan_job(std::move(j), true);
}
static void cb_dsel(Fl_Widget *, void *) { if (fl_choice("Permanently delete the selected files?", "Cancel", "Delete", nullptr) == 1) threat_act(true); }

// ---- update tab
static void cb_update(Fl_Widget *, void *) {
    if (g_upd) { fl_message("An update is already running."); return; }
    std::string err; auto a = update_args(err); if (a.empty()) { fl_alert("%s", err.c_str()); return; }
    auto p = std::make_unique<Proc>(); if (!p->start(a, err)) { fl_alert("%s", err.c_str()); return; }
    g_upd = std::move(p); tb_upd->text(""); log_to(td_upd, tb_upd, "Starting freshclam..."); b_update->deactivate();
}

// ---- quarantine tab
static void refresh_quarantine() {
    g_qitems = q_list(); br_q->clear(); unsigned long long tot = 0;
    for (size_t i = 0; i < g_qitems.size(); i++) { auto &q = g_qitems[i]; tot += q.size;
        std::string row = at_esc(tstamp("%Y-%m-%d %H:%M", q.when)) + "\t" + at_esc(sane(q.threat)) + "\t" + at_esc(sane(q.path)) + "\t" + human(q.size); br_q->add(row.c_str(), (void *)(intptr_t)(i + 1)); }
    lb_qinfo->copy_label((std::to_string(g_qitems.size()) + " item(s), " + human(tot) + " in " + sane(qdir())).c_str());
}
static std::vector<std::string> q_selected() { std::vector<std::string> v; for (int i = 1; i <= br_q->size(); i++) if (br_q->selected(i)) { size_t k = (size_t)(intptr_t)br_q->data(i) - 1; if (k < g_qitems.size()) v.push_back(g_qitems[k].id); } return v; }
static void cb_qrestore(Fl_Widget *, void *) {
    auto ids = q_selected(); if (ids.empty()) { fl_message("Select an item first."); return; }
    if (fl_choice("The restored file is still infected.\nRestore it anyway?", "Cancel", "Restore", nullptr) != 1) return;
    for (auto &id : ids) {
        std::string out, err;
        if (!q_restore(id, out, err)) {
            if (starts_with(err, "INTEGRITY") && fl_choice("%s\n\nRestore anyway?", "Cancel", "Restore anyway", nullptr, err.c_str()) == 1) { if (q_restore(id, out, err, "", true)) continue; }
            fl_alert("Restore failed: %s", err.c_str()); break;
        }
    }
    refresh_quarantine();
}
static void cb_qdelete(Fl_Widget *, void *) {
    auto ids = q_selected(); if (ids.empty()) { fl_message("Select an item first."); return; }
    if (fl_choice("Permanently delete %d item(s)?", "Cancel", "Delete", nullptr, (int)ids.size()) != 1) return;
    for (auto &id : ids) { std::string err; if (!q_delete(id, err)) { fl_alert("Delete failed: %s", err.c_str()); break; } }
    refresh_quarantine();
}
static void cb_qall(Fl_Widget *, void *) {
    if (g_qitems.empty()) return;
    if (fl_choice("Permanently delete ALL %d quarantined items?", "Cancel", "Delete all", nullptr, (int)g_qitems.size()) != 1) return;
    for (auto &q : g_qitems) { std::string err; q_delete(q.id, err); }
    refresh_quarantine();
}
static std::string choose_save(const char *title, const std::string &preset) {
    Fl_Native_File_Chooser fc; fc.title(title); fc.type(Fl_Native_File_Chooser::BROWSE_SAVE_FILE); fc.preset_file(preset.c_str()); fc.options(Fl_Native_File_Chooser::SAVEAS_CONFIRM);
    return fc.show() == 0 && fc.filename() ? fc.filename() : "";
}
static void cb_qsandbox(Fl_Widget *, void *) {
    auto ids = q_selected(); if (ids.size() != 1) { fl_message("Select exactly one item."); return; }
    std::string d = choose(true, "Folder for a read-only analysis copy"); if (d.empty()) return;
    std::string out, err; if (!q_restore(ids[0], out, err, d)) fl_alert("Failed: %s", err.c_str()); else fl_message("Analysis copy written (read-only, name ends in .infected; the item stays in the vault):\n%s", out.c_str());
}
static void cb_qexport(Fl_Widget *, void *) {
    std::string f = choose_save("Save signed evidence manifest", "clamgui-evidence-" + tstamp("%Y%m%d", time(nullptr)) + ".json"); if (f.empty()) return;
    std::string msg; bool ok = q_export(f, msg); if (ok) fl_message("%s", msg.c_str()); else fl_alert("%s", msg.c_str());
}
static void cb_qverify(Fl_Widget *, void *) {
    std::string f = choose(false, "Choose the evidence manifest (.json)"); if (f.empty()) return;
    std::string msg; bool ok = q_verify_export(f, msg); if (ok) fl_message("%s", msg.c_str()); else fl_alert("%s", msg.c_str());
}
static void cb_qopen(Fl_Widget *, void *) { make_private_dir(qdir()); open_path(qdir()); }

// ---- reports tab
static void refresh_reports() {
    g_replist.clear(); br_rep->clear(); std::error_code ec; std::vector<std::string> v;
    for (fs::directory_iterator it(P(reports_dir()), ec), end; !ec && it != end; it.increment(ec)) if (it->path().extension() == ".log") v.push_back(u8(it->path()));
    std::sort(v.rbegin(), v.rend());
    for (auto &p : v) { g_replist.push_back(p); std::string n = u8(P(p).stem()); br_rep->add(at_esc(sane(n)).c_str()); }
    tb_rep->text("");
}
static void cb_rep(Fl_Widget *, void *) { int i = br_rep->value(); if (i < 1 || (size_t)i > g_replist.size()) return; std::string t; if (read_file(g_replist[(size_t)i - 1], t, 4u << 20)) set_text(tb_rep, t); }
static void cb_repdel(Fl_Widget *, void *) { int i = br_rep->value(); if (i < 1 || (size_t)i > g_replist.size()) return; std::error_code ec; fs::remove(P(g_replist[(size_t)i - 1]), ec); refresh_reports(); }
static void cb_repopen(Fl_Widget *, void *) { make_private_dir(reports_dir()); open_path(reports_dir()); }

// ---- real-time tab + managed clamd (v2: the same daemon serves fast GUI scans and real-time protection)
static void daemon_start(bool say = true) {
    if (g_clamd) return;
    std::string cd = g_cfg.get("clamd"), err;
    if (cd.empty() || !is_exec_file(cd)) { if (say) log_to(td_rt, tb_rt, "clamd was not found - set its path on the Settings tab."); return; }
    if (!has_any_db(db_dir())) { if (say) log_to(td_rt, tb_rt, "No virus database yet - install one on the Update tab."); return; }
    if (!write_daemon_conf(err)) { log_to(td_rt, tb_rt, err); return; }
    auto p = std::make_unique<Proc>(); if (!p->start({cd, "--config-file=" + daemon_conf()}, err)) { log_to(td_rt, tb_rt, "ERROR: " + err); return; }
    g_clamd = std::move(p); g_daemon_ready = false; log_to(td_rt, tb_rt, "Starting clamd (loading signatures can take a while)..."); refresh_db_status();
}
static void daemon_stop() { if (g_clamd) g_clamd->kill(); g_daemon_ready = false; }
static void daemon_settings_changed() {       // engine / scan options changed: restart the daemon so it re-reads them
    bool want = g_cfg.geti("engine", 0) == 1 || g_rtstage != 0;
    if (g_clamd) { g_daemon_restart = want; daemon_stop(); } else if (want) daemon_start(false);
}
static void rt_stop() {
    if (g_rt) g_rt->kill();
    g_rtstage = 0; if (g_cfg.geti("engine", 0) != 1) daemon_stop();      // keep the daemon when it also serves fast scans
    b_rt->label("Start protection"); lb_rt->copy_label("Real-time protection is off."); refresh_db_status(); tray_refresh();
}
static void rt_start_clamrt() {
    std::string err; auto a = build_clamrt_args(err); if (a.empty()) { log_to(td_rt, tb_rt, err); rt_stop(); return; }
    auto p = std::make_unique<Proc>(); if (!p->start(a, err)) { log_to(td_rt, tb_rt, "ERROR: " + err); rt_stop(); return; }
    g_rt = std::move(p); g_rtstage = 2; lb_rt->copy_label("Real-time protection is ON."); log_to(td_rt, tb_rt, "clamrt started."); refresh_db_status(); tray_refresh();
}
static void cb_rt(Fl_Widget *, void *) {
    if (g_rtstage != 0) { log_to(td_rt, tb_rt, "Stopping..."); rt_stop(); return; }
    if (g_rt) { fl_message("%s", "The previous session is still shutting down - try again in a second."); return; }
    g_cfg.set("rt_paths", in_rtpaths->value()); g_cfg.set("rt_action", std::to_string(ch_rtact->value())); g_cfg.set("rt_blockexec", ck_rtblock->value() ? "1" : "0"); g_cfg.save();
    std::string err; if (build_clamrt_args(err).empty()) { fl_alert("%s\n(clamrt is the real-time watcher from the clamrt project.)", err.c_str()); return; }
    if (g_cfg.get("clamd").empty() || !is_exec_file(g_cfg.get("clamd"))) { fl_alert("clamd was not found - set its path on the Settings tab."); return; }
    if (!has_any_db(db_dir())) { fl_alert("Install a virus database first (Update tab)."); return; }
    tb_rt->text(""); g_rtstage = 1; b_rt->label("Stop protection");
    if (g_clamd && g_daemon_ready) { lb_rt->copy_label("Starting clamrt..."); rt_start_clamrt(); }
    else { lb_rt->copy_label("Starting clamd..."); daemon_start(); if (!g_clamd) { g_rtstage = 0; b_rt->label("Start protection"); lb_rt->copy_label("Real-time protection is off."); } }
    refresh_db_status();
}

// ---- schedule tab
static void refresh_sched() { set_text(tb_sched, sched_status()); }
static void cb_sched_apply(Fl_Widget *, void *) {
    std::string days; for (int i = 0; i < 7; i++) days += ck_day[i]->value() ? '1' : '0';
    std::string sp = trim(in_sscanp->value());
    if (ck_sscan->value() && sp.empty()) { fl_alert("Choose the folder the scheduled scan should check."); return; }
    g_cfg.set("sched_update_on", ck_supd->value() ? "1" : "0"); g_cfg.set("sched_update_time", trim(in_supdt->value()));
    g_cfg.set("sched_scan_on", ck_sscan->value() ? "1" : "0"); g_cfg.set("sched_scan_time", trim(in_sscant->value())); g_cfg.set("sched_scan_path", sp); g_cfg.set("sched_scan_days", days);
    std::string msg; bool ok = sched_apply(ck_supd->value(), trim(in_supdt->value()), ck_sscan->value(), trim(in_sscant->value()), days, msg);
    if (ok) g_cfg.save();
    fl_message("%s", msg.c_str()); refresh_sched();
}
static void cb_sched_pick(Fl_Widget *, void *) { std::string p = choose(true, "Folder for the scheduled scan"); if (!p.empty()) in_sscanp->value(p.c_str()); }

// ---- settings tab
static void cb_tool_pick(Fl_Widget *, void *d) { int i = (int)(intptr_t)d; std::string p = choose(false, "Choose the program"); if (!p.empty()) in_tool[i]->value(p.c_str()); }
static void cb_dir_pick(Fl_Widget *, void *d) { Fl_Input *w = (Fl_Input *)d; std::string p = choose(true, "Choose a folder"); if (!p.empty()) w->value(p.c_str()); }
static void load_settings_ui() {
    const char *n[] = {"clamscan", "freshclam", "clamd", "clamrt", "clamdscan"};
    for (int i = 0; i < 5; i++) in_tool[i]->value(g_cfg.get(n[i]).c_str());
    in_db->value(g_cfg.get("db_dir").c_str()); in_qd->value(g_cfg.get("quarantine_dir").c_str()); in_certs->value(g_cfg.get("certs_dir").c_str());
    in_phost->value(g_cfg.get("proxy_host").c_str()); in_pport->value(g_cfg.get("proxy_port").c_str());
    ck_arch->value(g_cfg.geti("scan_archives", 1)); ck_pua->value(g_cfg.geti("scan_pua", 0)); in_maxmb->value(g_cfg.get("max_file_mb").c_str());
    ch_action->value(std::max(0, std::min(2, g_cfg.geti("action", 0)))); in_excl->value(g_cfg.get("excludes").c_str());
}
static void cb_detect(Fl_Widget *, void *) { const char *n[] = {"clamscan", "freshclam", "clamd", "clamrt", "clamdscan"}; for (int i = 0; i < 5; i++) { std::string p = find_tool(n[i]); in_tool[i]->value(p.c_str()); } }
static void cb_save(Fl_Widget *, void *) {
    int mb = atoi(in_maxmb->value()); if (mb < 1 || mb > 4000) { fl_alert("Maximum file size must be 1-4000 MB."); return; }
    std::string pp = trim(in_pport->value()); if (!pp.empty()) { int p = atoi(pp.c_str()); if (p < 1 || p > 65535) { fl_alert("Proxy port must be 1-65535."); return; } }
    for (const char *s : {in_db->value(), in_qd->value()}) if (!*s || trim(s).empty()) { fl_alert("Database and quarantine folders cannot be empty."); return; }
    const char *n[] = {"clamscan", "freshclam", "clamd", "clamrt", "clamdscan"};
    for (int i = 0; i < 5; i++) { std::string v = trim(in_tool[i]->value()); if (!v.empty() && !is_exec_file(v)) { fl_alert("%s: \"%s\" is not an executable file.", n[i], v.c_str()); return; } g_cfg.set(n[i], v); }
    g_cfg.set("db_dir", trim(in_db->value())); g_cfg.set("quarantine_dir", trim(in_qd->value())); g_cfg.set("certs_dir", trim(in_certs->value()));
    g_cfg.set("proxy_host", trim(in_phost->value())); g_cfg.set("proxy_port", pp);
    g_cfg.set("scan_archives", ck_arch->value() ? "1" : "0"); g_cfg.set("scan_pua", ck_pua->value() ? "1" : "0"); g_cfg.set("max_file_mb", std::to_string(mb));
    g_cfg.set("action", std::to_string(ch_action->value())); g_cfg.set("excludes", in_excl->value());
    if (!g_cfg.save()) { fl_alert("Cannot save settings to %s", g_cfg.path().c_str()); return; }
    overlay_policy(); load_settings_ui(); daemon_settings_changed();      // v2: policy-managed values win, the daemon re-reads the options
    refresh_db_status(); refresh_quarantine(); fl_message("Settings saved.%s", g_cfg.managed.empty() ? "" : "\n(Some settings are managed by your administrator's policy and were not changed.)");
}
#ifdef _WIN32
static void cb_shell_on(Fl_Widget *, void *) {
    std::string exe = exe_path(); std::wstring cmd = L"\"" + u2w(exe) + L"\" \"%1\""; bool ok = true;
    for (const wchar_t *base : {L"Software\\Classes\\*\\shell\\ClamGUI", L"Software\\Classes\\Directory\\shell\\ClamGUI"}) {
        HKEY k; std::wstring b = base, c = b + L"\\command";
        if (RegCreateKeyExW(HKEY_CURRENT_USER, b.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr) == ERROR_SUCCESS) { const wchar_t *t = L"Scan with ClamGUI"; RegSetValueExW(k, nullptr, 0, REG_SZ, (const BYTE *)t, (DWORD)((wcslen(t) + 1) * 2)); RegCloseKey(k); } else ok = false;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, c.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr) == ERROR_SUCCESS) { RegSetValueExW(k, nullptr, 0, REG_SZ, (const BYTE *)cmd.c_str(), (DWORD)((cmd.size() + 1) * 2)); RegCloseKey(k); } else ok = false;
    }
    fl_message("%s", ok ? "Explorer context menu \"Scan with ClamGUI\" installed for this user." : "Could not write the registry keys.");
}
static void cb_shell_off(Fl_Widget *, void *) {
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\*\\shell\\ClamGUI"); RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\Directory\\shell\\ClamGUI");
    fl_message("Explorer context menu entry removed.");
}
#endif
// ---- v2: exclude presets (appended to the exclude list, never duplicated)
static void cb_preset(Fl_Widget *w, void *) {
    static const char *rx[] = {
        "", "[/\\\\](\\.cache|Cache|Code Cache|GPUCache|Cache2)[/\\\\]",                  // browser / app caches
        "\\.(vdi|vmdk|qcow2|vhdx?|ova|vbox-prev)$",                                          // virtual-machine disk images
        "[/\\\\]node_modules[/\\\\]"};                                                  // node_modules trees
    int i = ((Fl_Choice *)w)->value(); if (i <= 0 || i > 3) return;
    std::string cur = in_excl->value();
    for (auto &l : split(cur, '\n')) if (trim(l) == rx[i]) return;
    if (!cur.empty() && cur.back() != '\n') cur += '\n';
    in_excl->value((cur + rx[i]).c_str());
}
// ---- v2: Auto-protect and Advanced tabs
static void load_auto_ui() {
    ch_engine->value(g_cfg.geti("engine", 0) == 1 ? 1 : 0); ck_usb->value(g_cfg.geti("usb_autoscan", 0)); ck_dlw->value(g_cfg.geti("dl_watch", 0)); in_dldir->value(g_cfg.get("dl_dir").c_str());
    in_recent->value(g_cfg.get("recent_days").c_str()); ck_notify->value(g_cfg.geti("notify", 1)); ck_tray->value(g_cfg.geti("close_to_tray", 1));
    ch_intel->value(std::max(0, std::min(2, g_cfg.geti("intel_provider", 0)))); in_ikenv->value(g_cfg.get("intel_key_env").c_str()); in_iurl->value(g_cfg.get("intel_url").c_str());
    in_policy->value(g_cfg.get("policy_src").c_str()); in_reporturl->value(g_cfg.get("report_url").c_str()); ck_reppaths->value(g_cfg.geti("report_paths", 1));
}
static void cb_auto_apply(Fl_Widget *, void *) {
    int d = atoi(in_recent->value()); if (d < 1 || d > 3650) { fl_alert("Look-back days must be 1-3650."); return; }
    std::string url = trim(in_reporturl->value()), e; if (!url.empty() && !url_ok(url, e)) { fl_alert("Report URL: %s", e.c_str()); return; }
    std::string iu = trim(in_iurl->value()); if (!iu.empty() && !url_ok(iu, e)) { fl_alert("Lookup URL: %s", e.c_str()); return; }
    std::string ke = trim(in_ikenv->value()); for (char c : ke) if (!isalnum((unsigned char)c) && c != '_') { fl_alert("The key variable name may only contain letters, digits and _."); return; }
    g_cfg.set("engine", std::to_string(ch_engine->value())); g_cfg.set("usb_autoscan", ck_usb->value() ? "1" : "0"); g_cfg.set("dl_watch", ck_dlw->value() ? "1" : "0"); g_cfg.set("dl_dir", trim(in_dldir->value()));
    g_cfg.set("recent_days", std::to_string(d)); g_cfg.set("notify", ck_notify->value() ? "1" : "0"); g_cfg.set("close_to_tray", ck_tray->value() ? "1" : "0");
    g_cfg.set("intel_provider", std::to_string(ch_intel->value())); g_cfg.set("intel_key_env", ke); g_cfg.set("intel_url", iu);
    g_cfg.set("policy_src", trim(in_policy->value())); g_cfg.set("report_url", url); g_cfg.set("report_paths", ck_reppaths->value() ? "1" : "0");
    std::string pm; apply_policy(pm); overlay_policy();
    if (!g_cfg.save()) { fl_alert("Cannot save settings."); return; }
    load_auto_ui(); daemon_settings_changed(); refresh_db_status(); tray_refresh();
    std::string st = std::string(ck_dlw->value() ? "Watching downloads. " : "") + (ck_usb->value() ? "Scanning inserted drives. " : "") + (tray_active() ? "Tray icon active." : "No tray icon available: closing the window quits.");
    lb_auto->copy_label(st.c_str()); lb_adv->copy_label(pm.empty() ? (g_cfg.managed.empty() ? "Settings saved." : "Policy active.") : pm.c_str());
    fl_message("Saved.%s", pm.empty() ? "" : ("\n" + pm).c_str());
}
static void cb_dl_pick(Fl_Widget *, void *) { std::string p = choose(true, "Folder to watch"); if (!p.empty()) in_dldir->value(p.c_str()); }
#ifndef _WIN32
static void cb_fm_on(Fl_Widget *, void *) { std::string m; fm_install(m); fl_message("%s", m.c_str()); }
static void cb_fm_off(Fl_Widget *, void *) { std::string m; fm_remove(m); fl_message("%s", m.c_str()); }
static void cb_unit(Fl_Widget *, void *) { fl_message("Run in a terminal:\n\n    clamgui --print-systemd-unit | sudo tee /etc/systemd/system/clamgui.service\n\nThe unit runs clamd + clamrt in the background without the GUI (see the guide for the install steps)."); }
#else
static void cb_svc_on(Fl_Widget *, void *) {
    std::string m; bool ok = is_admin() ? service_install_now(m) : service_elevated(L"--install-service-elevated", m); if (ok) fl_message("%s", m.c_str()); else fl_alert("%s", m.c_str());
}
static void cb_svc_off(Fl_Widget *, void *) {
    std::string m; bool ok = is_admin() ? service_remove_now(m) : service_elevated(L"--remove-service-elevated", m); if (ok) fl_message("%s", m.c_str()); else fl_alert("%s", m.c_str());
}
#endif
static void cb_about(Fl_Widget *, void *) {
    std::string out; std::string v = g_cfg.get("clamscan").empty() ? "not found" : (run_capture({g_cfg.get("clamscan"), "--version"}, out), trim(out));
    fl_message("ClamGUI v" CLAMGUI_VERSION "\nA graphical front-end for ClamAV.\n\nEngine: %s\nConfig: %s\nData:   %s\n\nClamAV is (C) Cisco Systems, Inc. - GPLv2.", v.c_str(), config_dir().c_str(), data_dir().c_str());
}

// ---- pump: runs every 50 ms on the UI thread; drains child output without ever blocking
static bool drain(Proc &p, const std::function<void(const std::string &)> &line, const std::function<void(int)> &ex) {
    Msg m; auto t0 = std::chrono::steady_clock::now();
    while (p.pop(m, false)) {
        if (m.type == 0) line(m.s); else { ex(m.code); return true; }
        if (std::chrono::steady_clock::now() - t0 > std::chrono::milliseconds(30)) break;       // keep the UI responsive
    }
    return false;
}
static void usb_poll() {
    if (!g_cfg.geti("usb_autoscan", 0)) { g_usb_init = false; return; }
    auto cur = removable_mounts(); std::set<std::string> now(cur.begin(), cur.end());
    if (!g_usb_init) { g_usb_known = now; g_usb_init = true; return; }           // drives already present at start are not scanned
    for (auto &m : cur) if (!g_usb_known.count(m)) { QJob j; j.targets = {m}; j.reason = "USB drive " + m; g_jobq.push_back(std::move(j)); log_to(td_scan, tb_scan, "Drive inserted: " + m + " - scan queued"); }
    g_usb_known = now;
}
static void dl_poll() {
    if (!g_cfg.geti("dl_watch", 0)) { g_dl_seen.clear(); g_dl_first = true; return; }
    std::string dir = g_cfg.get("dl_dir"); if (dir != g_dl_dir_seen) { g_dl_seen.clear(); g_dl_first = true; g_dl_dir_seen = dir; }
    std::error_code ec; if (!fs::is_directory(P(dir), ec)) return;
    auto files = new_stable_files(dir, g_dl_seen, g_dl_first); if (files.empty()) return;
    QJob j; j.listfile = write_listfile(files); j.nlist = files.size(); j.reason = "new download"; if (j.listfile.empty()) return;
    g_jobq.push_back(std::move(j));
}
static void kill_children() { if (g_scan && !g_scan->finished) g_scan->proc.kill(); if (g_upd) g_upd->kill(); if (g_rt) g_rt->kill(); if (g_clamd) g_clamd->kill(); }
static void pump(void *) {
    if (g_sigquit) { kill_children(); g_quit = true; return; }
    curl_pump();
    if (g_scan && !g_scan->finished) {
        bool done = drain(g_scan->proc, [](const std::string &l) { g_scan->handle(l); }, [](int c) {
            g_scan->finish(c); log_to(td_scan, tb_scan, "Report saved: " + g_scan->repPath);
            std::string note = post_scan(*g_scan, false); if (!note.empty()) log_to(td_scan, tb_scan, note);
            prune_reports(); scan_buttons(); tray_refresh(); });
        if (done) refresh_reports();
        update_counts();
    }
    if (!(g_scan && !g_scan->finished) && !g_jobq.empty()) { QJob j = std::move(g_jobq.front()); g_jobq.pop_front(); start_scan_job(std::move(j), false); }
    if (g_upd) {
        bool done = drain(*g_upd, [](const std::string &l) { log_to(td_upd, tb_upd, l); }, [](int c) { log_to(td_upd, tb_upd, c == 0 ? "Update finished." : "Update failed (exit code " + std::to_string(c) + ")."); });
        if (done) { g_upd.reset(); b_update->activate(); refresh_db_status(); }
    }
    if (g_clamd && !g_daemon_ready && ++g_ping_tick >= 20) {                  // ~1 s: ask the daemon directly (its ready line may be buffered)
        g_ping_tick = 0;
        if (clamd_ping()) { g_daemon_ready = true; log_to(td_rt, tb_rt, "clamd is ready."); if (g_rtstage == 1) rt_start_clamrt(); refresh_db_status(); tray_refresh(); }
    }
    if (g_clamd) {
        bool done = drain(*g_clamd, [](const std::string &l) {
            log_to(td_rt, tb_rt, "clamd: " + l);
            if (!g_daemon_ready && clamd_ready_line(l)) { g_daemon_ready = true; log_to(td_rt, tb_rt, "clamd is ready."); if (g_rtstage == 1) rt_start_clamrt(); refresh_db_status(); } },
            [](int c) { log_to(td_rt, tb_rt, "clamd exited (code " + std::to_string(c) + ")."); g_daemon_ready = false; if (g_rt) g_rt->kill(); });
        if (done) {
            g_clamd.reset(); g_daemon_ready = false;
            if (g_rtstage) { g_rtstage = 0; b_rt->label("Start protection"); lb_rt->copy_label("Real-time protection stopped (clamd exited)."); }
            if (g_daemon_restart) { g_daemon_restart = false; daemon_start(false); }
            refresh_db_status(); tray_refresh();
        }
    }
    if (g_rt) {
        bool done = drain(*g_rt, [](const std::string &l) { log_to(td_rt, tb_rt, l); }, [](int c) { log_to(td_rt, tb_rt, "clamrt exited (code " + std::to_string(c) + ")."); });
        if (done) { g_rt.reset(); if (g_rtstage == 2) { if (g_cfg.geti("engine", 0) != 1 && g_clamd) g_clamd->kill(); g_rtstage = 0; b_rt->label("Start protection"); lb_rt->copy_label("Real-time protection stopped (clamrt exited)."); refresh_db_status(); tray_refresh(); } }
    }
    for (size_t i = 0; i < g_misc.size();) { Msg m; bool gone = false; while (g_misc[i]->pop(m, false)) if (m.type == 1) { gone = true; break; } if (gone) g_misc.erase(g_misc.begin() + (long)i); else i++; }
    if (++g_tick >= 60) { g_tick = 0; usb_poll(); dl_poll(); }           // every ~3 s
    Fl::repeat_timeout(0.05, pump);
}
static void do_quit() { kill_children(); g_cfg.save(); g_quit = true; }
static void cb_close(Fl_Widget *w, void *) {
    if (tray_active() && g_cfg.geti("close_to_tray", 1)) { w->hide(); return; }               // v2: stay in the tray (watchers keep running)
    bool busy = (g_scan && !g_scan->finished) || g_upd || g_rtstage;
    if (busy && fl_choice("A scan, update or real-time protection is still running.\nQuit and stop it?", "Keep running", "Quit", nullptr) != 1) return;
    do_quit();
}
static void tab_changed(Fl_Widget *, void *) {
    Fl_Widget *t = g_tabs->value(); const char *l = t ? t->label() : "";
    if (!strcmp(l, "Quarantine")) refresh_quarantine(); else if (!strcmp(l, "Reports")) refresh_reports(); else if (!strcmp(l, "Schedule")) refresh_sched(); else if (!strcmp(l, "Update")) refresh_db_status();
}

// ---- layout helpers
static Fl_Button *mkbtn(int x, int y, int w, int h, const char *l, Fl_Callback *cb, void *d = nullptr) { auto *b = new Fl_Button(x, y, w, h, l); b->callback(cb, d); return b; }
static Fl_Input *mkin(int x, int y, int w, int h, const char *l) { auto *i = new Fl_Input(x, y, w, h, l); i->align(FL_ALIGN_LEFT); return i; }

static void build_gui() {
    const int W = 860, H = 640;
    g_win = new Fl_Double_Window(W, H, "ClamGUI v" CLAMGUI_VERSION " - ClamAV front-end"); g_win->callback(cb_close);
    g_tabs = new Fl_Tabs(5, 5, W - 10, H - 40); g_tabs->callback(tab_changed);
    const int tx = 5, ty = 30, tw = W - 10, th = H - 70;   // tab page area

    // ---------------- Scan
    { Fl_Group *g = new Fl_Group(tx, ty, tw, th, "Scan");
      in_path = new Fl_Input(tx + 10, ty + 12, 470, 28); in_path->value(g_cfg.get("scan_path").c_str());
      mkbtn(tx + 490, ty + 12, 80, 28, "File...", cb_file); mkbtn(tx + 575, ty + 12, 80, 28, "Folder...", cb_dir);
      static const Fl_Menu_Item quick[] = {{"Home"}, {"Downloads"}, {"Documents"}, {"Whole computer"}, {nullptr}};
      ch_quick = new Fl_Choice(tx + 695, ty + 12, 150, 28, "Quick:"); ch_quick->menu(quick); ch_quick->value(0); ch_quick->callback(cb_quick);
      b_scan = mkbtn(tx + 10, ty + 48, 120, 30, "@>  Scan now", cb_scan); b_scan->color(fl_rgb_color(210, 240, 210));
      b_stop = mkbtn(tx + 135, ty + 48, 80, 30, "Stop", cb_stop); b_stop->deactivate();
      prog = new Fl_Progress(tx + 225, ty + 53, tw - 240, 20); prog->selection_color(fl_rgb_color(60, 170, 60)); prog->minimum(0); prog->maximum(100); prog->value(0);
      lb_count = new Fl_Box(tx + 10, ty + 82, tw - 20, 22, "Ready."); lb_count->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_CLIP);
      br_threat = new Fl_Multi_Browser(tx + 10, ty + 125, tw - 20, 150, "Detections:"); br_threat->align(FL_ALIGN_TOP_LEFT);
      static int cw[] = {190, 430, 130, 0}; br_threat->column_widths(cw); br_threat->column_char('\t');
      b_qsel = mkbtn(tx + 10, ty + 282, 180, 26, "Quarantine selected", cb_qsel); b_dsel = mkbtn(tx + 195, ty + 282, 150, 26, "Delete selected", cb_dsel);
      b_lookup = mkbtn(tx + 350, ty + 282, 170, 26, "Look up hash online", cb_lookup);
      tb_scan = new Fl_Text_Buffer; td_scan = new Fl_Text_Display(tx + 10, ty + 330, tw - 20, th - 340, "Log:"); td_scan->align(FL_ALIGN_TOP_LEFT); td_scan->buffer(tb_scan); td_scan->wrap_mode(Fl_Text_Display::WRAP_AT_BOUNDS, 0);
      g->resizable(td_scan); g->end(); }

    // ---------------- Update
    { Fl_Group *g = new Fl_Group(tx, ty, tw, th, "Update"); g->hide();
      b_update = mkbtn(tx + 10, ty + 12, 160, 32, "Update now", cb_update); b_update->color(fl_rgb_color(210, 225, 245));
      lb_dbinfo = new Fl_Box(tx + 190, ty + 8, tw - 200, 60, ""); lb_dbinfo->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_TOP);
      tb_upd = new Fl_Text_Buffer; td_upd = new Fl_Text_Display(tx + 10, ty + 90, tw - 20, th - 100, "freshclam output:"); td_upd->align(FL_ALIGN_TOP_LEFT); td_upd->buffer(tb_upd); td_upd->wrap_mode(Fl_Text_Display::WRAP_AT_BOUNDS, 0);
      g->resizable(td_upd); g->end(); }

    // ---------------- Quarantine
    { Fl_Group *g = new Fl_Group(tx, ty, tw, th, "Quarantine"); g->hide();
      lb_qinfo = new Fl_Box(tx + 10, ty + 6, tw - 20, 22, ""); lb_qinfo->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
      br_q = new Fl_Multi_Browser(tx + 10, ty + 34, tw - 20, th - 90); static int cw[] = {130, 170, 380, 90, 0}; br_q->column_widths(cw); br_q->column_char('\t');
      int by = ty + th - 46; mkbtn(tx + 10, by, 110, 30, "Restore...", cb_qrestore); mkbtn(tx + 125, by, 110, 30, "Delete", cb_qdelete); mkbtn(tx + 240, by, 110, 30, "Delete all", cb_qall); mkbtn(tx + 355, by, 110, 30, "Open folder", cb_qopen);
      mkbtn(tx + 480, by, 120, 30, "Analysis copy...", cb_qsandbox); mkbtn(tx + 605, by, 130, 30, "Export evidence...", cb_qexport); mkbtn(tx + 740, by, 100, 30, "Verify...", cb_qverify);
      g->resizable(br_q); g->end(); }

    // ---------------- Reports
    { Fl_Group *g = new Fl_Group(tx, ty, tw, th, "Reports"); g->hide();
      br_rep = new Fl_Hold_Browser(tx + 10, ty + 10, 250, th - 60); br_rep->callback(cb_rep);
      tb_rep = new Fl_Text_Buffer; td_rep = new Fl_Text_Display(tx + 270, ty + 10, tw - 280, th - 60); td_rep->buffer(tb_rep); td_rep->wrap_mode(Fl_Text_Display::WRAP_AT_BOUNDS, 0);
      mkbtn(tx + 10, ty + th - 40, 110, 30, "Delete report", cb_repdel); mkbtn(tx + 125, ty + th - 40, 110, 30, "Open folder", cb_repopen);
      g->resizable(td_rep); g->end(); }

    // ---------------- Real-time
    { Fl_Group *g = new Fl_Group(tx, ty, tw, th, "Real-time"); g->hide();
      in_rtpaths = new Fl_Multiline_Input(tx + 10, ty + 28, 500, 70, "Folders to watch (one per line):"); in_rtpaths->align(FL_ALIGN_TOP_LEFT); in_rtpaths->value(g_cfg.get("rt_paths").c_str());
      static const Fl_Menu_Item acts[] = {{"Report only"}, {"Quarantine (clamrt folder)"}, {nullptr}};
      ch_rtact = new Fl_Choice(tx + 640, ty + 28, 200, 28, "On detection:"); ch_rtact->align(FL_ALIGN_TOP_LEFT); ch_rtact->menu(acts); ch_rtact->value(std::max(0, std::min(1, g_cfg.geti("rt_action", 0))));
      ck_rtblock = new Fl_Check_Button(tx + 520, ty + 68, 320, 26, "Block execution of infected files (Linux, root)"); ck_rtblock->value(g_cfg.geti("rt_blockexec", 0));
      b_rt = mkbtn(tx + 10, ty + 108, 170, 32, "Start protection", cb_rt); b_rt->color(fl_rgb_color(210, 240, 210));
      lb_rt = new Fl_Box(tx + 195, ty + 108, tw - 205, 32, "Real-time protection is off."); lb_rt->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
      tb_rt = new Fl_Text_Buffer; td_rt = new Fl_Text_Display(tx + 10, ty + 170, tw - 20, th - 180, "Activity:"); td_rt->align(FL_ALIGN_TOP_LEFT); td_rt->buffer(tb_rt); td_rt->wrap_mode(Fl_Text_Display::WRAP_AT_BOUNDS, 0);
      g->resizable(td_rt); g->end(); }

    // ---------------- Schedule
    { Fl_Group *g = new Fl_Group(tx, ty, tw, th, "Schedule"); g->hide();
      ck_supd = new Fl_Check_Button(tx + 10, ty + 10, 330, 26, "Update virus definitions every day at"); ck_supd->value(g_cfg.geti("sched_update_on", 0));
      in_supdt = new Fl_Input(tx + 345, ty + 10, 70, 26); in_supdt->value(g_cfg.get("sched_update_time").c_str());
      ck_sscan = new Fl_Check_Button(tx + 10, ty + 50, 330, 26, "Run a scan at (HH:MM, 24 h):"); ck_sscan->value(g_cfg.geti("sched_scan_on", 0));
      in_sscant = new Fl_Input(tx + 345, ty + 50, 70, 26); in_sscant->value(g_cfg.get("sched_scan_time").c_str());
      in_sscanp = new Fl_Input(tx + 110, ty + 86, 600, 26, "Scan folder:"); in_sscanp->value(g_cfg.get("sched_scan_path").c_str()); mkbtn(tx + 720, ty + 86, 100, 26, "Browse...", cb_sched_pick);
      static const char *dn[] = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}; std::string dd = g_cfg.get("sched_scan_days");
      for (int i = 0; i < 7; i++) { ck_day[i] = new Fl_Check_Button(tx + 110 + i * 70, ty + 122, 66, 24, dn[i]); ck_day[i]->value((size_t)i < dd.size() && dd[(size_t)i] == '1'); }
      mkbtn(tx + 10, ty + 160, 170, 32, "Apply schedule", cb_sched_apply);
      Fl_Box *nb = new Fl_Box(tx + 200, ty + 160, tw - 210, 32,
#ifdef _WIN32
          "Uses Windows Task Scheduler (runs while you are logged on).");
#else
          "Uses your user crontab (the machine must be on at that time).");
#endif
      nb->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
      tb_sched = new Fl_Text_Buffer; td_sched = new Fl_Text_Display(tx + 10, ty + 225, tw - 20, th - 235, "Installed schedule:"); td_sched->align(FL_ALIGN_TOP_LEFT); td_sched->buffer(tb_sched);
      g->resizable(td_sched); g->end(); }

    // ---------------- Auto-protect (v2)
    { Fl_Group *g = new Fl_Group(tx, ty, tw, th, "Auto"); g->hide();
      static const Fl_Menu_Item eng[] = {{"clamscan (classic: loads signatures on every scan)"}, {"clamd daemon (fast: starts with ClamGUI, scans start instantly)"}, {nullptr}};
      ch_engine = new Fl_Choice(tx + 110, ty + 12, 520, 28, "Scan engine:"); ch_engine->menu(eng);
      ck_usb = new Fl_Check_Button(tx + 10, ty + 54, 600, 26, "Scan USB / removable drives automatically when they are inserted");
      ck_dlw = new Fl_Check_Button(tx + 10, ty + 84, 600, 26, "Watch a folder and scan new files as soon as they finish downloading (riskiest first)");
      in_dldir = mkin(tx + 110, ty + 118, 640, 26, "Folder:"); mkbtn(tx + 760, ty + 118, 80, 26, "...", cb_dl_pick);
      in_recent = new Fl_Int_Input(tx + 310, ty + 156, 60, 26, "Recent-files scan: look back (days)"); in_recent->align(FL_ALIGN_LEFT);
      mkbtn(tx + 390, ty + 154, 330, 30, "Scan recent files now (executables and archives first)", cb_recent);
      ck_notify = new Fl_Check_Button(tx + 10, ty + 200, 700, 26, "Desktop notification when a threat is found by an automatic or scheduled scan");
      ck_tray = new Fl_Check_Button(tx + 10, ty + 230, 800, 26, "Keep running in the system tray when the window is closed (the watchers above need ClamGUI to stay open)");
      mkbtn(tx + 10, ty + 270, 150, 32, "Apply", cb_auto_apply);
      lb_auto = new Fl_Box(tx + 175, ty + 270, tw - 185, 32, "Closing the window quits unless a tray icon is available."); lb_auto->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
      g->end(); }

    // ---------------- Advanced (v2)
    { Fl_Group *g = new Fl_Group(tx, ty, tw, th, "Advanced"); g->hide();
      Fl_Box *h1 = new Fl_Box(tx + 10, ty + 8, 400, 22, "Hash-only threat lookup (only the SHA-256 is sent)"); h1->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE); h1->labelfont(FL_BOLD);
      static const Fl_Menu_Item prov[] = {{"Off"}, {"MalwareBazaar (abuse.ch)"}, {"VirusTotal"}, {nullptr}};
      ch_intel = new Fl_Choice(tx + 150, ty + 34, 250, 26, "Provider:"); ch_intel->menu(prov);
      in_ikenv = mkin(tx + 150, ty + 66, 250, 26, "Key variable:"); Fl_Box *hn = new Fl_Box(tx + 410, ty + 66, tw - 420, 26, "name of the environment variable holding your API key (never stored)"); hn->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
      in_iurl = mkin(tx + 150, ty + 98, 690, 26, "URL override:");
      Fl_Box *h2 = new Fl_Box(tx + 10, ty + 140, 400, 22, "Fleet mode (central policy and report upload)"); h2->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE); h2->labelfont(FL_BOLD);
      in_policy = mkin(tx + 150, ty + 166, 690, 26, "Policy file / URL:");
      in_reporturl = mkin(tx + 150, ty + 198, 690, 26, "Report URL (https):");
      ck_reppaths = new Fl_Check_Button(tx + 150, ty + 228, 500, 24, "Include full file paths in uploaded reports");
      Fl_Box *h3 = new Fl_Box(tx + 10, ty + 262, 500, 22, "Integration and background service"); h3->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE); h3->labelfont(FL_BOLD);
#ifdef _WIN32
      mkbtn(tx + 10, ty + 290, 260, 30, "Install background service...", cb_svc_on); mkbtn(tx + 275, ty + 290, 200, 30, "Remove service", cb_svc_off);
      Fl_Box *sn = new Fl_Box(tx + 10, ty + 326, tw - 20, 40, "The service keeps clamd + clamrt running without anyone logged on. It asks for administrator rights (UAC) and copies the current settings and virus database to C:\\ProgramData\\clamgui."); sn->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
#else
      mkbtn(tx + 10, ty + 290, 260, 30, "Add file-manager menu entries", cb_fm_on); mkbtn(tx + 275, ty + 290, 200, 30, "Remove entries", cb_fm_off); mkbtn(tx + 480, ty + 290, 260, 30, "systemd service instructions", cb_unit);
      Fl_Box *sn = new Fl_Box(tx + 10, ty + 326, tw - 20, 40, "Nautilus script, Dolphin service menu, Thunar custom action and an application launcher: \"Scan with ClamGUI\"."); sn->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
#endif
      mkbtn(tx + 10, ty + 385, 150, 32, "Apply", cb_auto_apply);
      lb_adv = new Fl_Box(tx + 175, ty + 385, tw - 185, 32, ""); lb_adv->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
      g->end(); }

    // ---------------- Settings
    { Fl_Group *g = new Fl_Group(tx, ty, tw, th, "Settings"); g->hide();
      const char *tl[] = {"clamscan:", "freshclam:", "clamd:", "clamrt:", "clamdscan:"}; int y = ty + 10;
      for (int i = 0; i < 5; i++, y += 30) { in_tool[i] = mkin(tx + 110, y, 640, 26, tl[i]); mkbtn(tx + 760, y, 80, 26, "...", cb_tool_pick, (void *)(intptr_t)i); }
      in_db = mkin(tx + 110, y, 640, 26, "Virus database:"); mkbtn(tx + 760, y, 80, 26, "...", cb_dir_pick, in_db); y += 30;
      in_qd = mkin(tx + 110, y, 640, 26, "Quarantine:"); mkbtn(tx + 760, y, 80, 26, "...", cb_dir_pick, in_qd); y += 30;
      in_certs = mkin(tx + 110, y, 640, 26, "Certs folder:"); mkbtn(tx + 760, y, 80, 26, "...", cb_dir_pick, in_certs); y += 30;
      in_phost = mkin(tx + 110, y, 400, 26, "Update proxy:"); in_pport = new Fl_Input(tx + 560, y, 70, 26, "port"); in_pport->align(FL_ALIGN_LEFT); y += 38;
      ck_arch = new Fl_Check_Button(tx + 10, y, 220, 24, "Scan inside archives"); ck_pua = new Fl_Check_Button(tx + 240, y, 300, 24, "Detect potentially unwanted apps (PUA)");
      in_maxmb = new Fl_Int_Input(tx + 740, y, 60, 24, "Skip files larger than (MB):"); in_maxmb->align(FL_ALIGN_LEFT); y += 32;
      static const Fl_Menu_Item acts[] = {{"Report only"}, {"Move to quarantine"}, {"Delete"}, {nullptr}};
      ch_action = new Fl_Choice(tx + 110, y, 200, 26, "On detection:"); ch_action->menu(acts);
      { static const Fl_Menu_Item pre[] = {{"Add preset..."}, {"Browser caches"}, {"VM disk images"}, {"node_modules"}, {nullptr}};
        Fl_Choice *cp = new Fl_Choice(tx + 110, y + 36, 200, 26, "Excludes:"); cp->menu(pre); cp->callback(cb_preset); }
      in_excl = new Fl_Multiline_Input(tx + 440, y, 400, 70, "Exclude (regex,\none per line):"); in_excl->align(FL_ALIGN_LEFT); y += 80;
      mkbtn(tx + 10, y, 120, 30, "Save settings", cb_save); mkbtn(tx + 135, y, 130, 30, "Detect programs", cb_detect);
#ifdef _WIN32
      mkbtn(tx + 280, y, 220, 30, "Add Explorer menu entry", cb_shell_on); mkbtn(tx + 505, y, 200, 30, "Remove menu entry", cb_shell_off);
#endif
      g->end(); }
    g_tabs->end();
    g_status = new Fl_Box(10, H - 30, W - 110, 24, ""); g_status->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_CLIP);
    mkbtn(W - 95, H - 31, 85, 26, "About", cb_about);
    g_win->resizable(g_tabs); g_win->end();
    load_settings_ui(); load_auto_ui(); scan_buttons(); refresh_db_status();
}


// ============================================================================================ v2 NEW: system tray (status icon, balloons, one-click scan)
// Windows: Shell_NotifyIcon.  Linux: XEmbed _NET_SYSTEM_TRAY docking (works with any freedesktop tray host; there is no tray on plain GNOME
// without an extension - then tray_active() stays false, "close to tray" is disabled automatically and notifications use notify-send).
static void tray_toggle_window() { if (!g_win) return; if (g_win->visible()) g_win->hide(); else { g_win->show(); g_win->wait_for_expose(); } }
static int tray_state() {                       // 0 off, 1 partial (daemon / watchers only), 2 protected, 3 threats found by the last scan
    if (g_scan && g_scan->finished && !g_scan->threats.empty()) return 3;
    if (g_rtstage == 2) return 2;
    if (g_daemon_ready || g_cfg.geti("dl_watch", 0) || g_cfg.geti("usb_autoscan", 0)) return 1;
    return 0;
}
[[maybe_unused]] static std::string tray_tip() {
    static const char *t[] = {"ClamGUI - protection off", "ClamGUI - watching (real-time off)", "ClamGUI - real-time protection ON", "ClamGUI - THREATS FOUND, open to review"};
    return t[tray_state()];
}
static void tray_menu_cb(void *) {              // right click: three-way choice (robust on every tray host, no popup-menu positioning)
    int c = fl_choice("ClamGUI", "Open ClamGUI", "Scan recent downloads", "Quit");
    if (c == 0) { g_win->show(); g_win->wait_for_expose(); }
    else if (c == 1) { g_win->show(); g_win->wait_for_expose(); g_tabs->value(g_tabs->child(0)); cb_recent(nullptr, nullptr); }
    else if (c == 2) { bool busy = (g_scan && !g_scan->finished) || g_upd || g_rtstage; if (!busy || fl_choice("Something is still running.\nQuit and stop it?", "Keep running", "Quit", nullptr) == 1) do_quit(); }
}

#ifdef _WIN32
#include <shellapi.h>
static HWND g_trayw = nullptr; static bool g_tray_on = false; static UINT g_taskbar_msg = 0; static const UINT WM_TRAYICON = WM_APP + 1;
static NOTIFYICONDATAW tray_nid() { NOTIFYICONDATAW n{}; n.cbSize = sizeof n; n.hWnd = g_trayw; n.uID = 1; return n; }
static void tray_set_tip(NOTIFYICONDATAW &n) { std::wstring w = u2w(tray_tip()); wcsncpy(n.szTip, w.c_str(), 127); n.szTip[127] = 0; }
static bool tray_add() {
    NOTIFYICONDATAW n = tray_nid(); n.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE; n.uCallbackMessage = WM_TRAYICON; n.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32518)); tray_set_tip(n);
    return Shell_NotifyIconW(NIM_ADD, &n) != 0;
}
static LRESULT CALLBACK tray_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_TRAYICON) { if (LOWORD(l) == WM_LBUTTONUP) Fl::add_timeout(0, [](void *) { tray_toggle_window(); }); else if (LOWORD(l) == WM_RBUTTONUP) Fl::add_timeout(0, tray_menu_cb); return 0; }
    if (m == g_taskbar_msg && g_taskbar_msg) { if (g_tray_on) tray_add(); return 0; }       // Explorer restarted: re-add the icon
    return DefWindowProcW(h, m, w, l);
}
static void tray_init() {
    WNDCLASSW wc{}; wc.lpfnWndProc = tray_proc; wc.hInstance = GetModuleHandleW(nullptr); wc.lpszClassName = L"ClamGUITray"; RegisterClassW(&wc);
    g_trayw = CreateWindowExW(0, L"ClamGUITray", L"ClamGUI", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, wc.hInstance, nullptr); if (!g_trayw) return;
    g_taskbar_msg = RegisterWindowMessageW(L"TaskbarCreated"); g_tray_on = tray_add();
}
static bool tray_active() { return g_tray_on; }
static void tray_refresh() { if (!g_tray_on) return; NOTIFYICONDATAW n = tray_nid(); n.uFlags = NIF_TIP; tray_set_tip(n); Shell_NotifyIconW(NIM_MODIFY, &n); }
static bool tray_balloon(const std::string &title, const std::string &body) {
    if (!g_tray_on) return false;
    NOTIFYICONDATAW n = tray_nid(); n.uFlags = NIF_INFO; n.dwInfoFlags = NIIF_WARNING;
    std::wstring t = u2w(title), b = u2w(body); wcsncpy(n.szInfoTitle, t.c_str(), 63); n.szInfoTitle[63] = 0; wcsncpy(n.szInfo, b.c_str(), 255); n.szInfo[255] = 0;
    return Shell_NotifyIconW(NIM_MODIFY, &n) != 0;
}
#else
#include <FL/x.H>
#include <X11/Xlib.h>
#include <X11/Xatom.h>
static ::Window g_tw = 0; static bool g_tray_on = false; static GC g_tgc = nullptr; static int g_tray_w = 24, g_tray_h = 24;
static void tray_draw() {
    if (!g_tw || !g_tgc) return;
    unsigned char rgb[4][3] = {{140, 140, 140}, {230, 170, 30}, {40, 170, 70}, {210, 40, 40}}; int st = tray_state();
    XClearWindow(fl_display, g_tw);
    XSetForeground(fl_display, g_tgc, fl_xpixel(fl_rgb_color(rgb[st][0], rgb[st][1], rgb[st][2])));
    int d = std::min(g_tray_w, g_tray_h) - 4; if (d < 8) d = 8;
    XFillArc(fl_display, g_tw, g_tgc, (g_tray_w - d) / 2, (g_tray_h - d) / 2, (unsigned)d, (unsigned)d, 0, 360 * 64);
    XSetForeground(fl_display, g_tgc, fl_xpixel(FL_WHITE));                       // white check / cross mark
    if (st == 3) { XDrawLine(fl_display, g_tw, g_tgc, g_tray_w / 2, g_tray_h / 2 - d / 4, g_tray_w / 2, g_tray_h / 2 + d / 12); XFillRectangle(fl_display, g_tw, g_tgc, g_tray_w / 2 - 1, g_tray_h / 2 + d / 5, 2, 2); }
    else if (st == 2) { int cx = g_tray_w / 2, cy = g_tray_h / 2; XDrawLine(fl_display, g_tw, g_tgc, cx - d / 4, cy, cx - d / 12, cy + d / 5); XDrawLine(fl_display, g_tw, g_tgc, cx - d / 12, cy + d / 5, cx + d / 4, cy - d / 5); }
    XFlush(fl_display);
}
static int tray_sysevent(void *ev, void *) {      // raw X events for the tray window (FLTK does not know about it)
    XEvent *e = (XEvent *)ev; if (!g_tw || e->xany.window != g_tw) return 0;
    switch (e->type) {
    case Expose: tray_draw(); return 1;
    case ConfigureNotify: g_tray_w = e->xconfigure.width; g_tray_h = e->xconfigure.height; tray_draw(); return 1;
    case ReparentNotify: g_tray_on = e->xreparent.parent != RootWindow(fl_display, fl_screen); Fl::add_timeout(0, [](void *) { tray_refresh(); }); return 1;
    case DestroyNotify: g_tray_on = false; g_tw = 0; return 1;
    case ButtonPress: if (e->xbutton.button == 1) Fl::add_timeout(0, [](void *) { tray_toggle_window(); }); else if (e->xbutton.button == 3) Fl::add_timeout(0, tray_menu_cb); return 1;
    default: return 0;
    }
}
static void tray_init() {
    if (!fl_display) return;
    char sel[64]; snprintf(sel, sizeof sel, "_NET_SYSTEM_TRAY_S%d", fl_screen);
    Atom selatom = XInternAtom(fl_display, sel, False); ::Window mgr = XGetSelectionOwner(fl_display, selatom); if (!mgr) return;       // no tray host: stay off
    g_tw = XCreateSimpleWindow(fl_display, RootWindow(fl_display, fl_screen), 0, 0, 24, 24, 0, 0, fl_xpixel(FL_BACKGROUND_COLOR));
    XSelectInput(fl_display, g_tw, ExposureMask | ButtonPressMask | StructureNotifyMask);
    XStoreName(fl_display, g_tw, "ClamGUI");
    unsigned long info[2] = {0, 1}; Atom ei = XInternAtom(fl_display, "_XEMBED_INFO", False); XChangeProperty(fl_display, g_tw, ei, ei, 32, PropModeReplace, (unsigned char *)info, 2);
    g_tgc = XCreateGC(fl_display, g_tw, 0, nullptr);
    Fl::add_system_handler(tray_sysevent, nullptr);
    XEvent m{}; m.xclient.type = ClientMessage; m.xclient.window = mgr; m.xclient.message_type = XInternAtom(fl_display, "_NET_SYSTEM_TRAY_OPCODE", False); m.xclient.format = 32;
    m.xclient.data.l[0] = CurrentTime; m.xclient.data.l[1] = 0; m.xclient.data.l[2] = (long)g_tw;                    // SYSTEM_TRAY_REQUEST_DOCK
    XSendEvent(fl_display, mgr, False, NoEventMask, &m); XSync(fl_display, False);
}
static bool tray_active() { return g_tray_on && g_tw; }
static void tray_refresh() { if (g_tw) tray_draw(); }
static bool tray_balloon(const std::string &, const std::string &) { return false; }           // freedesktop balloons are done by notify-send
#endif

// ============================================================================================ main
int main(int argc, char **argv) {
    std::vector<std::string> args;
#ifdef _WIN32
    { int n = 0; wchar_t **w = CommandLineToArgvW(GetCommandLineW(), &n); for (int i = 1; w && i < n; i++) args.push_back(w2u(w[i])); if (w) LocalFree(w); }   // UTF-8 arguments
    (void)argc; (void)argv;
#else
    for (int i = 1; i < argc; i++) args.push_back(argv[i]);
#endif
    std::vector<std::string> paths; std::string mode, idarg, optto; int tab = 0, days = 14; bool force = false;
    for (size_t i = 0; i < args.size(); i++) {
        const std::string &a = args[i];
        if (a == "--version") { attach_console(); printf("ClamGUI v" CLAMGUI_VERSION "\n"); return 0; }
        if (a == "--help" || a == "-h") { attach_console(); usage(); return 0; }
        if (a == "--scan" || a == "--scheduled-scan" || a == "--scheduled-update" || a == "--quarantine-list" || a == "--install-schedule" || a == "--remove-schedule" || a == "--sha256" || a == "--service" || a == "--print-systemd-unit" || a == "--install-filemanager" || a == "--remove-filemanager" || a == "--install-service" || a == "--remove-service" || a == "--install-service-elevated" || a == "--remove-service-elevated") mode = a;
        else if ((a == "--restore" || a == "--delete" || a == "--export-evidence" || a == "--verify-export" || a == "--lookup" || a == "--policy-sign") && i + 1 < args.size()) { mode = a; idarg = args[++i]; }
        else if (a == "--scan-recent") { mode = a; if (i + 1 < args.size() && args[i + 1].compare(0, 2, "--") != 0) idarg = args[++i]; }
        else if (a == "--days" && i + 1 < args.size()) days = atoi(args[++i].c_str());
        else if (a == "--to" && i + 1 < args.size()) optto = args[++i];
        else if (a == "--force") force = true;
        else if (a == "--home" && i + 1 < args.size()) { static std::string h; h = args[++i];
#ifdef _WIN32
            _wputenv_s(L"CLAMGUI_HOME", u2w(h).c_str());
#else
            setenv("CLAMGUI_HOME", h.c_str(), 1);
#endif
        }
        else if (a == "--tab" && i + 1 < args.size()) tab = atoi(args[++i].c_str());
        else if (a == "--") { for (i++; i < args.size(); i++) paths.push_back(args[i]); }
        else if (a.size() > 1 && a[0] == '-' && a != "-") { attach_console(); fprintf(stderr, "unknown option: %s\n", a.c_str()); usage(); return 2; }
        else paths.push_back(a);
    }
    g_cfg.load();
    { std::string pm; if (!apply_policy(pm) || !pm.empty()) { if (!mode.empty()) { attach_console(); fprintf(stderr, "policy: %s\n", pm.c_str()); } } }     // v2: fleet policy overlay (before anything reads the settings)
    if (!mode.empty()) {
        attach_console();
        if (mode == "--print-systemd-unit") {
#ifndef _WIN32
            print_systemd_unit(); return 0;
#else
            fprintf(stderr, "systemd is Linux-only\n"); return 2;
#endif
        }
        if (mode == "--install-filemanager" || mode == "--remove-filemanager") {
#ifndef _WIN32
            std::string m; bool ok = mode == "--install-filemanager" ? fm_install(m) : fm_remove(m); printf("%s\n", m.c_str()); return ok ? 0 : 2;
#else
            fprintf(stderr, "file-manager entries are Linux-only (Explorer integration is not part of this version)\n"); return 2;
#endif
        }
        if (mode == "--service") {
#ifdef _WIN32
            int r = run_service_dispatcher(); if (r == 0) return 0;               // started by the service manager
            fprintf(stderr, "not started by the service manager - running in the console (Ctrl+C to stop)\n");
            SetConsoleCtrlHandler([](DWORD) -> BOOL { g_svc_stop = true; return TRUE; }, TRUE);
#else
            signal(SIGTERM, [](int) { g_svc_stop = true; }); signal(SIGINT, [](int) { g_svc_stop = true; }); signal(SIGHUP, SIG_IGN); signal(SIGPIPE, SIG_IGN);
#endif
            return run_supervisor();
        }
#ifdef _WIN32
        if (mode == "--install-service" || mode == "--remove-service" || mode == "--install-service-elevated" || mode == "--remove-service-elevated") {
            bool inst = mode.find("install") != std::string::npos, elev = mode.find("elevated") != std::string::npos; std::string m;
            if (elev && !is_admin()) return 2;       // never re-elevate recursively
            bool ok = (inst ? (is_admin() ? service_install_now(m) : service_elevated(L"--install-service-elevated", m)) : (is_admin() ? service_remove_now(m) : service_elevated(L"--remove-service-elevated", m)));
            if (!elev) printf("%s\n", m.c_str());
            return ok ? 0 : 2;
        }
#else
        if (mode == "--install-service" || mode == "--remove-service" || mode == "--install-service-elevated" || mode == "--remove-service-elevated") { fprintf(stderr, "on Linux use: clamgui --print-systemd-unit\n"); return 2; }
#endif
        if (mode == "--scan") { if (paths.empty()) { fprintf(stderr, "--scan needs at least one path\n"); return 2; } return cli_scan(paths, false); }
        if (mode == "--scheduled-scan") { std::string p = g_cfg.get("sched_scan_path"); if (p.empty()) { fprintf(stderr, "no scheduled scan folder configured\n"); return 2; } return cli_scan({p}, true, "", 0, "scheduled scan"); }
        if (mode == "--scan-recent") { std::string d = idarg.empty() ? g_cfg.get("dl_dir") : idarg; if (days < 1 || days > 3650) days = 14; return cli_scan_recent(d, days); }
        if (mode == "--lookup") return cli_lookup(idarg);
        if (mode == "--export-evidence") return cli_quarantine("export", idarg);
        if (mode == "--verify-export") return cli_quarantine("verify", idarg);
        if (mode == "--policy-sign") { std::string t, key = env("CLAMGUI_POLICY_KEY"); if (key.empty() || !read_file(idarg, t, 1u << 20)) { fprintf(stderr, "error: set CLAMGUI_POLICY_KEY and give a readable policy file\n"); return 2; } std::string body; for (auto &l : split(t, '\n')) { std::string x = l; if (!x.empty() && x.back() == '\r') x.pop_back(); if (!starts_with(x, "hmac=")) body += x + "\n"; } while (body.size() > 1 && body[body.size() - 1] == '\n' && body[body.size() - 2] == '\n') body.pop_back(); printf("%shmac=%s\n", body.c_str(), hmac_sha256(key, body).c_str()); return 0; }
        if (mode == "--sha256") { int rc = 0; for (auto &f : paths) { std::string h; if (sha256_file(f, h)) printf("%s  %s\n", h.c_str(), f.c_str()); else { fprintf(stderr, "cannot read %s\n", f.c_str()); rc = 2; } } return rc; }
        if (mode == "--scheduled-update") return cli_update();
        if (mode == "--install-schedule" || mode == "--remove-schedule") {          // apply / remove the schedule stored in the settings file
            std::string msg; bool on = mode == "--install-schedule";
            bool ok = sched_apply(on && g_cfg.geti("sched_update_on"), g_cfg.get("sched_update_time"), on && g_cfg.geti("sched_scan_on"), g_cfg.get("sched_scan_time"), g_cfg.get("sched_scan_days"), msg);
            printf("%s\n%s", msg.c_str(), sched_status().c_str()); return ok ? 0 : 2;
        }
        if (mode == "--quarantine-list") return cli_quarantine("list", "");
        return cli_quarantine(mode == "--restore" ? "restore" : "delete", idarg, optto, force);
    }
    signal(SIGINT, [](int) { g_sigquit = 1; }); signal(SIGTERM, [](int) { g_sigquit = 1; });
#ifndef _WIN32
    signal(SIGHUP, [](int) { g_sigquit = 1; }); signal(SIGPIPE, SIG_IGN);
#endif
    Fl::scheme("gtk+"); FL_NORMAL_SIZE = 13; Fl::lock();
    build_gui();
    g_win->show();
    if (tab >= 0 && tab < g_tabs->children()) g_tabs->value(g_tabs->child(tab));
    tab_changed(nullptr, nullptr);
    Fl::add_timeout(0.05, pump);
    tray_init();
    if (g_cfg.geti("engine", 0) == 1) daemon_start(false);               // v2: fast engine = clamd starts with the GUI
    if (!paths.empty()) { std::vector<std::string> abs; for (auto &p : paths) { std::error_code ec; auto a = fs::absolute(P(p), ec); abs.push_back(ec ? p : u8(a)); } in_path->value(abs[0].c_str()); start_scan(abs); }
    while (!g_quit) Fl::wait(0.1);                  // v2: not Fl::run(), so a window hidden to the tray does not end the program
    int rc = 0;
    if (g_scan && !g_scan->finished) g_scan->proc.kill();
    return rc;
}
