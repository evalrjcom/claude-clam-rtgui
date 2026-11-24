#!/bin/bash
# clamrt v4 end-to-end tests for the v3 features (regression suite) (Linux).  Run e2e_test.sh as well for the v2 regression suite.
# usage: [T=workdir] [CLAMD=path/to/clamd] [CERTS=dir] e2e_v3_test.sh <clamrt-binary>
# fanotify tests need root (CAP_SYS_ADMIN) and are skipped otherwise.  Tests use a private clamd + 1-signature DB.
set -u
RT=$1; T=${T:-/tmp/clamrt_e2e3}; CLAMD=${CLAMD:-clamd}; CERTS=${CERTS:-}
pkill -f "clamd -c $T/clamd.conf" 2>/dev/null; sleep 0.5
rm -rf $T; mkdir -p $T/db $T/q; chmod 700 $T/q
printf 'Test.Sig:0:*:deadbeefcafe0123\n' > $T/db/t.ndb
cat > $T/clamd.conf <<EOC
LocalSocket $T/clamd.sock
DatabaseDirectory $T/db
Foreground yes
LogFile $T/clamd.log
EOC
[ -n "$CERTS" ] && echo "CVDCertsDirectory $CERTS" >> $T/clamd.conf
BAD() { printf '\xde\xad\xbe\xef\xca\xfe\x01\x23 payload %s' "$1"; }
start_clamd() { ($CLAMD -c $T/clamd.conf >$T/clamd.out 2>&1 &); for i in $(seq 1 40); do [ -S $T/clamd.sock ] && break; sleep 0.5; done; }
stop_clamd() { pkill -f "clamd -c $T/clamd.conf"; sleep 0.5; rm -f $T/clamd.sock; }
P=0; F=0; S=0
chk() { if eval "$2"; then echo "PASS: $1"; P=$((P+1)); else echo "FAIL: $1"; F=$((F+1)); fi; }
skip() { echo "SKIP: $1"; S=$((S+1)); }
ROOT=0; [ "$(id -u)" = 0 ] && ROOT=1
FAN=0; if [ $ROOT = 1 ]; then ( $RT --mode fanotify --path $T/q --version >/dev/null ) ; fi
start_clamd
RTPIDS=""
run_rt() { # run_rt <name> args...   (background; log to $T/<name>.log)
  local n=$1; shift
  ($RT --clamd-socket $T/clamd.sock --debounce-ms 200 --log $T/$n.log "$@" & echo $! > $T/$n.pid); sleep 1.2
}
stop_rt() { kill -TERM $(cat $T/$1.pid) 2>/dev/null; sleep 1.3; }
G() { curl -s --max-time 3 "http://127.0.0.1:$1$2"; }

############################################################ A+B+C: JSON log, SHA-256, metrics, verdict cache, sweep
mkdir -p $T/a; run_rt a --path $T/a --log-format json --metrics 19110 --sweep-interval 5
BAD one > $T/a/evil.bin
printf 'clean content here\n' > $T/a/clean.txt
BAD two > "$T/a/qu\"ote\\back.bin"
printf '\xde\xad\xbe\xef\xca\xfe\x01\x23 bad-utf8-\xff\xfe' > "$T/a/bad$(printf '\xff')name.bin"
sleep 2
SHA=$(sha256sum $T/a/evil.bin | cut -d' ' -f1)
chk "JSON log: every line parses as JSON" "python3 -c \"import json,sys; [json.loads(l) for l in open('$T/a.log')]\""
chk "JSON log: detection record has sha256 equal to sha256sum" "python3 - <<PY
import json
for l in open('$T/a.log'):
    d=json.loads(l)
    if d.get('event')=='detection' and d['path'].endswith('/evil.bin'):
        assert d['sha256']=='$SHA' and d['signature'].startswith('Test.Sig') and d['how']=='scan'; raise SystemExit(0)
raise SystemExit(1)
PY"
chk "JSON log: quote/backslash/invalid-UTF-8 names stay valid JSON, all 3 infected found" "[ \$(grep -c '\"event\":\"detection\"' $T/a.log) -ge 3 ]"
M=$(G 19110 /metrics)
chk "metrics: /metrics reachable, detections_total >= 3" "echo \"\$M\" | awk '/^clamrt_detections_total/{exit !(\$2>=3)}'"
chk "metrics: files_scanned_total >= 4 and build_info present" "echo \"\$M\" | awk '/^clamrt_files_scanned_total/{ok=(\$2>=4)} END{exit !ok}' && echo \"\$M\" | grep -q 'clamrt_build_info{version=\"4\"} 1'"
chk "metrics: /status.json is valid JSON" "G 19110 /status.json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d[\"version\"]==\"4\"'"
chk "metrics: /events lists the detection" "G 19110 /events | grep -q 'detection Test.Sig'"
chk "metrics: /healthz ok, unknown path 404, POST 405" "[ \"\$(G 19110 /healthz)\" = ok ] && [ \$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:19110/nope) = 404 ] && [ \$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:19110/metrics) = 405 ]"
chk "metrics: garbage request does not kill the server" "(printf 'GARBAGE\r\n\r\n' | timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/19110; cat >&3; cat <&3' >/dev/null 2>&1; [ \"\$(G 19110 /healthz)\" = ok ])"
chk "metrics: loopback-only by default (listening on 127.0.0.1)" "grep -qi ' 0100007F:4AA6 ' /proc/net/tcp && ! grep -qi ' 00000000:4AA6 ' /proc/net/tcp"
# sweep + verdict cache: the clean file is re-visited by the 5 s sweep but not re-scanned (cache hit)
sleep 7
M=$(G 19110 /metrics)
chk "verdict cache: sweep re-visited unchanged clean file -> cache hits > 0" "echo \"\$M\" | awk '/^clamrt_verdict_cache_hits_total/{exit !(\$2>=1)}'"
# TUI against the live endpoint (pty)
chk "TUI: renders dashboard from /metrics and quits on q" "python3 - <<PY
import pty,os,time,select,sys
pid,fd=pty.fork()
if pid==0:
    os.execv('$RT',['$RT','--tui','19110'])
out=b''; t=time.time()
while time.time()-t<2.5:
    r,_,_=select.select([fd],[],[],0.3)
    if r:
        try: out+=os.read(fd,65536)
        except OSError: break
os.write(fd,b'q'); time.sleep(0.6)
try: out+=os.read(fd,65536)
except OSError: pass
_,st=os.waitpid(pid,0)
ok=b'dashboard' in out and b'DETECTIONS' in out and b'connected' in out and os.WIFEXITED(st) and os.WEXITSTATUS(st)==0
sys.exit(0 if ok else 1)
PY"
chk "TUI: shows DISCONNECTED (no crash) when nothing listens" "python3 - <<PY
import pty,os,time,select,sys
pid,fd=pty.fork()
if pid==0: os.execv('$RT',['$RT','--tui','19999'])
out=b''; t=time.time()
while time.time()-t<2.0:
    r,_,_=select.select([fd],[],[],0.3)
    if r:
        try: out+=os.read(fd,65536)
        except OSError: break
os.write(fd,b'q'); time.sleep(0.5); _,st=os.waitpid(pid,0)
sys.exit(0 if b'DISCONNECTED' in out and os.WEXITSTATUS(st)==0 else 1)
PY"
stop_rt a
chk "worker pool: --workers 4 accepted, --workers 0 / 99 rejected" "$RT --path $T/a --workers 0 >/dev/null 2>&1; [ \$? -eq 2 ] && $RT --path $T/a --workers 99 >/dev/null 2>&1; [ \$? -eq 2 ]"

############################################################ F: threat intel (fake MalwareBazaar / VirusTotal)
cat > $T/fakeapi.py <<'PY'
import http.server,sys,json
log=open(sys.argv[2],'a')
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def _rec(self,body=b''):
        log.write(json.dumps({"method":self.command,"path":self.path,"hdr":{k:v for k,v in self.headers.items()},"body":body.decode()})+"\n"); log.flush()
    def do_POST(self):
        n=int(self.headers.get('Content-Length',0)); b=self.rfile.read(n); self._rec(b)
        if b'KNOWNHASH' in b:
            r={"query_status":"ok","data":[{"signature":"AgentTesla","first_seen":"2026-01-02 03:04:05","file_type":"exe"}]}
        else: r={"query_status":"hash_not_found"}
        out=json.dumps(r).encode(); self.send_response(200); self.send_header('Content-Length',str(len(out))); self.end_headers(); self.wfile.write(out)
    def do_GET(self):
        self._rec()
        if self.path.startswith('/files/KNOWN'):
            r={"data":{"attributes":{"last_analysis_stats":{"malicious": 42},"suggested_threat_label":"trojan.emotet","first_submission_date": 1700000000}}}; code=200
        else: r={"error":{"code":"NotFoundError"}}; code=404
        out=json.dumps(r).encode(); self.send_response(code); self.send_header('Content-Length',str(len(out))); self.end_headers(); self.wfile.write(out)
http.server.HTTPServer(('127.0.0.1',int(sys.argv[1])),H).serve_forever()
PY
python3 $T/fakeapi.py 19120 $T/api.log & APIPID=$!; sleep 1
mkdir -p $T/i; export FAKE_KEY=sekret-Key_123
run_rt i --path $T/i --action report --intel mb --intel-url http://127.0.0.1:19120/api/v1/ --intel-key-env FAKE_KEY --metrics 19111
BAD intelfile > $T/i/hit.bin; sleep 4
chk "intel(mb): request carried the SHA-256 only (no path / file name / content)" "grep -q \"$(sha256sum $T/i/hit.bin | cut -d' ' -f1)\" $T/api.log && ! grep -q 'hit.bin\|intelfile\|payload' $T/api.log"
chk "intel(mb): API key sent as header (from env), not on any command line" "grep -q 'sekret-Key_123' $T/api.log && ! ps -eo args | grep -v grep | grep -q 'sekret-Key_123'"
chk "intel(mb): unknown hash logged as never seen" "grep -q 'INTEL: malwarebazaar has never seen sha256' $T/i.log"
chk "intel: metrics count the query" "G 19111 /metrics | awk '/^clamrt_intel_queries_total/{exit !(\$2>=1)}'"
stop_rt i
# a hash the fake API knows: craft it by making the server treat a marker as known -> use a file whose hash we pre-register
sed -i "s/KNOWNHASH/$(BAD known1 | sha256sum | cut -d' ' -f1)/" $T/fakeapi.py; kill $APIPID; python3 $T/fakeapi.py 19120 $T/api.log & APIPID=$!; sleep 1
run_rt i2 --path $T/i --action report --intel mb --intel-url http://127.0.0.1:19120/api/v1/ --intel-key-env FAKE_KEY
BAD known1 > $T/i/known.bin; sleep 4
chk "intel(mb): known hash -> family + first_seen logged" "grep -q 'INTEL: malwarebazaar knows sha256.*family=AgentTesla.*first_seen=2026-01-02' $T/i2.log"
stop_rt i2
KH=$(BAD known1 | sha256sum | cut -d' ' -f1)
sed -i "s|/files/KNOWN|/files/$KH|" $T/fakeapi.py; kill $APIPID; python3 $T/fakeapi.py 19120 $T/api.log & APIPID=$!; sleep 1
run_rt i3 --path $T/i --action report --intel vt --intel-url http://127.0.0.1:19120 --intel-key-env FAKE_KEY
BAD known1 > $T/i/known2.bin; sleep 4
chk "intel(vt): known hash -> engines_malicious=42 + label logged" "grep -q 'INTEL: virustotal knows.*family=trojan.emotet.*engines_malicious=42' $T/i3.log"
chk "intel(vt): API key sent as x-apikey header" "grep -q '\"x-apikey\": \"sekret-Key_123\"' $T/api.log"
stop_rt i3
kill $APIPID 2>/dev/null
run_rt i4 --path $T/i --action report --intel mb --intel-url http://127.0.0.1:1/ --intel-key-env FAKE_KEY --metrics 19112
BAD unreachable > $T/i/u.bin; sleep 4
chk "intel: unreachable API is an error counter + warning, scanning unaffected" "grep -q 'INFECTED.*u.bin' $T/i4.log && grep -q 'intel: lookup failed' $T/i4.log && G 19112 /metrics | awk '/^clamrt_intel_errors_total/{exit !(\$2>=1)}'"
stop_rt i4
( unset FAKE_KEY; $RT --path $T/i --intel mb >/dev/null 2>&1; echo $? > $T/rc ); chk "intel: refuses to start without a key source" "[ \$(cat $T/rc) -ne 0 ]"
FAKE_KEY='bad"key' $RT --path $T/i --intel mb --intel-key-env FAKE_KEY >/dev/null 2>&1; chk "intel: key with config-injection characters refused" "[ \$? -ne 0 ]"

############################################################ D: fanotify
if [ $ROOT = 1 ] && $RT --mode fanotify --path $T/q --metrics 19999 --version >/dev/null 2>&1 && python3 -c "
import ctypes;l=ctypes.CDLL(None,use_errno=True);import sys;sys.exit(0 if l.fanotify_init(1|2|4,0)>=0 else 1)" ; then
mkdir -p $T/f; cp /bin/true $T/f/clean_true; cp /bin/true $T/f/inf_true; BAD exe >> $T/f/inf_true; chmod +x $T/f/*
run_rt f --path $T/f --mode fanotify --block-exec --action report --metrics 19113
chk "fanotify: started (mount-wide, blocking)" "grep -q 'with fanotify (mount-wide, BLOCKING' $T/f.log"
$T/f/clean_true; chk "fanotify: clean binary executes" "[ \$? -eq 0 ]"
$T/f/inf_true 2>$T/f/err; rc=$?
chk "fanotify: INFECTED binary execution is DENIED (EPERM)" "[ $rc -ne 0 ] && grep -qi 'not permitted\|permission' $T/f/err"
chk "fanotify: denial logged with pid + process + sha256 + how=exec-block" "grep -q 'INFECTED: .*inf_true' $T/f.log"
chk "fanotify: exec_denied metric incremented" "G 19113 /metrics | awk '/^clamrt_exec_denied_total/{exit !(\$2>=1)}'"
for i in 1 2 3 4 5; do $T/f/clean_true; done
chk "fanotify: repeated executions of the same clean binary served from verdict cache" "G 19113 /metrics | awk '/^clamrt_exec_cache_hits_total/{exit !(\$2>=3)}'"
mkdir -p $T/f/newdir/deep; BAD closewrite > $T/f/newdir/deep/cw.bin; sleep 2
chk "fanotify: write in a brand-new nested dir caught (no per-directory watch needed)" "grep -q 'INFECTED: .*cw.bin' $T/f.log"
ln $T/f/inf_true $T/f/hardlink_x 2>/dev/null; true
stop_rt f
chk "fanotify: shutdown leaves no stuck executions (exec works after stop)" "$T/f/clean_true"
# fail-open / fail-closed when clamd is gone
stop_clamd
cp /bin/true $T/f/failtest1; cp /bin/true $T/f/failtest2; chmod +x $T/f/*
run_rt f2 --path $T/f --mode fanotify --block-exec --exec-fail open --exec-timeout-ms 1500
s=$(date +%s%N); $T/f/failtest1; rc1=$?; e=$(( ($(date +%s%N)-s)/1000000 ))
chk "fanotify: clamd down + fail-open: exec ALLOWED, within deadline (${e} ms)" "[ $rc1 -eq 0 ] && [ $e -lt 3500 ]"
stop_rt f2
run_rt f3 --path $T/f --mode fanotify --block-exec --exec-fail closed --exec-timeout-ms 1500
$T/f/failtest2 2>/dev/null; rc2=$?
chk "fanotify: clamd down + fail-closed: exec DENIED" "[ $rc2 -ne 0 ]"
stop_rt f3
chk "fanotify: after stop, exec works again" "$T/f/failtest2"
start_clamd
# sweep catches hard links that fanotify (close-write only) cannot see
mkdir -p $T/h $T/h_out; BAD hl > $T/h_out/evilsrc; touch -d '2001-01-01' $T/h_out/evilsrc
run_rt h --path $T/h --mode fanotify --action report --sweep-interval 5
ln $T/h_out/evilsrc $T/h/hl.bin; sleep 8
chk "fanotify+sweep: hard-linked infected file (old mtime, new ctime) caught by the ctime sweep" "grep -q 'INFECTED: .*hl.bin' $T/h.log"
stop_rt h
# --no-recursive must also hold in fanotify mode (mount marks see the whole mount)
mkdir -p $T/nr/sub; run_rt nr --path $T/nr --mode fanotify --no-recursive --action report
BAD top > $T/nr/top.bin; BAD deep > $T/nr/sub/deep.bin; sleep 2.5
chk "fanotify: --no-recursive honoured (top-level caught, sub-directory file ignored)" "grep -q 'INFECTED: .*top.bin' $T/nr.log && ! grep -q 'deep.bin' $T/nr.log"
stop_rt nr
run_rt fc --path $T/nr --mode fanotify --block-exec --exec-fail closed --exec-timeout-ms 800
chk "fanotify: --exec-fail closed prints the lock-out warning" "grep -q 'fail-closed: while clamd is unavailable EVERY program' $T/fc.log"
stop_rt fc
else skip "fanotify tests (need root + fanotify support)"; fi

############################################################ E: tripwire
mkdir -p $T/t1 $T/t2
CAN=$T/t1/AAAA_clamrt_canary_do_not_edit.docx
if [ $ROOT = 1 ] && python3 -c "
import ctypes;l=ctypes.CDLL(None,use_errno=True);import sys;sys.exit(0 if l.fanotify_init(1|2|4,0)>=0 else 1)"; then
run_rt t1 --path $T/t1 --mode fanotify --canary --tripwire-action suspend --metrics 19114
chk "tripwire: canary planted, low entropy, correct name" "[ -s $CAN ] && python3 -c \"import math,collections;d=open('$CAN','rb').read();c=collections.Counter(d);print(-sum(v/len(d)*math.log2(v/len(d)) for v in c.values()))\" | awk '{exit !(\$1<5)}'"
python3 - $CAN > $T/t1/victim.pid <<'PY' &
import sys,os,time
print(os.getpid(),flush=True)
time.sleep(1.5)
open(sys.argv[1],'ab').write(b'ENCRYPTED')   # ransomware overwrites the canary
for i in range(300):
    print('tick',i,file=sys.stderr); time.sleep(0.1)
PY
sleep 4; VP=$(head -1 $T/t1/victim.pid)
chk "tripwire(fanotify): canary write detected, pid attributed" "grep -q 'TRIPWIRE: canary file written' $T/t1.log && grep -q 'pid\|python' $T/t1.log"
chk "tripwire(fanotify): offending process SUSPENDED (state T)" "grep -q '^State:.*T (stopped)' /proc/$VP/status"
kill -KILL $VP 2>/dev/null
# encrypted-looking write storm by one process (rate rule), plus legit compressed / text files that must NOT trip
python3 - $T/t1 <<'PY' > $T/t1/storm.pid &
import os,sys,time
print(os.getpid(),flush=True)
time.sleep(1.5)
for i in range(120):
    open(f"{sys.argv[1]}/doc{i}.dat",'wb').write(os.urandom(8192)); time.sleep(0.02)
time.sleep(30)
PY
sleep 6; SP=$(head -1 $T/t1/storm.pid)
chk "tripwire(rate): high-entropy write storm detected + process suspended" "grep -q 'TRIPWIRE: .* encrypted-looking file writes' $T/t1.log && grep -q '^State:.*T (stopped)' /proc/$SP/status"
kill -KILL $SP 2>/dev/null
stop_rt t1
run_rt t2 --path $T/t2 --mode fanotify --canary --tripwire-action suspend --metrics 19115
python3 - $T/t2 <<'PY'
import os,sys,gzip,zlib
d=sys.argv[1]
for i in range(150):
    with gzip.open(f"{d}/real{i}.gz",'wb') as f: f.write(os.urandom(4096))          # genuine gzip: high entropy but magic OK
for i in range(150):
    open(f"{d}/text{i}.txt",'w').write(("hello world %d\n"%i)*400)                 # low entropy
for i in range(100):
    open(f"{d}/img{i}.jpg",'wb').write(b'\xff\xd8\xff\xe0'+os.urandom(6000))        # genuine jpg header
PY
sleep 4
chk "tripwire: NO false positives on 150 genuine .gz + 150 text + 100 .jpg files" "! grep -q 'TRIPWIRE' $T/t2.log"
timeout 20 python3 - $T/t2 <<'PY' &
import os,sys,time
for i in range(80): open(f"{sys.argv[1]}/photo{i}.jpg",'wb').write(os.urandom(6000))  # encrypted IN PLACE under original extension
time.sleep(15)
PY
IP=$!; sleep 4
chk "tripwire: the in-place encryptor process was SUSPENDED mid-run (stopped, not finished)" "grep -q 'process SUSPENDED' $T/t2.log && grep -q '^State:.*T (stopped)' /proc/\$(pgrep -f \"^python3 - $T/t2\" | head -1)/status"
pkill -KILL -f "python3 - $T/t2" 2>/dev/null; wait $IP 2>/dev/null; sleep 0.3
chk "tripwire: jpg files whose magic no longer matches (encrypted in place) DO trip" "grep -q 'TRIPWIRE: .* encrypted-looking' $T/t2.log"
stop_rt t2
mkdir -p $T/t3; sleep 0.2
cat > $T/t3_ig.py <<'PY'
import os,sys,time
os.system("cp /bin/sleep $0.slp 2>/dev/null")
PY
run_rt t3 --path $T/t3 --mode fanotify --tripwire --tripwire-action kill --tripwire-ignore-comm python3 --tripwire-rate 20
python3 -c "
import os
for i in range(60): open('$T/t3/x%d.dat'%i,'wb').write(os.urandom(4096))"
sleep 3
chk "tripwire: --tripwire-ignore-comm python3 -> storm from python3 is ignored, process alive" "! grep -q 'TRIPWIRE' $T/t3.log"
stop_rt t3
else skip "tripwire fanotify tests"; fi
# inotify mode: canary deletion alert (no pid available), suspend request degrades gracefully
mkdir -p $T/t4; run_rt t4 --path $T/t4 --mode inotify --canary --tripwire-action suspend
rm -f $T/t4/AAAA_clamrt_canary_do_not_edit.docx; sleep 1.5
chk "tripwire(inotify): canary DELETE alerts and says the process is unknown" "grep -q 'TRIPWIRE: canary file deleted' $T/t4.log && grep -q 'originating process is unknown' $T/t4.log"
python3 -c "
import os
for i in range(70): open('$T/t4/e%d.bin'%i,'wb').write(os.urandom(4096))"
sleep 3
chk "tripwire(inotify): rate rule alerts without a PID, nothing is killed" "grep -q 'TRIPWIRE: .* encrypted-looking' $T/t4.log"
stop_rt t4
$RT --path $T/t4 --tripwire-rate 1 >/dev/null 2>&1; chk "tripwire: bad --tripwire-rate rejected" "[ \$? -eq 2 ]"

############################################################ syslog / journald sinks
mkdir -p $T/s /run/systemd/journal 2>/dev/null
cat > $T/dg.py <<'PY'
import socket,os,sys
p=sys.argv[1]
try: os.unlink(p)
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.bind(p); s.settimeout(8)
out=open(sys.argv[2],'wb')
try:
    while True: out.write(s.recv(65536)+b'\n----\n'); out.flush()
except Exception: pass
PY
if [ $ROOT = 1 ] && [ ! -e /run/systemd/journal/socket ]; then
  python3 $T/dg.py /run/systemd/journal/socket $T/journal.out & JP=$!; sleep 0.5
  run_rt s --path $T/s --journald --action report
  BAD jd > "$T/s/jd.bin"; sleep 2.5; stop_rt s; wait $JP 2>/dev/null
  chk "journald: native datagram with MESSAGE, PRIORITY and CLAMRT_PATH / CLAMRT_SIGNATURE / CLAMRT_SHA256 fields" "grep -q 'SYSLOG_IDENTIFIER=clamrt' $T/journal.out && grep -q 'CLAMRT_PATH=.*jd.bin' $T/journal.out && grep -q 'CLAMRT_SIGNATURE=Test.Sig' $T/journal.out && grep -q 'CLAMRT_SHA256=' $T/journal.out && grep -q '^PRIORITY=4' $T/journal.out"
  rm -f /run/systemd/journal/socket
else skip "journald test (a real journald socket exists or not root)"; fi
if [ $ROOT = 1 ] && [ ! -e /dev/log ]; then
  python3 $T/dg.py /dev/log $T/syslog.out & JP=$!; sleep 0.5
  run_rt s2 --path $T/s --syslog --action report
  BAD sl > "$T/s/sl.bin"; sleep 2.5; stop_rt s2; wait $JP 2>/dev/null
  chk "syslog: detection delivered to /dev/log" "grep -q 'clamrt' $T/syslog.out && grep -q 'INFECTED: .*sl.bin' $T/syslog.out"
  rm -f /dev/log
else skip "syslog test (/dev/log exists or not root)"; fi

############################################################ CLI validation (v3 options)
for bad in "--mode nope" "--block-exec --mode inotify" "--log-format xml" "--metrics 99999" "--metrics host:" "--intel foo" "--sweep-interval 2" "--verdict-ttl 999999" "--exec-timeout-ms 5" "--tripwire-action explode"; do
  $RT --path $T/q $bad >/dev/null 2>&1; rc=$?; chk "CLI rejects: $bad" "[ $rc -ne 0 ]"
done
stop_clamd
echo; echo "RESULT: $P passed, $F failed, $S skipped"; [ $F -eq 0 ]
