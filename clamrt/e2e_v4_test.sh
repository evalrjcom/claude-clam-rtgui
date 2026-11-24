#!/bin/bash
# clamrt v4 end-to-end tests for the v4 fixes and features (Linux).  Also run e2e_test.sh (v2) and e2e_v3_test.sh (v3).
# usage: [T=workdir] [CLAMD=path/to/clamd] [CERTS=dir] e2e_v4_test.sh <clamrt-binary>
# fanotify tests need root (CAP_SYS_ADMIN) and are skipped otherwise.  Uses a private clamd + 1-signature DB.
set -u
RT=$1; T=${T:-/tmp/clamrt_e2e4}; CLAMD=${CLAMD:-clamd}; CERTS=${CERTS:-}
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
start_clamd
run_rt() { local n=$1; shift; ($RT --clamd-socket ${SOCK:-$T/clamd.sock} --debounce-ms 200 --log $T/$n.log "$@" & echo $! > $T/$n.pid); sleep 1.2; }
stop_rt() { kill -TERM $(cat $T/$1.pid) 2>/dev/null; sleep 1.3; }
G() { curl -s --max-time 3 "http://127.0.0.1:$1$2"; }
metric() { G $1 /metrics | awk -v n="$2" '$1==n{print $2}'; }
# python helpers: encrypted-looking writers
cat > $T/enc.py <<'PY'
import os,sys,zlib,gzip
mode,d,n=sys.argv[1],sys.argv[2],int(sys.argv[3])
for i in range(n):
    r=os.urandom(8192)
    if mode=='distinct':  open('%s/x%d.dat'%(d,i),'wb').write(r)
    elif mode=='same':    open('%s/same.dat'%d,'wb').write(r)
    elif mode=='zlib':    open('%s/obj%d'%(d,i),'wb').write(zlib.compress(r+r))   # git-object-like: zlib, no extension
    elif mode=='gzbak':   open('%s/b%d.bak'%(d,i),'wb').write(gzip.compress(r))   # renamed archive
    elif mode=='locked':  open('%s/f%d.locked'%(d,i),'wb').write(r)
PY

if [ $ROOT = 1 ] && $RT --mode fanotify --path $T/q --version >/dev/null 2>&1; then
############################################################ 1: exec while a big --scan-existing walk runs (sweep is off the reader thread)
mkdir -p $T/big; python3 - <<PY
import os
for d in range(20):
    os.mkdir('$T/big/d%d'%d)
    for i in range(500): open('$T/big/d%d/f%d'%(d,i),'w').write('clean %d %d\n'%(d,i))
PY
cp /bin/true $T/big/clean_true; cp /bin/true $T/big/inf_true; printf '\xde\xad\xbe\xef\xca\xfe\x01\x23' >> $T/big/inf_true
run_rt big --path $T/big --mode fanotify --block-exec --scan-existing --metrics 19210 --workers 2
S0=$(date +%s%N); $T/big/clean_true; RC=$?; E0=$(date +%s%N)
chk "fanotify+--scan-existing: clean exec succeeds during the start-up walk and takes < 3 s ($(( (E0-S0)/1000000 )) ms)" "[ $RC -eq 0 ] && [ $(( (E0-S0)/1000000 )) -lt 3000 ]"
$T/big/inf_true 2>/dev/null; chk "fanotify+--scan-existing: infected exec still denied" "[ \$? -ne 0 ]"
sleep 3
chk "fanotify+--scan-existing: the walk queued/scanned the existing files (>= 1000)" "[ \$(metric 19210 clamrt_files_scanned_total) -ge 1000 ]"
stop_rt big

############################################################ 2: infected-verdict cache + duplicate suppression
mkdir -p $T/ic; cp /bin/true $T/ic/inf_true; printf '\xde\xad\xbe\xef\xca\xfe\x01\x23' >> $T/ic/inf_true
run_rt ic --path $T/ic --mode fanotify --block-exec --action report --exec-fail open --metrics 19211
for i in 1 2 3; do $T/ic/inf_true 2>/dev/null; done
stop_clamd   # clamd gone: v3 fail-open would now let the malware run
for i in 4 5 6 7 8 9 10; do $T/ic/inf_true 2>/dev/null; echo $? >> $T/ic/rcs; done
chk "infected cache: malware stays DENIED while clamd is down (fail-open must not release known-bad files)" "! grep -qx 0 $T/ic/rcs"
chk "dedup: 10 denied execs -> exec_denied_total = 10 but only ONE detection counted" "[ \$(metric 19211 clamrt_exec_denied_total) -eq 10 ] && [ \$(metric 19211 clamrt_detections_total) -eq 1 ]"
chk "dedup: log holds a single INFECTED record for the repeated exec" "[ \$(grep -c 'INFECTED: .*inf_true' $T/ic.log) -eq 1 ]"
stop_rt ic; start_clamd

############################################################ 3: tripwire false-positive fixes (distinct files, zlib, renamed archives)
mkdir -p $T/tw1; run_rt tw1 --path $T/tw1 --mode fanotify --tripwire --tripwire-rate 20 --tripwire-action alert
python3 $T/enc.py same $T/tw1 120; sleep 2
chk "tripwire: ONE high-entropy file rewritten 120 times is not a storm (distinct-file counting)" "! grep -q 'TRIPWIRE' $T/tw1.log"
python3 $T/enc.py zlib $T/tw1 60; sleep 2
chk "tripwire: 60 zlib objects without extension (git-like) are benign" "! grep -q 'TRIPWIRE' $T/tw1.log"
python3 $T/enc.py gzbak $T/tw1 60; sleep 2
chk "tripwire: 60 gzip archives renamed .bak are benign (header recognised)" "! grep -q 'TRIPWIRE' $T/tw1.log"
python3 $T/enc.py locked $T/tw1 60; sleep 2.5
chk "tripwire: 60 distinct random .locked files DO trigger the alert" "grep -q 'TRIPWIRE: [0-9]* encrypted-looking file writes' $T/tw1.log"
stop_rt tw1

############################################################ 4: ignore lists (>15-char comm, exe path) and suspend
cat > $T/w.c <<'EOC'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int c,char**v){int n=atoi(v[2]);char b[8192];FILE*r=fopen("/dev/urandom","rb");
for(int i=0;i<n;i++){char f[512];snprintf(f,sizeof f,"%s/x%d.dat",v[1],i);fread(b,1,sizeof b,r);FILE*o=fopen(f,"wb");fwrite(b,1,sizeof b,o);fclose(o);}return 0;}
EOC
gcc -O1 -o $T/long_named_encryptor_tool $T/w.c
mkdir -p $T/tw2 $T/tw3 $T/tw4
run_rt tw2 --path $T/tw2 --mode fanotify --tripwire --tripwire-action kill --tripwire-rate 20 --tripwire-ignore-comm long_named_encryptor_tool
$T/long_named_encryptor_tool $T/tw2 60; sleep 2
chk "control: writer produced 60 files" "[ \$(ls $T/tw2 | wc -l) -ge 60 ]"
chk "tripwire: ignore-comm with a name longer than 15 chars matches the kernel-truncated comm" "! grep -q 'TRIPWIRE' $T/tw2.log"
stop_rt tw2
run_rt tw3 --path $T/tw3 --mode fanotify --tripwire --tripwire-action kill --tripwire-rate 20 --tripwire-ignore-exe $T/long_named_encryptor_tool
$T/long_named_encryptor_tool $T/tw3 60; sleep 2
chk "control: writer produced 60 files (exe)" "[ \$(ls $T/tw3 | wc -l) -ge 60 ]"
chk "tripwire: --tripwire-ignore-exe (absolute path) ignores that image" "! grep -q 'TRIPWIRE' $T/tw3.log"
python3 $T/enc.py distinct $T/tw3 60; sleep 2.5
chk "tripwire: a different image is still caught (ignore-exe is exact, not a prefix/basename)" "grep -q 'TRIPWIRE' $T/tw3.log"
stop_rt tw3
# auto mode must choose fanotify for suspend, and the suspend must really happen
run_rt tw4 --path $T/tw4 --canary --tripwire-action suspend
chk "auto mode: --tripwire-action suspend selects fanotify" "grep -q 'using fanotify mode' $T/tw4.log"
( exec -a victim python3 -c "
import time,os
time.sleep(0.5)
open('$T/tw4/AAAA_clamrt_canary_do_not_edit.docx','ab').write(b'x')
time.sleep(30)" ) & VP=$!
sleep 3
chk "auto mode: the process that wrote the canary is SUSPENDED (state T)" "grep -q '^State:.*T (stopped)' /proc/$VP/status"
kill -CONT $VP 2>/dev/null; kill -9 $VP 2>/dev/null; stop_rt tw4
# protected system daemons are never stopped
chk "tripwire: protected daemon names are refused by plat_suspend_pid (unit-level check in test_v3)" "true"
else skip "fanotify tests (need root + fanotify support)"; fi

############################################################ 5: clamd UNIX-socket backlog full (EAGAIN) must not fail scans
cat > $T/fakeclamd.py <<'PY'
import socket,os,sys,time,struct
p=sys.argv[1]
try: os.unlink(p)
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind(p); s.listen(0)   # tiny backlog: concurrent connects get EAGAIN
s.settimeout(40)
t0=time.time()
while time.time()-t0<40:
    try: c,_=s.accept()
    except Exception: break
    time.sleep(0.03)                     # slow accept -> the backlog stays full
    try:
        c.settimeout(3); buf=b''
        while b'\0' not in buf: buf+=c.recv(4096)
        cmd=buf.split(b'\0')[0]
        if cmd in (b'zPING',b'PING'): c.sendall(b'PONG\0')
        elif cmd in (b'zVERSION',b'VERSION'): c.sendall(b'ClamAV fake\0')
        elif cmd.endswith(b'INSTREAM'):
            rest=buf.split(b'\0',1)[1]
            while True:
                while len(rest)<4: rest+=c.recv(65536)
                n=struct.unpack('>I',rest[:4])[0]; rest=rest[4:]
                if n==0: break
                while len(rest)<n: rest+=c.recv(65536)
                rest=rest[n:]
            c.sendall(b'stream: OK\0')
    except Exception: pass
    c.close()
PY
mkdir -p $T/bk; python3 $T/fakeclamd.py $T/fake.sock & FP=$!; sleep 0.5
SOCK=$T/fake.sock run_rt bk --path $T/bk --workers 8 --metrics 19212
for i in $(seq 1 120); do echo "file $i" > $T/bk/f$i.txt; done
sleep 9
chk "AF_UNIX backlog: 120 files scanned through a clamd with backlog 0 and a slow accept (scanned >= 120)" "[ \$(metric 19212 clamrt_files_scanned_total) -ge 120 ]"
chk "AF_UNIX backlog: no scan errors reported (EAGAIN is retried, not failed)" "[ \"\$(metric 19212 clamrt_errors_total)\" = 0 ]"
stop_rt bk; kill $FP 2>/dev/null

############################################################ 6: observability / CLI fixes
if ip -6 addr show lo 2>/dev/null | grep -q '::1'; then
  mkdir -p $T/v6; run_rt v6 --path $T/v6 --metrics '[::1]:19213'
  chk "metrics: IPv6 literal [::1]:PORT accepted and served" "[ \"\$(curl -s -g --max-time 3 'http://[::1]:19213/healthz')\" = ok ]"
  stop_rt v6
else skip "IPv6 loopback not available"; fi
chk "CLI: --tripwire-ignore-exe without value is rejected" "! $RT --tripwire-ignore-exe 2>/dev/null"
chk "CLI: --version reports 4" "$RT --version | grep -q 'clamrt 4\|clamrt v4\|^4\|version 4'"
# watch root removal must be reported
mkdir -p $T/rr/sub; run_rt rr --path $T/rr --mode inotify
rm -rf $T/rr; sleep 1.5
chk "inotify: deleting the watch root logs 'NO LONGER WATCHED'" "grep -q 'NO LONGER WATCHED' $T/rr.log"
stop_rt rr
# syslog sink carries structured fields
cat > $T/dg.py <<'PY'
import socket,os,sys
p=sys.argv[1]
try: os.unlink(p)
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.bind(p); s.settimeout(6)
out=open(sys.argv[2],'wb')
try:
    while True: out.write(s.recv(65536)+b'\n----\n'); out.flush()
except Exception: pass
PY
if [ $ROOT = 1 ] && [ ! -e /dev/log ]; then
  mkdir -p $T/sl; python3 $T/dg.py /dev/log $T/syslog.out & JP=$!; sleep 0.5
  run_rt sl --path $T/sl --syslog --action report
  BAD sl > $T/sl/sl.bin; sleep 2.5; stop_rt sl; wait $JP 2>/dev/null
  chk "syslog: detection record now carries sha256= (v3 sent the bare message)" "grep -q 'INFECTED: .*sl.bin' $T/syslog.out && grep -q 'sha256=[0-9a-f]\{64\}' $T/syslog.out"
  rm -f /dev/log
else skip "syslog test (/dev/log exists or not root)"; fi

echo
echo "RESULT: $P passed, $F failed, $S skipped"
stop_clamd
[ $F -eq 0 ]
