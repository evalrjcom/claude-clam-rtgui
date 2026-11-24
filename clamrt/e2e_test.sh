#!/bin/bash
# clamrt v2 end-to-end test (Linux).
# usage: [T=workdir] [CLAMD=path/to/clamd] [CERTS=dir] e2e_test.sh <clamrt-binary>
# Needs a working clamd binary; uses a private 1-signature database (Test.Sig).
# Tests marked (v2) cover bugs found in the v1 audit.
set -u
RT=$1; T=${T:-/tmp/clamrt_e2e}; CLAMD=${CLAMD:-clamd}; CERTS=${CERTS:-}
pkill -f "clamd -c $T/clamd.conf" 2>/dev/null; pkill -x "$(basename $RT)" 2>/dev/null; sleep 0.5
rm -rf $T; mkdir -p $T/db $T/watch $T/outside $T/q; chmod 700 $T/q
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
stop_clamd() { pkill -f "clamd -c $T/clamd.conf"; }
P=0; F=0; chk() { if eval "$2"; then echo "PASS: $1"; P=$((P+1)); else echo "FAIL: $1"; F=$((F+1)); fi; }
start_clamd
($RT --path $T/watch --path $T/watch --clamd-socket $T/clamd.sock --action quarantine --quarantine-dir $T/q \
    --exclude /skipme/ --debounce-ms 200 --verbose --log $T/rt.log & echo $! > $T/rt.pid)
sleep 1

echo hello > $T/watch/clean.txt
BAD a > $T/watch/evil1.bin
mkdir -p $T/watch/new/sub; BAD b > $T/watch/new/sub/evil2.bin
BAD c > $T/outside/evil3.bin; mv $T/outside/evil3.bin $T/watch/moved_in.bin
ln -s $T/outside/target $T/watch/link; BAD d > $T/outside/target; touch $T/watch/link
mkdir -p $T/watch/skipme; BAD e > $T/watch/skipme/evil4.bin
BAD f > "$T/watch/we ird
name.bin"
(for i in 1 2 3 4 5; do echo "chunk $i"; sleep 0.1; done) > $T/watch/slow_clean.txt
: > $T/watch/empty.txt                                               # (v2) empty file must not error
BAD h > $T/outside/evilh; ln $T/outside/evilh $T/watch/hardlinked.bin # (v2) hard link: no close_write event
sleep 3

chk "clean file left alone"          "[ -f $T/watch/clean.txt ]"
chk "evil1 quarantined"              "[ ! -e $T/watch/evil1.bin ] && ls $T/q | grep -q evil1.bin"
chk "evil in NEW nested dir caught"  "[ ! -e $T/watch/new/sub/evil2.bin ] && ls $T/q | grep -q evil2.bin"
chk "evil MOVED IN caught"           "[ ! -e $T/watch/moved_in.bin ] && ls $T/q | grep -q moved_in.bin"
chk "symlink not followed"           "[ -L $T/watch/link ] && [ -f $T/outside/target ]"
chk "excluded dir not scanned"       "[ -f $T/watch/skipme/evil4.bin ]"
chk "newline-name caught + log not injectable" "ls $T/q | grep -q 'we_ird_name.bin' && ! grep -q '^name.bin' $T/rt.log"
chk "quarantine sidecar written"     "grep -q 'signature=Test.Sig' $T/q/*evil1.bin.info"
chk "quarantined file mode 000"      "[ \$(stat -c %a \$(ls $T/q/*evil1.bin)) = 0 ]"
chk "slow file scanned once settled" "grep -q 'clean: .*slow_clean.txt' $T/rt.log"
chk "quarantine dir not rescanned"   "! grep -q 'event: $T/q' $T/rt.log"
chk "(v2) empty file scanned clean"  "grep -q 'clean: .*empty.txt' $T/rt.log"
chk "(v2) HARD-LINKED infected file caught" "[ ! -e $T/watch/hardlinked.bin ] && ls $T/q | grep -q hardlinked.bin"
chk "(v2) duplicate --path watched once"   "[ \$(grep -c 'event: .*evil1.bin' $T/rt.log) -le 3 ] && grep -q 'starting; action=quarantine, 1 root' $T/rt.log"

# (v2) same infected name twice within one second: v1 left the second file in place
BAD c1 > $T/watch/dup.bin; sleep 0.6; BAD c2 > $T/watch/dup.bin; sleep 1.5
chk "(v2) same-name re-detection quarantined (no name collision)" "[ ! -e $T/watch/dup.bin ] && [ \$(ls $T/q | grep -c 'dup.bin$') -eq 2 ]"

# (v2) SIGHUP: logrotate moves the log, process must reopen it
mv $T/rt.log $T/rt.log.1; kill -HUP $(cat $T/rt.pid); sleep 0.3; echo hi > $T/watch/after_hup.txt; sleep 1.2
chk "(v2) SIGHUP reopens log (process survives, new log written)" "kill -0 $(cat $T/rt.pid) && grep -q 'after_hup' $T/rt.log"
chk "(v2) log file is not world-readable" "[ \$(stat -c %a $T/rt.log) = 640 ]"

# clamd outage: infected file written while clamd is down must be caught after it returns
stop_clamd; sleep 1; rm -f $T/clamd.sock
BAD g > $T/watch/during_outage.bin
sleep 2.5
chk "outage: file still present while clamd down" "[ -f $T/watch/during_outage.bin ]"
start_clamd
sleep 8
chk "outage: caught after clamd restart (retry/backoff)" "[ ! -e $T/watch/during_outage.bin ] && ls $T/q | grep -q during_outage"

# (v2) inotify queue overflow: v1 reported 8 of 100.  The queue limit is read when an inotify instance is
# created, so lower it BEFORE starting a dedicated instance, freeze that instance, flood, thaw.
if echo 16 > /proc/sys/fs/inotify/max_queued_events 2>/dev/null; then
  mkdir -p $T/ovf
  ($RT --path $T/ovf --clamd-socket $T/clamd.sock --action quarantine --quarantine-dir $T/q --debounce-ms 200 --log $T/rt_ovf.log & echo $! > $T/ovf.pid)
  sleep 1
  mkdir -p $T/ovf/flood; sleep 0.8   # flood/ must already be watched, otherwise it is simply walked on thaw
  kill -STOP $(cat $T/ovf.pid); for i in $(seq 1 100); do BAD "f$i" > $T/ovf/flood/f$i.bin; done
  mkdir -p $T/ovf/late_dir; BAD late > $T/ovf/late_dir/late.bin; sleep 0.5
  kill -CONT $(cat $T/ovf.pid); sleep 7
  echo 16384 > /proc/sys/fs/inotify/max_queued_events
  chk "(v2) overflow: warning logged + counted" "grep -q 'dropped change events' $T/rt_ovf.log"
  chk "(v2) overflow: all 100 flooded files caught by the rescan" "[ \$(ls $T/q | grep -c '_f[0-9]*\.bin\$') -ge 100 ]"
  chk "(v2) overflow: file in dir created during overflow caught" "ls $T/q | grep -q late.bin"
  BAD after > $T/ovf/late_dir/after_overflow.bin; sleep 1.5
  chk "(v2) overflow: that dir is watched afterwards" "[ ! -e $T/ovf/late_dir/after_overflow.bin ]"
  kill -TERM $(cat $T/ovf.pid); sleep 1.2
else echo "SKIP: overflow tests (cannot write /proc/sys/fs/inotify/max_queued_events)"; fi

kill -TERM $(cat $T/rt.pid); sleep 1.5
chk "graceful stop with summary"     "grep -q 'stopping: scanned=' $T/rt.log"

# (v2) CLI / startup hardening
chmod 777 $T/q
$RT --path $T/watch --action quarantine --quarantine-dir $T/q --log $T/rt3.log >/dev/null 2>&1; rc=$?
chk "(v2) world-writable quarantine dir refused at start-up" "[ $rc -ne 0 ]"
chmod 700 $T/q
$RT --path $T/watch --exclude '' >/dev/null 2>&1; chk "(v2) empty --exclude rejected" "[ $? -eq 2 ]"
$RT --path /nonexistent_dir_xyz >/dev/null 2>&1; chk "bad --path rejected" "[ $? -eq 2 ]"
$RT --help >$T/help.out 2>/dev/null; chk "(v2) --help on stdout, exit 0" "[ $? -eq 0 ] && grep -q Usage $T/help.out"
mkdir -p $T/empty_root; ln -sfn /etc/passwd $T/logsym; $RT --path $T/empty_root --log $T/logsym >/dev/null 2>&1; chk "(v2) log path symlink not followed" "[ $? -ne 0 ] && ! grep -q clamrt /etc/passwd"
stop_clamd
echo; grep -E "INFECTED|WARN|ERROR|stopping" $T/rt.log | sed 's/^[0-9-]* [0-9:]* //' | head -12
echo; echo "RESULT: $P passed, $F failed"; [ $F -eq 0 ]
