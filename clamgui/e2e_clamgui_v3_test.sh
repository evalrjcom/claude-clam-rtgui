#!/bin/bash
# ClamGUI v3 regression tests (headless CLI paths + GUI smoke under Xvfb).
# usage: CLAMSCAN=/path/clamscan FRESHCLAM=... CERTS=/path/certs [CLAMD=...] ./e2e_clamgui_v3_test.sh /path/to/clamgui_v3
# The GUI part needs Xvfb + xdotool and is skipped when they are missing.  crontab tests need `crontab`.
set -u
GUI=$1; PN=$(basename "$GUI" | cut -c1-15)   # the kernel truncates process names to 15 chars: pgrep/pkill -x must use the truncated name
T=${T:-/tmp/clamgui_e2e}; export CLAMGUI_HOME=$T/home
CLAMSCAN=${CLAMSCAN:-clamscan}; FRESHCLAM=${FRESHCLAM:-freshclam}; CLAMD=${CLAMD:-clamd}; CERTS=${CERTS:-}; CLAMDSCAN=${CLAMDSCAN:-clamdscan}
pkill -x "$PN" 2>/dev/null; rm -rf $T; mkdir -p $T/home/config $T/home/data/db $T/in
printf 'Test.Sig:0:*:deadbeefcafe0123\n' > $T/home/data/db/t.ndb
setcfg() { grep -v "^$1=" $T/home/config/clamgui.conf > $T/c.tmp 2>/dev/null; echo "$1=$2" >> $T/c.tmp; mv $T/c.tmp $T/home/config/clamgui.conf; }
: > $T/home/config/clamgui.conf
setcfg clamscan "$(command -v $CLAMSCAN)"; setcfg freshclam "$(command -v $FRESHCLAM)"; setcfg clamd "$(command -v $CLAMD 2>/dev/null)"; setcfg clamdscan "$(command -v $CLAMDSCAN 2>/dev/null)"; [ -n "$CERTS" ] && setcfg certs_dir "$CERTS"
BAD() { printf '\xde\xad\xbe\xef\xca\xfe\x01\x23 payload %s' "$1"; }
P=0; F=0; S=0
chk() { if eval "$2"; then echo "PASS: $1"; P=$((P+1)); else echo "FAIL: $1"; F=$((F+1)); fi; }
skip() { echo "SKIP: $1"; S=$((S+1)); }
NEWEST() { ls -t $T/home/data/reports/scan-*.log | head -1; }

$GUI --version | grep -q 'ClamGUI v3' ; chk "version string carries v3" "[ $? -eq 0 ]"
$GUI --help | grep -q 'v3' ; chk "usage text carries v3" "[ $? -eq 0 ]"
echo clean > $T/in/ok.txt
$GUI --scan $T/in/ok.txt >$T/o1.txt 2>&1; chk "clean file -> exit 0" "[ $? -eq 0 ]"
chk "clean scan report is named -clean.log" "NEWEST | grep -q -- '-clean.log'"
BAD a > $T/in/evil.bin; mkdir "$T/in/sub dir"; BAD b > "$T/in/sub dir/we: ird  name.bin"; BAD c > "$T/in/-dash.bin"
$GUI --scan $T/in >$T/o2.txt 2>&1; RC=$?
chk "infected tree -> exit 1" "[ $RC -eq 1 ]"
chk "FOUND line shows threat and path" "grep -q 'FOUND: $T/in/evil.bin: Test.Sig' $T/o2.txt"
chk "path containing ': ' parsed correctly" "grep -q 'FOUND: $T/in/sub dir/we: ird  name.bin: Test.Sig' $T/o2.txt"
chk "infected report is named -infected.log and lists the threat" "NEWEST | grep -q -- '-infected.log' && grep -q 'evil.bin' \$(NEWEST)"
(cd $T/in && $GUI --scan -- -dash.bin >$T/o3.txt 2>&1); chk "path starting with '-' is scanned as a path (not an option)" "grep -q 'FOUND: ./-dash.bin' $T/o3.txt"
$GUI --scan -x >$T/o4.txt 2>&1; chk "unknown option rejected with exit 2" "[ $? -eq 2 ]"
ln -s $T/in/evil.bin $T/lnk_dir_target 2>/dev/null; mkdir -p $T/lk; ln -s $T/in/evil.bin $T/lk/link.bin; $GUI --scan $T/lk >$T/o5.txt 2>&1
chk "symlinks are not followed (no detection through a link)" "! grep -q FOUND $T/o5.txt"
# invalid UTF-8 file names must not break output
mkdir $T/u8; BAD u | cat > "$T/u8/$(printf 'bad\xff\xfe\x01name.bin')"; $GUI --scan $T/u8 >$T/o6.txt 2>&1
chk "invalid UTF-8 / control bytes in names are sanitised in output" "grep -q 'FOUND:' $T/o6.txt && iconv -f UTF-8 -t UTF-8 $T/o6.txt >/dev/null 2>&1"
# exclude regex
setcfg excludes 'evil\.bin'; $GUI --scan $T/in/evil.bin >$T/o7.txt 2>&1; chk "exclude pattern skips the file" "! grep -q FOUND $T/o7.txt"; setcfg excludes ''

# ---- quarantine action
setcfg action 1
mkdir $T/q; BAD q1 > $T/q/one.bin; BAD q2 > $T/q/two.bin
$GUI --scan $T/q >$T/o8.txt 2>&1
chk "quarantine action moves the files away" "[ ! -e $T/q/one.bin ] && [ ! -e $T/q/two.bin ]"
chk "scan output says quarantined" "grep -q '\[quarantined\]' $T/o8.txt"
chk "quarantine listing shows both items" "[ \$($GUI --quarantine-list | wc -l) -eq 2 ]"
QD=$T/home/data/quarantine
chk "quarantine dir is private (0700) and stored files read-only (0400)" "[ \$(stat -c %a $QD) = 700 ] && [ \$(stat -c %a \$(ls $QD/*.quar | head -1)) = 400 ]"
ID=$($GUI --quarantine-list | grep one.bin | cut -f1)
$GUI --restore $ID >/dev/null 2>&1; chk "restore puts the file back" "[ -e $T/q/one.bin ]"
BAD other > $T/q/one.bin.tmp; ID2=$($GUI --quarantine-list | grep two.bin | cut -f1); echo occupied > $T/q/two.bin; $GUI --restore $ID2 >/dev/null 2>&1
chk "restore never overwrites an existing file" "[ \"\$(cat $T/q/two.bin)\" = occupied ] && [ -e $T/q/two.bin.restored ]"
BAD d > $T/q/three.bin; $GUI --scan $T/q/three.bin >/dev/null 2>&1; ID3=$($GUI --quarantine-list | grep three.bin | cut -f1)
$GUI --delete $ID3 >/dev/null 2>&1; chk "delete removes item and its stored file" "! ls $QD/$ID3.quar >/dev/null 2>&1 && ! $GUI --quarantine-list | grep -q $ID3"
$GUI --delete '../../etc/passwd' >/dev/null 2>&1; chk "path-traversal id rejected (exit 2)" "[ $? -eq 2 ]"
$GUI --restore 0123456789abcdef >/dev/null 2>&1; chk "unknown id rejected (exit 2)" "[ $? -eq 2 ]"
# a symlink swapped in after detection must never be followed by the action
BAD v > $T/q/victim.bin; echo precious > $T/precious.txt
setcfg action 2
python3 - <<PY
import subprocess,os,sys
# simulate TOCTOU: the detected path is a symlink at action time -> must be refused
os.system("rm -f $T/q/victim.bin"); os.symlink("$T/precious.txt","$T/q/victim.bin")
PY
chk "a symlink in place of the infected file is neither scanned nor followed by the delete action (precious file survives)" "[ -e $T/precious.txt ] && $GUI --scan $T/q/victim.bin >/dev/null 2>&1; [ -e $T/precious.txt ]"

# ---- delete action
BAD e > $T/q/del.bin; $GUI --scan $T/q/del.bin >$T/o9.txt 2>&1; chk "delete action removes the infected file" "[ ! -e $T/q/del.bin ] && grep -q '\[deleted\]' $T/o9.txt"
setcfg action 0

# ---- error paths
cp $T/home/config/clamgui.conf $T/conf.bak; setcfg clamscan /nonexistent/clamscan
$GUI --scan $T/in/ok.txt >$T/o10.txt 2>&1; RC=$?; chk "missing clamscan -> clear message, exit 2" "[ $RC -eq 2 ] && grep -q 'clamscan was not found' $T/o10.txt"
cp $T/conf.bak $T/home/config/clamgui.conf
mkdir -p $T/emptydb; setcfg db_dir $T/emptydb; $GUI --scan $T/in/ok.txt >$T/o11.txt 2>&1; chk "empty database dir -> asks for an update, exit 2" "[ $? -eq 2 ] && grep -q 'no virus database' $T/o11.txt"
setcfg db_dir $T/home/data/db
setcfg max_file_mb 1; head -c 3000000 /dev/zero > $T/big.bin; $GUI --scan $T/big.bin >$T/o12.txt 2>&1; chk "max file size option reaches clamscan (big zero file scanned clean, exit 0)" "[ $? -eq 0 ]"; setcfg max_file_mb 100
$GUI --scan $T/does-not-exist >$T/o13.txt 2>&1; chk "nonexistent target -> exit 2" "[ $? -eq 2 ]"

# ---- throughput: many files, many lines of output
mkdir $T/many; python3 -c "
import os
for i in range(20000): open('$T/many/f%d'%i,'w').write('c%d'%i)
"
BAD m > $T/many/f777; $GUI --scan $T/many >$T/o14.txt 2>&1; RC=$?
chk "20000-file scan: every file counted, the one infection found" "[ $RC -eq 1 ] && grep -q 'Scanned 20000 files, 1 infected' $T/o14.txt"

# ---- update plumbing (network may be unavailable: only the plumbing is checked)
timeout 90 $GUI --scheduled-update >$T/o15.txt 2>&1; chk "freshclam config generated with the database dir and runs under the GUI" "grep -q \"DatabaseDirectory $T/home/data/db\" $T/home/config/freshclam.conf && grep -qi 'ClamAV update process started\|freshclam' $T/o15.txt"
chk "update report written" "ls $T/home/data/reports/update-*.log >/dev/null 2>&1"

# ---- scheduler (crontab)
if command -v crontab >/dev/null 2>&1; then
  crontab -l > $T/cron.orig 2>/dev/null; (echo "# foreign"; echo "7 7 * * * /bin/true") | crontab -
  setcfg sched_update_on 1; setcfg sched_update_time 03:15; setcfg sched_scan_on 1; setcfg sched_scan_time 02:30; setcfg sched_scan_days 1010101; setcfg sched_scan_path $T/in
  $GUI --install-schedule >/dev/null 2>&1; CT=$(crontab -l)
  chk "cron: update + scan lines installed with correct fields" "echo \"\$CT\" | grep -q '^15 3 \* \* \* .*--scheduled-update' && echo \"\$CT\" | grep -q '^30 2 \* \* 1,3,5,0 .*--scheduled-scan'"
  chk "cron: foreign entries preserved" "echo \"\$CT\" | grep -q '7 7 \* \* \* /bin/true'"
  $GUI --install-schedule >/dev/null 2>&1; chk "cron: re-applying does not duplicate the block" "[ \$(crontab -l | grep -c 'scheduled-scan') -eq 1 ]"
  setcfg sched_scan_time 25:99; $GUI --install-schedule >/dev/null 2>&1; chk "cron: invalid time rejected (exit 2) and existing block kept" "[ $? -eq 2 ] && crontab -l | grep -q scheduled-scan"
  setcfg sched_scan_time 02:30; $GUI --remove-schedule >/dev/null 2>&1; CT=$(crontab -l)
  chk "cron: removal deletes only the ClamGUI block" "! echo \"\$CT\" | grep -q clamgui && echo \"\$CT\" | grep -q '/bin/true'"
  $GUI --scheduled-scan >$T/o16.txt 2>&1; chk "--scheduled-scan scans the configured folder (exit 1: infected files present)" "[ $? -eq 1 ] && grep -q FOUND $T/o16.txt"
  if [ -s $T/cron.orig ]; then crontab $T/cron.orig; else crontab -r 2>/dev/null; fi
else skip "scheduler tests (no crontab)"; fi


# ======================================================================== v2 features
# ---- hashing / HMAC against reference tools
echo "hash me" > $T/h.txt; chk "sha256 matches sha256sum" "[ \"\$($GUI --sha256 $T/h.txt | cut -d' ' -f1)\" = \"\$(sha256sum $T/h.txt | cut -d' ' -f1)\" ]"
: > $T/empty.f; chk "sha256 of an empty file is correct" "[ \"\$($GUI --sha256 $T/empty.f | cut -d' ' -f1)\" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ]"
head -c 1000003 /dev/urandom > $T/big.f; chk "sha256 of a 1 MB file matches (multi-block, odd length)" "[ \"\$($GUI --sha256 $T/big.f | cut -d' ' -f1)\" = \"\$(sha256sum $T/big.f | cut -d' ' -f1)\" ]"
printf 'a=1\nb=2\n' > $T/pol.txt; PK=s3cret-key
SIG=$(CLAMGUI_POLICY_KEY=$PK $GUI --policy-sign $T/pol.txt | tail -1 | sed 's/^hmac=//')
chk "policy HMAC equals openssl HMAC-SHA256" "[ \"$SIG\" = \"\$(printf 'a=1\nb=2\n' | openssl dgst -sha256 -hmac $PK | sed 's/.*= //')\" ]"

# ---- vault v2: hash recorded, sandbox restore, signed export, tamper + integrity detection
setcfg action 1; mkdir $T/v2; BAD v1 > $T/v2/a.bin; BAD v2 > $T/v2/b.bin; ORIGSHA=$(sha256sum $T/v2/a.bin | cut -d' ' -f1)
$GUI --scan $T/v2 >/dev/null 2>&1
IDA=$($GUI --quarantine-list | grep a.bin | cut -f1); IDB=$($GUI --quarantine-list | grep b.bin | cut -f1)
chk "vault records the SHA-256 of each item" "$GUI --quarantine-list | grep a.bin | grep -q $ORIGSHA"
mkdir $T/sbx; $GUI --restore $IDA --to $T/sbx >$T/o20.txt 2>&1
chk "sandbox restore writes a read-only .infected copy" "[ -e $T/sbx/a.bin.infected ] && [ \$(stat -c %a $T/sbx/a.bin.infected) = 400 ] && [ \"\$(sha256sum $T/sbx/a.bin.infected | cut -d' ' -f1)\" = $ORIGSHA ]"
chk "sandbox restore keeps the item in the vault and the original path empty" "$GUI --quarantine-list | grep -q $IDA && [ ! -e $T/v2/a.bin ]"
EV=$T/evidence.json; $GUI --export-evidence $EV >$T/o21.txt 2>&1; chk "evidence export writes manifest + signature" "[ -s $EV ] && ls $EV.sig $EV.hmac >/dev/null 2>&1 | grep -q . || [ -s $EV.sig ] || [ -s $EV.hmac ]"
chk "evidence manifest lists both items with their hashes" "grep -q $ORIGSHA $EV && grep -q $IDB $EV"
$GUI --verify-export $EV >$T/o22.txt 2>&1; chk "verify accepts an untouched export" "[ $? -eq 0 ]"
cp $EV $T/ev_t.json; cp $EV.sig $T/ev_t.json.sig 2>/dev/null; cp $EV.pub.pem $T/ev_t.json.pub.pem 2>/dev/null; cp $EV.hmac $T/ev_t.json.hmac 2>/dev/null
sed -i "s/$ORIGSHA/0000000000000000000000000000000000000000000000000000000000000000/" $T/ev_t.json
$GUI --verify-export $T/ev_t.json >$T/o23.txt 2>&1; chk "verify rejects a tampered manifest (exit 2)" "[ $? -eq 2 ]"
# integrity: modify the stored copy; restore must refuse unless --force
chmod u+w $QD/$IDB.quar; echo tamper >> $QD/$IDB.quar; chmod 400 $QD/$IDB.quar
$GUI --restore $IDB >$T/o24.txt 2>&1; RC=$?; chk "restore refuses a vault item whose SHA-256 changed" "[ $RC -eq 2 ] && grep -qi integrity $T/o24.txt && [ ! -e $T/v2/b.bin ]"
$GUI --restore $IDB --force >/dev/null 2>&1; chk "restore --force overrides the integrity check" "[ -e $T/v2/b.bin ]"

# ---- local HTTP mock: hash-only lookup, report upload, loopback-only http
cat > $T/mock.py <<'PY'
import http.server, sys, json
LOG = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _rec(self, body=b""):
        with open(LOG, "a") as f: f.write(json.dumps({"m": self.command, "p": self.path, "h": {k.lower(): v for k, v in self.headers.items()}, "b": body.decode("latin1")}) + "\n")
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); b = self.rfile.read(n); self._rec(b)
        if self.path.startswith("/bazaar"): out = b'{"query_status":"ok","data":[{"signature":"Mock.Family","file_type":"exe","first_seen":"2026-01-01 00:00:00"}]}'
        else: out = b'{"ok":true}'
        self.send_response(200); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def do_GET(self):
        self._rec(); out = b'{"data":{"attributes":{"last_analysis_stats":{"malicious":7,"suspicious":1},"meaningful_name":"mock.exe"}}}'
        self.send_response(200); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
MP=18765; : > $T/mock.log; (python3 $T/mock.py $MP $T/mock.log & echo $! > $T/mock.pid); sleep 1
setcfg intel_provider 1; setcfg intel_url http://127.0.0.1:$MP/bazaar; export ABUSECH_AUTH_KEY=KEY-ABUSE-123
$GUI --lookup $ORIGSHA >$T/o25.txt 2>&1; chk "MalwareBazaar-style lookup parses the reply" "grep -q 'Mock.Family' $T/o25.txt"
chk "lookup sends only the hash (POST body) and the key in a header, not on argv" "grep -q 'query=get_info' $T/mock.log && grep -q $ORIGSHA $T/mock.log && grep -qi 'auth-key' $T/mock.log"
chk "API key never appears in any process argument list" "! grep -q KEY-ABUSE-123 $T/o25.txt"
setcfg intel_provider 2; setcfg intel_url http://127.0.0.1:$MP/vt; export VT_API_KEY=KEY-VT-456; setcfg intel_key_env VT_API_KEY
$GUI --lookup $ORIGSHA >$T/o26.txt 2>&1; chk "VirusTotal-style lookup parses detections" "grep -q '7 engine' $T/o26.txt"
$GUI --lookup 'not-a-hash' >$T/o27.txt 2>&1; chk "malformed hash rejected before any request (exit 2)" "[ $? -eq 2 ]"
setcfg intel_url http://example.com/x; $GUI --lookup $ORIGSHA >$T/o28.txt 2>&1; chk "plain http to a non-loopback host is refused" "[ $? -ne 0 ] && grep -qi 'https' $T/o28.txt"
setcfg intel_provider 0; setcfg intel_url ''
# report upload (fleet mode)
: > $T/mock.log; setcfg report_url http://127.0.0.1:$MP/report; export CLAMGUI_REPORT_TOKEN=TOKEN-789; setcfg report_paths 0; setcfg action 0
$GUI --scan $T/in/evil.bin >$T/o29.txt 2>&1; sleep 1
chk "scan report uploaded as JSON with Bearer token header" "grep -q '/report' $T/mock.log && grep -q 'bearer TOKEN-789\|Bearer TOKEN-789' $T/mock.log && grep -q 'Test.Sig' $T/mock.log"
chk "uploaded report omits full paths when report_paths=0" "! grep -q '$T/in' $T/mock.log"
setcfg report_paths 1; : > $T/mock.log; $GUI --scan $T/in/evil.bin >/dev/null 2>&1; sleep 1; chk "report_paths=1 includes the file path" "grep -q 'evil.bin' $T/mock.log"
setcfg report_url ''; kill $(cat $T/mock.pid) 2>/dev/null

# ---- fleet policy: HMAC-signed file overrides user settings and is not persisted over them
setcfg action 0; printf 'action=2\nmax_file_mb=7\nbogus_key=1\n' > $T/policy.txt
CLAMGUI_POLICY_KEY=$PK $GUI --policy-sign $T/policy.txt > $T/policy.signed
CLAMGUI_POLICY=$T/policy.signed CLAMGUI_POLICY_KEY=$PK $GUI --scan $T/in/ok.txt >$T/o30.txt 2>&1
chk "valid signed policy is accepted (no policy error)" "grep -q 'signature verified' $T/o30.txt"
BAD pol > $T/in/pol.bin; CLAMGUI_POLICY=$T/policy.signed CLAMGUI_POLICY_KEY=$PK $GUI --scan $T/in/pol.bin >$T/o31.txt 2>&1
chk "policy overrides action (delete) although the user setting is report-only" "[ ! -e $T/in/pol.bin ]"
chk "user setting on disk untouched by the policy" "grep -q '^action=0' $T/home/config/clamgui.conf"
BAD pol2 > $T/in/pol2.bin; sed 's/action=2/action=2 /;s/7/9/' $T/policy.signed > $T/policy.bad
CLAMGUI_POLICY=$T/policy.bad CLAMGUI_POLICY_KEY=$PK $GUI --scan $T/in/pol2.bin >$T/o32.txt 2>&1
chk "tampered policy rejected: not applied and an error is shown" "[ -e $T/in/pol2.bin ] && grep -qi 'policy' $T/o32.txt && ! grep -q 'signature verified' $T/o32.txt"
CLAMGUI_POLICY=$T/policy.signed CLAMGUI_POLICY_KEY=wrong-key $GUI --scan $T/in/pol2.bin >$T/o33.txt 2>&1; chk "policy signed with a different key rejected" "[ -e $T/in/pol2.bin ] && grep -qi 'policy' $T/o33.txt && ! grep -q 'signature verified' $T/o33.txt"
rm -f $T/in/pol2.bin

# ---- recent-file triage: riskiest first
mkdir -p $T/dl; echo readme > $T/dl/readme.txt; printf 'MZ\x90\x00 exe' > $T/dl/setup.exe; printf 'PK\x03\x04 zipdata' > $T/dl/photo.jpg.zip; printf '%%PDF-1.4 x' > $T/dl/doc.pdf; printf 'MZ' > $T/dl/invoice.pdf.exe
$GUI --scan-recent $T/dl --days 1 >$T/o34.txt 2>&1; RC=$?; chk "--scan-recent scans the recent files (exit 0)" "[ $RC -eq 0 ] && grep -q 'Scanned 5' $T/o34.txt"
FIRST=$(grep -m1 -oE 'invoice.pdf.exe|setup.exe|readme.txt|doc.pdf|photo.jpg.zip' $T/home/data/reports/scan-*.log | head -1)
chk "report header shows the reason 'recent files'" "grep -q 'recent' \$(NEWEST)"
touch -d '30 days ago' $T/dl/readme.txt; $GUI --scan-recent $T/dl --days 7 >$T/o35.txt 2>&1; chk "files older than --days are skipped" "grep -q 'Scanned 4' $T/o35.txt"

# ---- notifications (stub notify-send on PATH)
mkdir -p $T/bin; printf '#!/bin/sh\necho "$@" >> %s/notify.log\n' $T > $T/bin/notify-send; chmod +x $T/bin/notify-send; : > $T/notify.log
setcfg notify 1; setcfg sched_scan_path $T/in; PATH=$T/bin:$PATH $GUI --scheduled-scan >/dev/null 2>&1
chk "scheduled scan that finds threats raises a desktop notification" "grep -q 'threat' $T/notify.log"
: > $T/notify.log; setcfg notify 0; PATH=$T/bin:$PATH $GUI --scheduled-scan >/dev/null 2>&1; chk "notifications can be disabled" "[ ! -s $T/notify.log ]"; setcfg notify 1
: > $T/notify.log; PATH=$T/bin:$PATH $GUI --scan $T/in/ok.txt >/dev/null 2>&1; chk "clean scan raises no notification" "[ ! -s $T/notify.log ]"

# ---- exclude presets are plain regexes the engine honours
setcfg excludes '[/\\](\.cache|Cache|Code Cache|GPUCache|Cache2)[/\\]'; mkdir -p $T/ex/.cache; BAD e > $T/ex/.cache/x.bin; BAD e > $T/ex/y.bin
$GUI --scan $T/ex >$T/o36.txt 2>&1; chk "browser-cache preset skips .cache but still finds other files" "! grep -q 'FOUND: $T/ex/.cache/x.bin' $T/o36.txt && grep -q 'FOUND: $T/ex/y.bin' $T/o36.txt"
setcfg excludes '\.(vdi|vmdk|qcow2|vhdx?|ova|vbox-prev)$'; mkdir -p $T/ex2; BAD v > $T/ex2/disk.vmdk; BAD v > $T/ex2/dos.bin; $GUI --scan $T/ex2 >$T/o37.txt 2>&1
chk "VM-image preset skips .vmdk" "! grep -q 'FOUND: $T/ex2/disk.vmdk' $T/o37.txt && grep -q 'FOUND: $T/ex2/dos.bin' $T/o37.txt"
setcfg excludes ''

# ---- engine setting falls back to clamscan when no daemon is ready
setcfg engine 1; $GUI --scan $T/in/evil.bin >$T/o38.txt 2>&1; chk "engine=clamd without a ready daemon falls back to clamscan" "[ $? -eq 1 ] && grep -q 'FOUND' $T/o38.txt"; setcfg engine 0

# ---- Linux file-manager integration (idempotent, foreign Thunar actions preserved)
FH=$T/fmhome; mkdir -p $FH/.config/Thunar; printf '<?xml version="1.0" encoding="UTF-8"?>\n<actions>\n<action><icon>x</icon><name>Mine</name><command>true</command></action>\n</actions>\n' > $FH/.config/Thunar/uca.xml
HOME=$FH XDG_DATA_HOME=$FH/.local/share XDG_CONFIG_HOME=$FH/.config $GUI --install-filemanager >$T/o39.txt 2>&1; RC=$?
chk "file-manager entries installed (exit 0)" "[ $RC -eq 0 ]"
chk "Nautilus script, Dolphin service menu, launcher created" "[ -x $FH/.local/share/nautilus/scripts/Scan\ with\ ClamGUI ] && ls $FH/.local/share/kio/servicemenus/*.desktop >/dev/null 2>&1 && ls $FH/.local/share/applications/*lam*.desktop >/dev/null 2>&1"
chk "Thunar action added and the user's own action preserved" "grep -q clamgui-scan-1 $FH/.config/Thunar/uca.xml && grep -q '<name>Mine</name>' $FH/.config/Thunar/uca.xml && xmllint --noout $FH/.config/Thunar/uca.xml 2>/dev/null || python3 -c \"import xml.dom.minidom as m;m.parse('$FH/.config/Thunar/uca.xml')\""
HOME=$FH XDG_DATA_HOME=$FH/.local/share XDG_CONFIG_HOME=$FH/.config $GUI --install-filemanager >/dev/null 2>&1; chk "installing twice does not duplicate the Thunar action" "[ \$(grep -c clamgui-scan-1 $FH/.config/Thunar/uca.xml) -eq 1 ]"
HOME=$FH XDG_DATA_HOME=$FH/.local/share XDG_CONFIG_HOME=$FH/.config $GUI --remove-filemanager >/dev/null 2>&1
chk "removal deletes only ClamGUI entries" "! grep -q clamgui-scan-1 $FH/.config/Thunar/uca.xml && grep -q '<name>Mine</name>' $FH/.config/Thunar/uca.xml && [ ! -e $FH/.local/share/nautilus/scripts/Scan\ with\ ClamGUI ]"
$GUI --print-systemd-unit | grep -q 'ExecStart=.*--service' ; chk "systemd unit generated with hardening options" "[ $? -eq 0 ] && $GUI --print-systemd-unit | grep -q NoNewPrivileges=yes"

# ---- supervisor (--service): real clamd, orderly SIGTERM
if [ -x "$(command -v $CLAMD)" ]; then
  setcfg rt_paths $T/in; setcfg clamrt /tmp/clamrt_v4; ( $GUI --service >$T/svc.out 2>&1 & echo $! > $T/svc.pid ); for i in $(seq 1 60); do grep -q 'clamd is ready\|ready' $T/svc.out 2>/dev/null && break; sleep 1; done
  chk "supervisor starts clamd and reports it ready" "grep -qi 'clamd started' $T/svc.out && grep -qi 'ready' $T/svc.out"
  chk "clamd socket exists while the supervisor runs" "ls $T/home/data/clamd.sock >/dev/null 2>&1 || ls $T/home/data/*.sock >/dev/null 2>&1 || pgrep -f 'clamd.*--config-file' >/dev/null"
  kill -TERM $(cat $T/svc.pid); for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 $(cat $T/svc.pid) 2>/dev/null || break; sleep 1; done
  chk "SIGTERM stops the supervisor and no clamd is left behind" "! kill -0 $(cat $T/svc.pid) 2>/dev/null && ! pgrep -f 'clamd.*--config-file=$T/home' >/dev/null"
  chk "service.log written" "[ -s $T/home/data/service.log ]"
else skip "supervisor test (no clamd)"; fi

# ---- watchers + clamd engine inside the GUI (Xvfb)
if command -v Xvfb >/dev/null && command -v xdotool >/dev/null; then
  export DISPLAY=:79; pkill -f "Xvfb :79" 2>/dev/null; (Xvfb :79 -screen 0 1000x720x24 >/dev/null 2>&1 &); sleep 1
  setcfg action 0; setcfg dl_watch 1; setcfg dl_dir $T/dlw; setcfg usb_autoscan 1; setcfg engine 1; setcfg notify 1; mkdir -p $T/dlw $T/usb; BAD pre > $T/dlw/preexisting.bin
  printf 'x /dev/sdz1 ext4 rw 0 0\n' > $T/mounts; rm -f $T/home/data/reports/*; : > $T/notify.log
  (PATH=$T/bin:$PATH CLAMGUI_MOUNTS=$T/mounts $GUI >$T/gw.out 2>&1 &); sleep 2
  for i in $(seq 1 40); do ls $T/home/data/clamd.sock >/dev/null 2>&1 && break; sleep 1; done; sleep 3
  BAD dl > $T/dlw/fresh.bin; sleep 12
  chk "downloads watcher scans a newly finished file" "grep -l 'fresh.bin' $T/home/data/reports/scan-*-infected.log >/dev/null 2>&1"
  chk "files already present at start are not scanned" "! grep -l 'preexisting.bin' $T/home/data/reports/*.log >/dev/null 2>&1"
  chk "download scan used the clamd engine once it was ready" "grep -q 'Engine: clamd (fast)' \$(ls -t $T/home/data/reports/scan-*-infected.log | head -1)"
  BAD usbf > $T/usb/stick.bin; printf 'x /dev/sdz1 ext4 rw 0 0\nx2 %s/usb vfat rw 0 0\n' $T > $T/mounts; sleep 10
  chk "inserted drive is scanned automatically" "grep -l 'stick.bin' $T/home/data/reports/scan-*-infected.log >/dev/null 2>&1"
  chk "GUI process stayed alive through the watcher scans" "pgrep -x $PN >/dev/null"
  pkill -TERM -x "$PN"; sleep 2; chk "GUI exit stops the managed clamd" "! pgrep -f 'clamd.*--config-file=$T/home' >/dev/null"
  # tray: needs a tray host
  if command -v stalonetray >/dev/null; then
    (stalonetray --geometry 4x1+0+0 --icon-size 24 -bg '#222222' >/dev/null 2>&1 &); sleep 1
    setcfg dl_watch 0; setcfg usb_autoscan 0; setcfg engine 0
    ($GUI >$T/gtray.out 2>&1 &); sleep 3
    import -window root $T/tray.png 2>/dev/null; chk "tray: status icon docked and drawn (grey = protection off)" "convert $T/tray.png -crop 1x1+11+11 txt:- | tail -1 | grep -q '(140,140,140)'"
    WID=$(xdotool search --onlyvisible --name 'ClamGUI' 2>/dev/null | head -1); xdotool windowfocus ${WID:-0} 2>/dev/null
    xdotool key --window ${WID:-0} Escape 2>/dev/null; sleep 1
    chk "tray: closing the window keeps the program running (close to tray)" "pgrep -x $PN >/dev/null"
    pkill -TERM -x "$PN"; sleep 3; chk "tray: SIGTERM still exits while hidden" "! pgrep -x $PN >/dev/null"
    pkill stalonetray
  else skip "tray test (stalonetray missing)"; fi
  pkill -f "Xvfb :79"; sleep 1; rm -f /tmp/.X79-lock /tmp/.X11-unix/X79
else skip "watcher/tray GUI tests (Xvfb/xdotool missing)"; fi


# ======================================================================== v3 regression tests
# hung helper: a fake notify-send that never exits must not freeze a scan (run_capture timeout)
mkdir -p $T/fakebin $T/v3t; printf '#!/bin/sh\nsleep 300\n' > $T/fakebin/notify-send; chmod +x $T/fakebin/notify-send
BAD x3 > $T/v3t/a.bin; setcfg action 0; setcfg notify 1
S0=$(date +%s); PATH=$T/fakebin:$PATH CLAMGUI_HELPER_TIMEOUT=3 DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent timeout 40 $GUI --scan $T/v3t >$T/o50.txt 2>&1; RC=$?; S1=$(date +%s)
chk "v3: a hung helper (notify-send) is killed by the timeout, scan still finishes (exit 1)" "[ $RC -eq 1 ] && [ $((S1-S0)) -lt 30 ]"
pgrep -f 'sleep 300' >/dev/null; chk "v3: the hung helper process is not left running" "[ $? -ne 0 ]"
# systemd unit: binary outside /usr,/opt -> documented install target; ExecStart present
$GUI --print-systemd-unit | grep -q '^ExecStart=/usr/local/sbin/clamgui ' ; chk "v3: systemd unit ExecStart uses the install target for a non-installed binary" "[ $? -eq 0 ]"
# newline-named file is reported, not silently dropped
mkdir -p $T/nl; BAD nl > "$T/nl/ok.bin"; touch "$T/nl/bad
name.bin"
$GUI --scan-recent $T/nl --days 1 >$T/o51.txt 2>&1; chk "v3: a newline-named file is reported as NOT scanned" "grep -q 'newline in the name' $T/o51.txt"
# curl ignores ~/.curlrc (-q): a hostile rc with an unreachable proxy must not break a lookup against the loopback mock
mkdir -p $T/curlhome; echo 'proxy = "http://127.0.0.1:1"' > $T/curlhome/.curlrc
(python3 $T/mock.py $MP $T/mock.log & echo $! > $T/mock.pid); sleep 1; setcfg intel_provider 1; setcfg intel_url http://127.0.0.1:$MP/bazaar
HOME=$T/curlhome CURL_HOME=$T/curlhome $GUI --lookup $ORIGSHA >$T/o52.txt 2>&1; chk "v3: a hostile ~/.curlrc (proxy) is ignored by the curl wrapper" "grep -q 'Mock.Family' $T/o52.txt"; kill $(cat $T/mock.pid) 2>/dev/null
# ---- GUI smoke (Xvfb)
if command -v Xvfb >/dev/null && command -v xdotool >/dev/null; then
  export DISPLAY=:79; pkill -f "Xvfb :79" 2>/dev/null; (Xvfb :79 -screen 0 1000x720x24 >/dev/null 2>&1 &); sleep 1
  for t in 0 1 2 3 4 5 6 7 8; do ($GUI --tab $t >$T/g$t.out 2>&1 &); sleep 1; GP=$(pgrep -f -- "$GUI --tab $t" | head -1); [ -n "$GP" ] && kill -0 $GP 2>/dev/null; chk "GUI tab $t opens and stays up" "[ -n \"$GP\" ] && kill -0 $GP"; pkill -TERM -f -- "$GUI --tab $t"; sleep .5; done
  chk "GUI printed no runtime errors on any tab" "! cat $T/g?.out | grep -qE 'ERROR|Sanitizer|runtime error|Assertion'"
  setcfg action 0; rm -f $T/home/data/reports/*
  ($GUI $T/in >$T/gscan.out 2>&1 &); sleep 4
  chk "GUI scan started from the command line wrote an infected report" "ls $T/home/data/reports/scan-*-infected.log >/dev/null 2>&1"
  pkill -TERM -f -- "$GUI $T/in"; sleep 1; chk "SIGTERM closes the GUI" "! pgrep -f -- \"$GUI $T/in\" >/dev/null"
  # killing the GUI mid-scan must also stop clamscan
  ($GUI $T/many >$T/gbig.out 2>&1 &); sleep 0.6; pkill -TERM -f -- "$GUI $T/many"; sleep 1.5
  chk "GUI killed mid-scan leaves no clamscan child behind" "! pgrep -f 'clamscan.*many' >/dev/null"
  pkill -f "Xvfb :79"
else skip "GUI smoke tests (Xvfb/xdotool missing)"; fi

echo; echo "RESULT: $P passed, $F failed, $S skipped"
[ $F -eq 0 ]
