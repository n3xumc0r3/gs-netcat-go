#!/bin/bash
# Test PWD request/reply round-trip: connector with -i --pwd sends a PWD
# request after the initial WSIZE. The listener's event-pump replies
# with ChnPWD containing the shell's cwd (read from /proc/<pid>/cwd).
# We check the connector's stderr for "[in-band] remote wd:".
set -e
BIN=/home/z/my-project/gsport/bin/gs-netcat
SECRET="PwdTest$(date +%s)"
TMPERR_C=/tmp/gsport_pwd_test.err.connector
TMPERR_L=/tmp/gsport_pwd_test.err.listener

echo "=== PWD round-trip test ==="
echo "Secret: $SECRET"

# Listener: -i spawns shell. stdin = /dev/null so shell sees EOF on
# its stdin and exits (but we kill it anyway after the test).
$BIN -l -i -s "$SECRET" -v </dev/null 2>"$TMPERR_L" &
LPID=$!
sleep 1

# Connector: -i --pwd sends PWD request, then waits a bit (sleep) so
# the reply has time to arrive, then exits (echo "exit" goes to remote
# shell which exits, triggering session close).
( sleep 3; echo "exit" ) | timeout 10 $BIN -i --pwd -s "$SECRET" -v 2>"$TMPERR_C" >/dev/null || true

sleep 1
kill $LPID 2>/dev/null || true
wait $LPID 2>/dev/null || true

echo "--- Connector stderr (PWD-related lines) ---"
grep -E "(PWD|remote wd)" "$TMPERR_C" || echo "(no PWD lines)"
echo "--- Listener stderr (last 15 lines) ---"
tail -15 "$TMPERR_L"

# Look for "[in-band] remote wd: /some/path"
if grep -E "remote wd: /.+" "$TMPERR_C" | head -1; then
        echo "RESULT: PASS — PWD round-trip works"
        exit 0
else
        echo "RESULT: FAIL — no remote wd reply seen"
        exit 1
fi
