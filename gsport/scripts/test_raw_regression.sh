#!/bin/bash
# Regression test: raw cat mode (no -i) still works after PTY additions.
set -e
BIN=/home/z/my-project/gsport/bin/gs-netcat
SECRET="RawRegression$(date +%s)"
TMPOUT=/tmp/gsport_raw_regression.out
TMPERR_L=/tmp/gsport_raw_regression.err.listener
TMPERR_C=/tmp/gsport_raw_regression.err.connector

echo "=== raw cat-mode regression ==="
echo "Secret: $SECRET"

# Listener: stdin = /dev/null (no input), stdout -> $TMPOUT (where we check).
# We use < /dev/null so its stdin immediately EOFs and io.Copy(conn, stdin)
# doesn't block — but the listener stays alive because the remote-closed
# branch of the select is what exits the listener (raw-mode select waits
# on either stdinDone or remoteClosed; stdinDone fires first, then it
# waits 1s for remoteClosed).
$BIN -l -s "$SECRET" -q < /dev/null >"$TMPOUT" 2>"$TMPERR_L" &
LPID=$!
sleep 1
# Connector: stdin = echo pipe (sends payload then EOF), stdout = /dev/null
# (we don't care about what listener would have sent — listener has no input).
echo "hello-raw-mode-still-works" | timeout 8 $BIN -s "$SECRET" -q >/dev/null 2>"$TMPERR_C" || true
sleep 1
kill $LPID 2>/dev/null || true
wait $LPID 2>/dev/null || true

echo "--- raw-mode output ---"
cat "$TMPOUT"
echo "---"
if grep -q "hello-raw-mode-still-works" "$TMPOUT"; then
        echo "RESULT: PASS — raw cat mode works"
        exit 0
else
        echo "RESULT: FAIL — payload not delivered"
        echo "--- listener stderr ---"
        tail -20 "$TMPERR_L"
        echo "--- connector stderr ---"
        tail -20 "$TMPERR_C"
        exit 1
fi
