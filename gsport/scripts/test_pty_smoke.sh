#!/bin/bash
# Smoke test: Go listener with -i (PTY shell) ↔ Go connector with -i
# through production gsocket.org relay. Connector pipes commands to the
# remote shell; we check that the shell's output (ls + DONE marker)
# comes back through the in-band multiplexed channel.
set -e

BIN=/home/z/my-project/gsport/bin/gs-netcat
SECRET="SmokeTestInband$(date +%s)"
TMPOUT=/tmp/gsport_pty_smoke.out
TMPERR=/tmp/gsport_pty_smoke.err

echo "=== gs-netcat -i PTY smoke test ==="
echo "Secret: $SECRET"
echo "Building connector input (ls /tmp; echo DONE; exit)..."
INPUT="ls /tmp
echo DONE_MARKER_42
exit
"

echo "Starting listener (-l -i) in background..."
$BIN -l -i -s "$SECRET" -v 2>"$TMPERR.listener" &
LPID=$!
sleep 1  # give listener time to register with relay

echo "Running connector (-i) with command input..."
# Connector pipes the commands into the remote shell. We give it a
# short timeout so the test can't hang on failure.
echo "$INPUT" | timeout 15 $BIN -i -s "$SECRET" -v 2>"$TMPERR.connector" >"$TMPOUT" || true

echo "--- Listener stderr (last 30 lines) ---"
tail -30 "$TMPERR.listener" || true
echo "--- Connector stderr (last 30 lines) ---"
tail -30 "$TMPERR.connector" || true
echo "--- Connector stdout (looking for DONE_MARKER_42) ---"
cat "$TMPOUT"
echo "---"

if grep -q "DONE_MARKER_42" "$TMPOUT"; then
        echo "RESULT: PASS — shell output came back through in-band channel"
        # Cleanup
        kill $LPID 2>/dev/null || true
        wait $LPID 2>/dev/null || true
        exit 0
else
        echo "RESULT: FAIL — DONE_MARKER_42 not found in connector output"
        # Cleanup
        kill $LPID 2>/dev/null || true
        wait $LPID 2>/dev/null || true
        exit 1
fi
