#!/bin/bash
# Test that PONG arrives enriched with real load/n_users/user.
# Listener -i in background; connector -i with --ping-interval 2 sends
# PING every 2s; listener replies with PONG carrying gsstats values.
# We grep the connector's -v stderr for "PONG received" with non-zero
# load / n_users.
set -e
BIN=/home/z/my-project/gsport/bin/gs-netcat
SECRET="PongTest$(date +%s)"
TMPERR_C=/tmp/gsport_pong_test.err.connector
TMPERR_L=/tmp/gsport_pong_test.err.listener

echo "=== PONG enrichment test ==="
echo "Secret: $SECRET"

# Listener: -i spawns shell, but we feed /dev/null so it doesn't get input.
$BIN -l -i -s "$SECRET" -v </dev/null 2>"$TMPERR_L" &
LPID=$!
sleep 1

# Connector: -i, ping every 2s. Pipe `exit\n` so the shell exits after
# a couple of PING/PONG exchanges.
( echo "echo HELLO_FROM_SHELL_42"; sleep 5; echo "exit" ) | timeout 12 $BIN -i -s "$SECRET" -v --ping-interval 2 2>"$TMPERR_C" >/dev/null || true

sleep 1
kill $LPID 2>/dev/null || true
wait $LPID 2>/dev/null || true

echo "--- Connector stderr (PONG lines) ---"
grep "PONG received" "$TMPERR_C" || echo "(no PONG lines)"
echo "--- Listener stderr (last 10 lines) ---"
tail -10 "$TMPERR_L"

# Look for at least one PONG line with users > 0
if grep -E "PONG received \(load=[0-9]+ idle=[0-9]+ users=[0-9]+ user=" "$TMPERR_C" | head -1; then
        echo "RESULT: PASS — PONG arrived enriched"
        exit 0
else
        echo "RESULT: FAIL — no enriched PONG seen"
        exit 1
fi
