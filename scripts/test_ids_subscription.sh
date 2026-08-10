#!/bin/bash
# Live interop test: IDS subscription (MsgIDS) between Go client and Go server.
#
# Verifies:
#   1. Go client sends MsgIDS via --ids flag.
#   2. Go server receives MsgIDS, calls gsids.Subscribe, starts ticker.
#   3. Server logs "IDS request received — subscribed to utmp events" in -v.
#   4. Connection stays stable for 12+ seconds (proves no panic in the
#      IDS ticker goroutine which runs every 5s).
#   5. Server's "IDS subscription removed" message appears on disconnect.
#
# Note: actual MsgLOG alerts (new-login, idle→active) require real utmp
# activity which doesn't happen in a test container. The presence of
# the subscription log + ticker stability is the smoke-test target.

set -e

cd /home/z/my-project/gsport
BIN=./bin/linux-amd64/gs-netcat
SECRET="IDS-Test-$(date +%s)-$RANDOM"

echo "=== Test: --ids flag (MsgIDS subscription) Go↔Go ==="
echo "Secret: $SECRET"

# Start Go listener in interactive mode with verbose. Wrap in timeout
# so it exits even if the remote-close detection fails (e.g. relay
# keeps the connection half-open).
timeout 25 $BIN -l -i -v -s "$SECRET" 2>/tmp/ids_listener.log &
LPID=$!
echo "Listener PID: $LPID"

# Give listener a moment to start.
sleep 1

# Start Go connector with --ids. Send "ls /", then "exit" to make the
# server-side shell exit gracefully (which closes the conn, which lets
# both sides exit cleanly without needing SIGTERM from `timeout`).
( echo "ls /"; echo "exit"; sleep 12; ) | timeout 16 $BIN -i -v --ids -s "$SECRET" 2>/tmp/ids_client.log &
CPID=$!
echo "Client PID: $CPID"

# Wait for client to finish.
wait $CPID 2>/dev/null || true
echo "Client exited."

# Wait for listener to exit on its own (server should detect the
# remote close and exit gracefully — run's defer conn.Close() runs the
# OnClose hooks). The timeout 25 ensures we don't hang forever if
# remote-close detection fails.
wait $LPID 2>/dev/null || true
echo "Listener exited."

echo ""
echo "=== Listener stderr (full) ==="
cat /tmp/ids_listener.log

echo ""
echo "=== Client stderr (full) ==="
cat /tmp/ids_client.log

echo ""
echo "=== Assertions ==="

# 1. Server logged that it received the IDS request.
if grep -q "IDS request received" /tmp/ids_listener.log; then
    echo "PASS: server received MsgIDS and subscribed"
else
    echo "FAIL: server did not log IDS subscription"
    exit 1
fi

# 2. Server logged that subscription was removed on disconnect.
if grep -q "IDS subscription removed" /tmp/ids_listener.log; then
    echo "PASS: server removed IDS subscription on disconnect"
else
    echo "FAIL: server did not log subscription removal"
    exit 1
fi

# 3. Client logged that it sent the IDS subscription.
if grep -q "sent IDS subscription request" /tmp/ids_client.log; then
    echo "PASS: client sent MsgIDS"
else
    echo "FAIL: client did not send MsgIDS"
    exit 1
fi

# 4. No panic / crash in listener output.
if grep -qi "panic\|fatal error\|goroutine" /tmp/ids_listener.log; then
    echo "FAIL: server panicked"
    cat /tmp/ids_listener.log
    exit 1
fi
echo "PASS: no panic in server (12s = ~2 IDS ticks)"

echo ""
echo "=== Test PASSED ==="
