---
Task ID: window-size-fix-v0.1.15
Agent: main
Task: Fix "overwritten text" display corruption — client window is 120 cols but WSIZE sends 80.

Work Log:
- Root cause found: GetStdinWindowSize() in termios_windows.go passed os.Stdin.Fd() to GetConsoleScreenBufferInfo
- Win32 API GetConsoleScreenBufferInfo REQUIRES hConsoleOutput (output handle), NOT input handle
- Passing stdin always fails (returns 0) → fallback to return 80, 24 → EVERY Windows client reported 80x24
- Server created ConPTY at 80x24, shell formatted output for 80 cols
- Client's real terminal was 120 cols → VT cursor positioning sequences assumed 80-col layout → cursor at wrong columns → text overwritten/scrambled
- Same bug affected watchWindowSize polling (250ms) — never detected resizes because GetStdinWindowSize always returned 80x24
- Fix: use os.Stdout.Fd() (correct output handle), with fallback to os.Stderr.Fd() if stdout is piped
- Added queryConsoleSize helper for clean code
- Bumped version to v0.1.15-fix
- Built v0.1.15-fix.exe (3569152 bytes)

Stage Summary:
- This was the root cause of ALL display corruption symptoms:
  * "overwritten text" after ls output
  * PONG messages scrambling the prompt
  * Long commands getting truncated/overwritten
- After fix: client will send WSIZE 120x24 (matching real window)
- Server PTY will be 120 cols, shell will format for 120 cols, VT sequences will match client layout
- watchWindowSize polling will now actually detect resizes
- Artifact: /home/z/my-project/download/gs-netcat-v0.1.15-fix.exe
