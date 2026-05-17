#!/usr/bin/env bash
# HispanShield OS — Vsock Command Dispatcher
#
# Runs inside the Firecracker MicroVM. Listens on VSOCK port 9999 for
# JSON command objects from the host (sent by firecracker_runner.sh via socat).
#
# Protocol (newline-delimited JSON):
#   Input:  {"cmd": "<tool>", "args": ["arg1", "arg2", ...], "timeout": <sec>}
#   Output: {"exit_code": 0, "stdout": "...", "stderr": "..."}
#
# Security:
#   - Commands are limited to an explicit allowlist (ALLOWED_TOOLS)
#   - Arguments are shell-quoted via printf '%q' before execution
#   - No shell metacharacters are passed through
#   - Execution timeout is enforced (default 60s, max 300s)
#   - All invocations are logged to /var/log/aegis-vsock.log

set -euo pipefail

VSOCK_PORT=9999
LOG_FILE="/var/log/aegis-vsock.log"
MAX_TIMEOUT=300
DEFAULT_TIMEOUT=60

# Allowlisted tools — only these can be executed via vsock
declare -A ALLOWED_TOOLS=(
    [nmap]="/usr/bin/nmap"
    [masscan]="/usr/bin/masscan"
    [nikto]="/usr/bin/nikto"
    [gobuster]="/usr/bin/gobuster"
    [sqlmap]="/usr/bin/sqlmap"
    [hydra]="/usr/bin/hydra"
    [john]="/usr/sbin/john"
    [hashcat]="/usr/bin/hashcat"
    [crackmapexec]="/usr/bin/crackmapexec"
    [socat]="/usr/bin/socat"
    [nc]="/usr/bin/nc"
    [tcpdump]="/usr/bin/tcpdump"
    [tshark]="/usr/bin/tshark"
    [curl]="/usr/bin/curl"
    [wget]="/usr/bin/wget"
    [nslookup]="/usr/bin/nslookup"
    [dig]="/usr/bin/dig"
    [traceroute]="/usr/bin/traceroute"
    [strace]="/usr/bin/strace"
    [python3]="/usr/bin/python3"
)

# ── Helpers ───────────────────────────────────────────────────────────────────

log() {
    printf '%s [aegis-vsock] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" \
        >> "$LOG_FILE" 2>/dev/null || true
}

json_escape() {
    # Minimal JSON string escaping without external deps
    printf '%s' "$1" \
        | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/; s/\t/\\t/g' \
        | tr -d '\n' \
        | sed 's/\\n$//'
}

send_response() {
    local exit_code="$1"
    local stdout_escaped
    local stderr_escaped
    stdout_escaped=$(json_escape "$2")
    stderr_escaped=$(json_escape "$3")
    printf '{"exit_code":%d,"stdout":"%s","stderr":"%s"}\n' \
        "$exit_code" "$stdout_escaped" "$stderr_escaped"
}

# ── Command execution ─────────────────────────────────────────────────────────

execute_command() {
    local cmd="$1"
    local args_json="$2"
    local timeout_sec="$3"

    # Validate tool
    local tool_path="${ALLOWED_TOOLS[$cmd]:-}"
    if [ -z "$tool_path" ]; then
        send_response 1 "" "Tool not in allowlist: ${cmd}"
        return
    fi
    if [ ! -x "$tool_path" ]; then
        send_response 1 "" "Tool binary not found: ${tool_path}"
        return
    fi

    # Clamp timeout
    if [ "$timeout_sec" -gt "$MAX_TIMEOUT" ]; then
        timeout_sec=$MAX_TIMEOUT
    fi
    if [ "$timeout_sec" -le 0 ]; then
        timeout_sec=$DEFAULT_TIMEOUT
    fi

    # Parse args from JSON array (simple approach: one arg per line, no nested quotes)
    # args_json is expected as: ["arg1","arg2",...]
    local args=()
    while IFS= read -r arg; do
        # Validate: reject shell metacharacters in any argument
        if printf '%s' "$arg" | grep -qP '[;&|`$<>!\\]'; then
            send_response 1 "" "Rejected: shell metacharacter in argument: ${arg}"
            log "REJECTED cmd=${cmd} reason=shell_metacharacter arg=${arg}"
            return
        fi
        args+=("$arg")
    done < <(printf '%s' "$args_json" \
        | python3 -c "import sys,json; [print(a) for a in json.load(sys.stdin)]" 2>/dev/null)

    log "EXEC cmd=${cmd} args_count=${#args[@]} timeout=${timeout_sec}s"

    local stdout_out stderr_out exit_code
    stdout_out=$(timeout "$timeout_sec" "$tool_path" "${args[@]}" 2>/tmp/vsock_stderr_$$ || true)
    exit_code=$?
    stderr_out=$(cat /tmp/vsock_stderr_$$ 2>/dev/null || true)
    rm -f /tmp/vsock_stderr_$$

    log "DONE cmd=${cmd} exit_code=${exit_code}"
    send_response "$exit_code" "$stdout_out" "$stderr_out"
}

# ── Main loop ─────────────────────────────────────────────────────────────────

install -d -m 700 "$(dirname "$LOG_FILE")"
log "Vsock dispatcher starting on port ${VSOCK_PORT}"

# Use socat to listen on VSOCK CID=any, port=VSOCK_PORT
# Each connection is handled in a subshell (one command per connection)
exec socat VSOCK-LISTEN:${VSOCK_PORT},reuseaddr,fork \
    EXEC:"/bin/bash -c '
        read -r line
        cmd=\$(printf \"%s\" \"\$line\" | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get(\\\"cmd\\\",\\\"\\\"))\" 2>/dev/null)
        args=\$(printf \"%s\" \"\$line\" | python3 -c \"import sys,json; d=json.load(sys.stdin); import json as j; print(j.dumps(d.get(\\\"args\\\",[])))\")
        timeout_sec=\$(printf \"%s\" \"\$line\" | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get(\\\"timeout\\\",60))\" 2>/dev/null)
        source /usr/local/sbin/vsock-dispatcher.sh
        execute_command \"\$cmd\" \"\$args\" \"\$timeout_sec\"
    '"
