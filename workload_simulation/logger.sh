#!/bin/bash
set -euo pipefail

WORKDIR="."
FLAG_FILE="${WORKDIR}/.casce_logging_active"
PID_FILE="${WORKDIR}/.casce_kernel_tracer.pid"
KERNEL_LOG="${WORKDIR}/kernel_events.json"
PG_LOG="${WORKDIR}/postgres_events.json"
TRACER="${WORKDIR}/kernel_telemetry.py"

mark() {
    local phase="$1"
    local ts
    ts="$(date +%s.%N)"
    echo "{\"marker\": \"${phase}\", \"timestamp\": ${ts}}" >> "$KERNEL_LOG"
    echo "{\"marker\": \"${phase}\", \"timestamp\": ${ts}}" >> "$PG_LOG"
}

status() {
    if [ -f "$FLAG_FILE" ] && [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "Logging is ACTIVE (kernel tracer pid $(cat "$PID_FILE"))."
    else
        echo "Logging is STOPPED."
    fi
}

start() {
    if [ -f "$FLAG_FILE" ]; then
        echo "Already running (use 'status' to check, 'stop' to stop)."
        exit 0
    fi

    touch "$KERNEL_LOG" "$PG_LOG"

    echo "Starting kernel eBPF tracer..."
    nohup python3 "$TRACER" > "${WORKDIR}/.kernel_tracer.log" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 1
    if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "Kernel tracer failed to start -- check ${WORKDIR}/.kernel_tracer.log"
        rm -f "$PID_FILE"
        exit 1
    fi

    touch "$FLAG_FILE"
    mark "LOGGING_START"

    UPTIME=$(cat /proc/uptime | cut -d '.' -f1)
    NOW=$(date +%s)
    let SYS_BOOT=NOW-UPTIME
    echo "{\"server_boot_unix_time\": ${SYS_BOOT}}" > "${WORKDIR}/time_sync.json"

    echo "Logging ACTIVE."
    echo "  Kernel events   -> ${KERNEL_LOG}"
    echo "  Postgres events -> ${PG_LOG}"
}

stop() {
    if [ ! -f "$FLAG_FILE" ]; then
        echo "Logging is not currently active."
        exit 0
    fi

    rm -f "$FLAG_FILE"

    if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
        rm -f "$PID_FILE"
    fi

    mark "LOGGING_STOP"
    echo "Logging STOPPED."
}

case "${1:-}" in
    start)       start ;;
    stop)        stop ;;
    status)      status ;;
    *) echo "usage: $0 start|stop|status"; exit 1 ;;
esac
