#!/bin/bash
# CASCE dual-plane logger (run inside casce_environment as root).
#
#   logger.sh start                      begin capturing (Postgres hook + eBPF)
#   logger.sh stop                       stop capturing
#   logger.sh status                     is capturing active?
#   logger.sh mark_attack <name> start|end   annotate an attack window
#   logger.sh archive                    move the current logs to archive/<timestamp>/
#
# The eBPF collector writes the LOGGING_START marker and the clock anchor
# itself (same instant, like datagen/codegen.py), so this script no longer
# stamps its own start marker. The Postgres hook only writes while the flag
# file exists, and the flag is created only after the tracer is attached, so
# no Postgres event is ever captured without kernel tracing running.
set -euo pipefail

WORKDIR="/dataset_workspace"
FLAG_FILE="${WORKDIR}/.casce_logging_active"
PID_FILE="${WORKDIR}/.casce_kernel_tracer.pid"
READY_FILE="${WORKDIR}/.casce_kernel_tracer.ready"
KERNEL_LOG="${WORKDIR}/kernel_events.json"
KERNEL_RAW_LOG="${WORKDIR}/kernel_events.raw.json"
PG_LOG="${WORKDIR}/postgres_events.json"
LABEL_LOG="${WORKDIR}/session_labels.jsonl"
TRACER="${WORKDIR}/ebpf_telemetry/kernel_telemetry.py"
TRACER_LOG="${WORKDIR}/.kernel_tracer.log"

marker() {
    # marker <json-fields-without-timestamp>
    local ts
    ts="$(date +%s.%N)"
    echo "{$1, \"timestamp\": ${ts}}" >> "$KERNEL_LOG"
    echo "{$1, \"timestamp\": ${ts}}" >> "$PG_LOG"
}

is_active() {
    [ -f "$FLAG_FILE" ] && [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

status() {
    if is_active; then
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

    # One capture per run: never append a new run to an old one.
    for f in "$KERNEL_LOG" "$PG_LOG" "$LABEL_LOG"; do
        if [ -s "$f" ]; then
            echo "Refusing to start: $(basename "$f") still holds a previous capture."
            echo "Copy it where you need it, then run:  $0 archive"
            exit 1
        fi
    done

    # Postgres backends run as user postgres and append to these files.
    touch "$KERNEL_LOG" "$KERNEL_RAW_LOG" "$PG_LOG" "$LABEL_LOG"
    chmod 666 "$PG_LOG" "$LABEL_LOG"
    rm -f "$READY_FILE"

    echo "Starting kernel eBPF tracer (compiling BPF program, may take ~10-30 s)..."
    nohup python3 "$TRACER" --out "$KERNEL_LOG" --raw-out "$KERNEL_RAW_LOG" \
        --pg-log "$PG_LOG" --ready-file "$READY_FILE" > "$TRACER_LOG" 2>&1 &
    echo $! > "$PID_FILE"

    for _ in $(seq 1 120); do
        [ -f "$READY_FILE" ] && break
        if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "Kernel tracer failed to start -- see ${TRACER_LOG}:"
            tail -n 20 "$TRACER_LOG"
            rm -f "$PID_FILE"
            exit 1
        fi
        sleep 0.5
    done
    if [ ! -f "$READY_FILE" ]; then
        echo "Kernel tracer did not become ready within 60 s -- see ${TRACER_LOG}."
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
        rm -f "$PID_FILE"
        exit 1
    fi

    touch "$FLAG_FILE"

    # Kept for Algorithm 1's fallback path only; the clock anchor is what it uses.
    UPTIME=$(cut -d '.' -f1 /proc/uptime)
    NOW=$(date +%s)
    echo "{\"server_boot_unix_time\": $((NOW - UPTIME))}" > "${WORKDIR}/time_sync.json"

    echo "Logging ACTIVE."
    echo "  Kernel events   -> ${KERNEL_LOG}   (raw: ${KERNEL_RAW_LOG})"
    echo "  Postgres events -> ${PG_LOG}"
    echo "  Session labels  -> ${LABEL_LOG}"
}

stop() {
    if [ ! -f "$FLAG_FILE" ]; then
        echo "Logging is not currently active."
        exit 0
    fi

    rm -f "$FLAG_FILE"            # Postgres hook stops writing immediately
    marker "\"marker\": \"LOGGING_STOP\""

    if [ -f "$PID_FILE" ]; then
        local pid
        pid="$(cat "$PID_FILE")"
        kill -INT "$pid" 2>/dev/null || true    # lets the tracer drain its buffer
        for _ in $(seq 1 20); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.5
        done
        kill -9 "$pid" 2>/dev/null || true
        rm -f "$PID_FILE" "$READY_FILE"
    fi

    echo "Logging STOPPED."
}

mark_attack() {
    local name="${1:-}" phase="${2:-}"
    if [ -z "$name" ] || { [ "$phase" != "start" ] && [ "$phase" != "end" ]; }; then
        echo "usage: $0 mark_attack <name> start|end"; exit 1
    fi
    is_active || { echo "Logging is not active -- marker not written."; exit 1; }
    marker "\"marker\": \"ATTACK_${phase^^}\", \"attack\": \"${name}\""
}

archive() {
    if is_active; then
        echo "Logging is active -- stop it before archiving."; exit 1
    fi
    local dest="${WORKDIR}/archive/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$dest"
    for f in "$KERNEL_LOG" "$KERNEL_RAW_LOG" "$PG_LOG" "$LABEL_LOG" "${WORKDIR}/time_sync.json" "$TRACER_LOG"; do
        [ -e "$f" ] && mv "$f" "$dest/"
    done
    echo "Archived previous capture to $dest"
}

case "${1:-}" in
    start)       start ;;
    stop)        stop ;;
    status)      status ;;
    mark_attack) shift; mark_attack "$@" ;;
    archive)     archive ;;
    *) echo "usage: $0 start|stop|status|archive|mark_attack <name> start|end"; exit 1 ;;
esac
