#!/usr/bin/env bash
# Controls lifecycle for local cloud simulator binaries: start, stop, status, url.
# Supports named concurrency (--name / LMCLOUD_SIM_NAME), process group termination,
# PID reuse validation, and clean signal handling.
#
# NOTE ON SIGNALS & CI:
# Backgrounded shells or CI runners may launch with SIGINT ignored (SIG_IGN).
# Handlers must perform cleanup AND exit with standard signal codes:
#   SIGINT -> exit 130 (128 + 2)
#   SIGTERM -> exit 143 (128 + 15)
# CI workflows should always call 'sim.sh stop' in an 'if: always()' teardown block.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CACHE_DIR="${LMCLOUD_SIM_DIR:-$ROOT/.cache/sims}"
RUNDIR_BASE="${LMCLOUD_SIM_RUNDIR:-$ROOT/.cache/sims/run}"

usage() {
  cat <<'EOF'
Usage: scripts/sim.sh <start|stop|status|url> <aws|azure|gcp|oci> [options]

Commands:
  start   Start simulator in background, wait for readiness, print endpoint URL
  stop    Stop running simulator cleanly
  status  Check if simulator is running (exit 0 if running, 1 if stopped)
  url     Print endpoint URL of running simulator (exit 0 if running, 1 if stopped)

Options:
  --name NAME     Instance name for concurrent runs (default: $LMCLOUD_SIM_NAME or 'default')
  --port N        Specify fixed port (default: provider default port, or free port if busy)
  --free-port     Force dynamic free port selection
  --data-dir DIR  Specify data directory (default: isolated temp directory in run dir)
  --timeout S     Readiness timeout in seconds (default: 60)
EOF
  exit 2
}

# Extract --name from arguments anywhere to support named instances
NAME="${LMCLOUD_SIM_NAME:-default}"
FILTERED_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --name)
      NAME="$2"
      shift 2
      ;;
    --name=*)
      NAME="${1#*=}"
      shift 1
      ;;
    *)
      FILTERED_ARGS+=("$1")
      shift 1
      ;;
  esac
done

if [ ${#FILTERED_ARGS[@]} -lt 2 ]; then
  usage
fi

ACTION="${FILTERED_ARGS[0]}"
PROVIDER_RAW="${FILTERED_ARGS[1]}"
REMAINING_ARGS=()
if [ ${#FILTERED_ARGS[@]} -gt 2 ]; then
  REMAINING_ARGS=("${FILTERED_ARGS[@]:2}")
fi

case "$PROVIDER_RAW" in
  aws|awssim)     PROVIDER="aws";   SIM_NAME="awssim" ;;
  azure|azuresim) PROVIDER="azure"; SIM_NAME="azuresim" ;;
  gcp|gcpsim)     PROVIDER="gcp";   SIM_NAME="gcpsim" ;;
  oci|ocisim)     PROVIDER="oci";   SIM_NAME="ocisim" ;;
  *)
    echo "ERROR: Unknown provider '$PROVIDER_RAW'. Expected aws, azure, gcp, or oci." >&2
    exit 2
    ;;
esac

# Isolated run directory per provider and instance name
SIM_RUNDIR="$RUNDIR_BASE/$PROVIDER/$NAME"
PID_FILE="$SIM_RUNDIR/pid"
PORT_FILE="$SIM_RUNDIR/port"
URL_FILE="$SIM_RUNDIR/url"
LOG_FILE="$SIM_RUNDIR/sim.log"
DATA_DIR_MARKER="$SIM_RUNDIR/custom_data_dir"

is_pid_alive() {
  local pid="$1"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

find_free_port() {
  python3 -c '
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(("127.0.0.1", 0))
    print(s.getsockname()[1])
'
}

is_port_free() {
  local port="$1"
  python3 -c '
import socket, sys
port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        sys.exit(0)
    except OSError:
        sys.exit(1)
' "$port"
}

get_default_port() {
  case "$PROVIDER" in
    aws)   echo 4566 ;;
    azure) echo 4577 ;;
    gcp)   echo 4588 ;;
    oci)   echo 4599 ;;
  esac
}

get_readiness_url() {
  local port="$1"
  case "$PROVIDER" in
    aws)   echo "http://127.0.0.1:$port/_floci/health" ;;
    azure) echo "http://127.0.0.1:$port/_floci/health" ;;
    gcp)   echo "http://127.0.0.1:$port/health" ;;
    oci)   echo "http://127.0.0.1:$port/_floci-oci/health" ;;
  esac
}

ensure_binary() {
  local bin_path="$CACHE_DIR/$SIM_NAME"
  if [ ! -x "$bin_path" ]; then
    "$HERE/fetch-sims.sh" "$SIM_NAME" >&2
  fi
  if [ ! -x "$bin_path" ]; then
    echo "ERROR: Simulator binary $bin_path not executable after fetch" >&2
    exit 1
  fi
  echo "$bin_path"
}

# Process group / process kill helper
kill_process_or_group() {
  local pid="$1"
  local sig="$2"
  # Attempt process group kill first, fall back to single process
  kill "-$sig" "-$pid" 2>/dev/null || kill "-$sig" "$pid" 2>/dev/null || true
}

# Reads pid metadata: RECORDED_PID, RECORDED_EXE, RECORDED_START
read_pid_info() {
  local pfile="$1"
  RECORDED_PID=""
  RECORDED_EXE=""
  RECORDED_START=""
  [ -f "$pfile" ] || return 1

  while IFS='=' read -r key val || [ -n "$key" ]; do
    case "$key" in
      PID) RECORDED_PID="$val" ;;
      EXE) RECORDED_EXE="$val" ;;
      START) RECORDED_START="$val" ;;
      # Support legacy single-line integer pidfiles
      [0-9]*)
        if [ -z "$RECORDED_PID" ]; then
          RECORDED_PID="$key"
        fi
        ;;
    esac
  done < "$pfile"
}

# Verifies process identity to protect against PID recycling
verify_process_identity() {
  local pid="$1"
  local expected_exe="$2"
  local expected_start="$3"

  is_pid_alive "$pid" || return 1

  local exe_name
  exe_name="$(basename "$expected_exe" 2>/dev/null || echo "$expected_exe")"

  if [ -f "/proc/$pid/cmdline" ]; then
    local proc_cmd
    proc_cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
    case "$proc_cmd" in
      *"$exe_name"*) ;;
      *) return 1 ;;
    esac
  else
    # macOS fallback via ps comm
    local proc_comm
    proc_comm="$(ps -o comm= -p "$pid" 2>/dev/null | sed 's/^[[:space:]]*//' || true)"
    case "$proc_comm" in
      *"$exe_name"*) ;;
      *) return 1 ;;
    esac
  fi

  # Validate start time if recorded
  if [ -n "$expected_start" ]; then
    local cur_start
    cur_start="$(ps -o lstart= -p "$pid" 2>/dev/null | sed 's/^[[:space:]]*//' || true)"
    if [ -n "$cur_start" ] && [ "$cur_start" != "$expected_start" ]; then
      return 1
    fi
  fi

  return 0
}

do_status() {
  if [ -f "$PID_FILE" ]; then
    read_pid_info "$PID_FILE"
    if [ -n "$RECORDED_PID" ]; then
      if verify_process_identity "$RECORDED_PID" "${RECORDED_EXE:-$SIM_NAME}" "$RECORDED_START"; then
        local p_val
        p_val="$(cat "$PORT_FILE" 2>/dev/null || echo '?')"
        echo "$PROVIDER (name: $NAME) is running (pid $RECORDED_PID, url http://127.0.0.1:$p_val)"
        return 0
      else
        if is_pid_alive "$RECORDED_PID"; then
          echo "WARNING: PID $RECORDED_PID does not match $PROVIDER process identity. Clearing stale pidfile." >&2
        fi
        rm -f "$PID_FILE" "$PORT_FILE" "$URL_FILE"
      fi
    fi
  fi
  echo "$PROVIDER (name: $NAME) is stopped"
  return 1
}

do_url() {
  if [ -f "$PID_FILE" ]; then
    read_pid_info "$PID_FILE"
    if [ -n "$RECORDED_PID" ] && verify_process_identity "$RECORDED_PID" "${RECORDED_EXE:-$SIM_NAME}" "$RECORDED_START"; then
      if [ -f "$URL_FILE" ]; then
        cat "$URL_FILE"
        return 0
      elif [ -f "$PORT_FILE" ]; then
        echo "http://127.0.0.1:$(cat "$PORT_FILE")"
        return 0
      fi
    else
      rm -f "$PID_FILE" "$PORT_FILE" "$URL_FILE"
    fi
  fi
  echo "ERROR: $PROVIDER (name: $NAME) is not running" >&2
  return 1
}

do_stop() {
  if [ -f "$PID_FILE" ]; then
    read_pid_info "$PID_FILE"
    if [ -n "$RECORDED_PID" ] && is_pid_alive "$RECORDED_PID"; then
      if verify_process_identity "$RECORDED_PID" "${RECORDED_EXE:-$SIM_NAME}" "$RECORDED_START"; then
        kill_process_or_group "$RECORDED_PID" TERM
        local waited=0
        while is_pid_alive "$RECORDED_PID" && [ "$waited" -lt 50 ]; do
          sleep 0.1
          waited=$((waited + 1))
        done
        if is_pid_alive "$RECORDED_PID"; then
          kill_process_or_group "$RECORDED_PID" KILL
        fi
      else
        echo "WARNING: PID $RECORDED_PID does not match $PROVIDER process identity. Refusing to kill foreign process." >&2
      fi
    fi
  fi

  rm -f "$PID_FILE" "$PORT_FILE" "$URL_FILE"
  # Clean up default isolated data directory unless custom data dir was specified
  if [ ! -f "$DATA_DIR_MARKER" ] && [ -d "$SIM_RUNDIR/data" ]; then
    rm -rf "$SIM_RUNDIR/data"
  fi
  rm -f "$DATA_DIR_MARKER"

  echo "Stopped $PROVIDER (name: $NAME)"
  return 0
}

do_start() {
  local specified_port=""
  local force_free=false
  local custom_data_dir=""
  local timeout_secs=60

  while [ $# -gt 0 ]; do
    case "$1" in
      --port)
        specified_port="$2"
        shift 2
        ;;
      --port=*)
        specified_port="${1#*=}"
        shift 1
        ;;
      --free-port)
        force_free=true
        shift 1
        ;;
      --data-dir)
        custom_data_dir="$2"
        shift 2
        ;;
      --data-dir=*)
        custom_data_dir="${1#*=}"
        shift 1
        ;;
      --timeout)
        timeout_secs="$2"
        shift 2
        ;;
      --timeout=*)
        timeout_secs="${1#*=}"
        shift 1
        ;;
      *)
        echo "ERROR: Unknown option '$1'" >&2
        usage
        ;;
    esac
  done

  # Idempotent start: return existing running instance if already healthy
  if [ -f "$PID_FILE" ]; then
    read_pid_info "$PID_FILE"
    if [ -n "$RECORDED_PID" ] && verify_process_identity "$RECORDED_PID" "${RECORDED_EXE:-$SIM_NAME}" "$RECORDED_START"; then
      cat "$URL_FILE"
      return 0
    else
      # Stale pidfile
      rm -f "$PID_FILE" "$PORT_FILE" "$URL_FILE"
    fi
  fi

  # Determine port: fixed, free, or default port (with fallback to free if busy)
  local port=""
  if [ -n "$specified_port" ]; then
    port="$specified_port"
    if ! is_port_free "$port"; then
      echo "ERROR: Specified port $port is already in use" >&2
      exit 1
    fi
  elif [ "$force_free" = true ]; then
    port="$(find_free_port)"
  else
    local def_port
    def_port="$(get_default_port)"
    if is_port_free "$def_port"; then
      port="$def_port"
    else
      port="$(find_free_port)"
    fi
  fi

  local sim_bin
  sim_bin="$(ensure_binary)"

  mkdir -p "$SIM_RUNDIR"
  local data_dir
  if [ -n "$custom_data_dir" ]; then
    data_dir="$custom_data_dir"
    echo "$data_dir" > "$DATA_DIR_MARKER"
  else
    data_dir="$SIM_RUNDIR/data"
    rm -f "$DATA_DIR_MARKER"
  fi
  mkdir -p "$data_dir"

  # Truncate log file on start
  : > "$LOG_FILE"

  local child_pid=""
  cleanup_on_error() {
    if [ -n "$child_pid" ] && is_pid_alive "$child_pid"; then
      kill_process_or_group "$child_pid" TERM
      local waited=0
      while is_pid_alive "$child_pid" && [ "$waited" -lt 20 ]; do
        sleep 0.1
        waited=$((waited + 1))
      done
      if is_pid_alive "$child_pid"; then
        kill_process_or_group "$child_pid" KILL
      fi
    fi
    rm -f "$PID_FILE" "$PORT_FILE" "$URL_FILE"
  }

  on_int() {
    cleanup_on_error
    exit 130
  }

  on_term() {
    cleanup_on_error
    exit 143
  }

  on_err() {
    local ec=$?
    cleanup_on_error
    exit "$ec"
  }

  trap on_int INT
  trap on_term TERM
  trap on_err ERR

  # Launch in its own process group via setsid (or python setsid fallback on BSD/macOS)
  if command -v setsid >/dev/null 2>&1; then
    setsid "$sim_bin" serve --port "$port" --data-dir "$data_dir" > "$LOG_FILE" 2>&1 &
  else
    python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
      "$sim_bin" serve --port "$port" --data-dir "$data_dir" > "$LOG_FILE" 2>&1 &
  fi
  child_pid="$!"

  local lstart
  lstart="$(ps -o lstart= -p "$child_pid" 2>/dev/null | sed 's/^[[:space:]]*//' || true)"

  cat <<EOF > "$PID_FILE"
PID=$child_pid
EXE=$sim_bin
START=$lstart
EOF
  echo "$port" > "$PORT_FILE"
  echo "http://127.0.0.1:$port" > "$URL_FILE"

  # Wait for readiness
  local ready_url
  ready_url="$(get_readiness_url "$port")"
  local start_time
  start_time="$(python3 -c 'import time; print(int(time.time()))')"

  while true; do
    if ! is_pid_alive "$child_pid"; then
      echo "ERROR: $PROVIDER exited unexpectedly during startup. Log tail:" >&2
      tail -n 20 "$LOG_FILE" >&2 || true
      cleanup_on_error
      exit 1
    fi

    local code
    code="$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 1 "$ready_url" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then
      break
    fi

    local now
    now="$(python3 -c 'import time; print(int(time.time()))')"
    if [ $((now - start_time)) -ge "$timeout_secs" ]; then
      echo "ERROR: Timed out waiting $timeout_secs seconds for $PROVIDER readiness at $ready_url" >&2
      tail -n 20 "$LOG_FILE" >&2 || true
      cleanup_on_error
      exit 1
    fi

    sleep 0.2
  done

  # Disarm error cleanup trap once successfully ready
  trap - ERR INT TERM
  echo "http://127.0.0.1:$port"
}

case "$ACTION" in
  start)  do_start "${REMAINING_ARGS[@]}" ;;
  stop)   do_stop ;;
  status) do_status ;;
  url)    do_url ;;
  *)      usage ;;
esac
