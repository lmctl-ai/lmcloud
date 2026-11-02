#!/usr/bin/env bash
# Controls lifecycle for local cloud simulator binaries: start, stop, status, url.
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

Options for start:
  --port N        Specify fixed port (default: provider default port, or free port if busy)
  --free-port     Force dynamic free port selection
  --data-dir DIR  Specify data directory (default: isolated temp directory in run dir)
  --timeout S     Readiness timeout in seconds (default: 60)
EOF
  exit 2
}

[ $# -ge 2 ] || usage

ACTION="$1"
PROVIDER_RAW="$2"
shift 2

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

SIM_RUNDIR="$RUNDIR_BASE/$PROVIDER"
PID_FILE="$SIM_RUNDIR/pid"
PORT_FILE="$SIM_RUNDIR/port"
URL_FILE="$SIM_RUNDIR/url"
LOG_FILE="$SIM_RUNDIR/sim.log"

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
    azure) echo "http://127.0.0.1:$port/devstoreaccount1?comp=list" ;;
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

do_status() {
  if [ -f "$PID_FILE" ]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if is_pid_alive "$pid"; then
      local url="http://127.0.0.1:$(cat "$PORT_FILE" 2>/dev/null || echo '?')"
      echo "$PROVIDER is running (pid $pid, url $url)"
      return 0
    fi
  fi
  echo "$PROVIDER is stopped"
  return 1
}

do_url() {
  if [ -f "$PID_FILE" ]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if is_pid_alive "$pid"; then
      if [ -f "$URL_FILE" ]; then
        cat "$URL_FILE"
        return 0
      elif [ -f "$PORT_FILE" ]; then
        echo "http://127.0.0.1:$(cat "$PORT_FILE")"
        return 0
      fi
    fi
  fi
  echo "ERROR: $PROVIDER is not running" >&2
  return 1
}

do_stop() {
  if [ -f "$PID_FILE" ]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if is_pid_alive "$pid"; then
      kill "$pid" 2>/dev/null || true
      local waited=0
      while is_pid_alive "$pid" && [ "$waited" -lt 50 ]; do
        sleep 0.1
        waited=$((waited + 1))
      done
      if is_pid_alive "$pid"; then
        kill -9 "$pid" 2>/dev/null || true
      fi
    fi
  fi
  rm -f "$PID_FILE" "$PORT_FILE" "$URL_FILE"
  if [ -d "$SIM_RUNDIR/data" ]; then
    rm -rf "$SIM_RUNDIR/data"
  fi
  echo "Stopped $PROVIDER"
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

  # Check if already running
  if [ -f "$PID_FILE" ]; then
    local existing_pid
    existing_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if is_pid_alive "$existing_pid"; then
      cat "$URL_FILE"
      return 0
    fi
  fi

  # Determine port
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
  local data_dir="${custom_data_dir:-$SIM_RUNDIR/data}"
  mkdir -p "$data_dir"
  rm -f "$LOG_FILE"

  # Launch the sim in foreground 'serve' with stdout and stderr redirected to log
  local child_pid=""
  cleanup_on_error() {
    if [ -n "$child_pid" ] && is_pid_alive "$child_pid"; then
      kill "$child_pid" 2>/dev/null || true
      sleep 0.2
      kill -9 "$child_pid" 2>/dev/null || true
    fi
    rm -f "$PID_FILE" "$PORT_FILE" "$URL_FILE"
  }
  trap cleanup_on_error ERR INT TERM

  "$sim_bin" serve --port "$port" --data-dir "$data_dir" > "$LOG_FILE" 2>&1 &
  child_pid="$!"
  echo "$child_pid" > "$PID_FILE"
  echo "$port" > "$PORT_FILE"
  echo "http://127.0.0.1:$port" > "$URL_FILE"

  # Wait for readiness
  local ready_url
  ready_url="$(get_readiness_url "$port")"
  local start_time
  start_time="$(date +%s)"
  local ready=false

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
      ready=true
      break
    fi

    local now
    now="$(date +%s)"
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
  start)  do_start "$@" ;;
  stop)   do_stop ;;
  status) do_status ;;
  url)    do_url ;;
  *)      usage ;;
esac
