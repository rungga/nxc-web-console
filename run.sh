#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/backend"

UV_BIN="${UV_BIN:-$(command -v uv || true)}"
if [[ -z "$UV_BIN" && -x "$HOME/.local/bin/uv" ]]; then
  UV_BIN="$HOME/.local/bin/uv"
fi
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 || true)}"

if [[ -n "$UV_BIN" && -z "${UV_CACHE_DIR:-}" ]]; then
  UV_DEFAULT_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/uv"
  if ! mkdir -p "$UV_DEFAULT_CACHE" 2>/dev/null || [[ ! -w "$UV_DEFAULT_CACHE" ]]; then
    export UV_CACHE_DIR="${TMPDIR:-/tmp}/nxc-webgui-uv-cache"
    mkdir -p "$UV_CACHE_DIR"
  fi
fi

if [[ ! -x ".venv/bin/python" ]]; then
  if [[ -n "$UV_BIN" ]]; then
    UV_VENV_ARGS=(venv --python 3.12)
    if [[ -d ".venv" ]]; then
      UV_VENV_ARGS+=(--clear)
    fi
    "$UV_BIN" "${UV_VENV_ARGS[@]}" .venv
  elif [[ -n "$PYTHON_BIN" ]] && "$PYTHON_BIN" -c 'import venv' >/dev/null 2>&1; then
    if [[ -d ".venv" ]]; then
      "$PYTHON_BIN" -m venv --clear .venv
    else
      "$PYTHON_BIN" -m venv .venv
    fi
  else
    printf 'Python 3.12 or uv is required. Install uv from https://docs.astral.sh/uv/\n' >&2
    exit 1
  fi
fi

if [[ -n "$UV_BIN" ]]; then
  "$UV_BIN" pip install --python .venv/bin/python -q -r requirements.txt -c constraints.txt
else
  .venv/bin/python -m pip install -q -r requirements.txt -c constraints.txt
fi

nxc_runtime_works() {
  local candidate="$1"
  local version_output
  version_output="$("$candidate" --version 2>&1 || true)"
  printf '%s\n' "$version_output" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+[^ ]*[[:space:]]+-'
}

if [[ -z "${NXC_BIN:-}" ]]; then
  NXC_BIN=""
  for command_name in nxc netexec NetExec; do
    candidate="$(command -v "$command_name" || true)"
    if [[ -n "$candidate" && -x "$candidate" ]] && nxc_runtime_works "$candidate"; then
      NXC_BIN="$candidate"
      break
    fi
  done
  if [[ -z "$NXC_BIN" ]]; then
    for candidate in "$HOME/.local/bin/nxc" "$HOME/.local/bin/netexec" "$HOME/.local/bin/NetExec"; do
      if [[ -x "$candidate" ]] && nxc_runtime_works "$candidate"; then
        NXC_BIN="$candidate"
        break
      fi
    done
  fi
  if [[ -z "$NXC_BIN" && -x "$SCRIPT_DIR/bin/nxc-lima" ]] && nxc_runtime_works "$SCRIPT_DIR/bin/nxc-lima"; then
    NXC_BIN="$SCRIPT_DIR/bin/nxc-lima"
    NXC_LIMA_STATE_DIR="${NXC_LIMA_STATE_DIR:-$HOME/.nxc-lima}"
    export NXC_HOME="${NXC_HOME:-$NXC_LIMA_STATE_DIR/home/.nxc}"
  fi
  export NXC_BIN="${NXC_BIN:-nxc}"
fi

exec .venv/bin/python -m uvicorn app.main:app --host "${NXCWEB_HOST:-127.0.0.1}" --port "${NXCWEB_PORT:-8000}"
