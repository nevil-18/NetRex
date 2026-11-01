#!/usr/bin/env bash
# Starts the backend API and the admin Vite app. Ctrl-C stops both.
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

# Prompt for the key unless it's already in the environment.
if [[ -z "${GEMINI_API_KEY:-}" ]]; then
  read -rsp "GEMINI_API_KEY: " GEMINI_API_KEY
  echo
fi
if [[ -z "$GEMINI_API_KEY" ]]; then
  echo "GEMINI_API_KEY is required." >&2
  exit 1
fi

# Give each server its own process group so shutdown also reaches its children
# (uvicorn's reloader worker, npm's vite process).
set -m

(
  cd backend
  source .venv/bin/activate
  export GEMINI_API_KEY
  exec uvicorn app.main:app --reload --host 127.0.0.1 --port 8741
) </dev/null &
backend_pid=$!

(
  cd admin
  exec npm run dev
) </dev/null &
admin_pid=$!

cleanup() {
  trap - EXIT INT TERM
  kill -TERM -- "-$backend_pid" "-$admin_pid" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# If either server exits, stop the other one too.
wait -n
