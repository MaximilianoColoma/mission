#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
scrubbed=()
if [[ ${PYTHONPATH+x} ]]; then scrubbed+=(PYTHONPATH); fi
if [[ ${PYTHONHOME+x} ]]; then scrubbed+=(PYTHONHOME); fi
unset PYTHONPATH PYTHONHOME
export WITMIS_ENV_SCRUBBED="$(IFS=,; printf '%s' "${scrubbed[*]-}")"
exec /usr/bin/python3 "$ROOT/scripts/install.py" "$@"
