#!/usr/bin/env bash
# Compatibility entry point. Existing secrets are always preserved.
set -euo pipefail
exec bash "$(dirname -- "${BASH_SOURCE[0]}")/bootstrap.sh" "$@"
