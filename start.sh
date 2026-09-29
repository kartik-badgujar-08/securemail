#!/usr/bin/env bash
# Forwarding launcher script for convenience
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${DIR}/run.sh" "$@"
