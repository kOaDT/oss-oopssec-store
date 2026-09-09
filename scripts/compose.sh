#!/bin/bash

# Wrapper around docker compose that reads the Node version from .nvmrc and
# exports it, so the version lives in exactly one place. Compose interpolates
# the whole file on every command, so even `down` and `logs` go through here.

set -e

cd "$(dirname "$0")/.."

NODE_VERSION="$(tr -d '[:space:]' < .nvmrc)"

if [ -z "$NODE_VERSION" ]; then
  echo "error: .nvmrc is missing or empty; it holds the Node version to build with." >&2
  exit 1
fi

export NODE_VERSION

exec docker compose "$@"
