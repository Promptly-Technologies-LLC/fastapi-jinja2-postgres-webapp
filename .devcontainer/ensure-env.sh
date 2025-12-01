#!/usr/bin/env bash
set -euo pipefail

# Run from repo root
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Ensure a .env exists BEFORE docker compose evaluates env_file
if [ ! -f ".env" ]; then
  if [ -f ".env.example" ]; then
    cp .env.example .env || true
  else
    touch .env
  fi
fi

echo ".env ensured for compose evaluation."

