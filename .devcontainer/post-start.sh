#!/usr/bin/env bash
set -euo pipefail

# Tee all output to a log file for post-hoc debugging
exec > >(tee -a /tmp/devcontainer-poststart.log) 2>&1

cd "$(dirname "${BASH_SOURCE[0]}")/.."

docker compose -f .devcontainer/docker-compose.yml up -d
