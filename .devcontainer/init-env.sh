#!/usr/bin/env bash
set -euo pipefail

# Run from repo root
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Ensure a working .env exists
if [ ! -f ".env" ]; then
  if [ -f ".env.example" ]; then
    cp .env.example .env || true
  else
    touch .env
  fi
fi

# Ensure DB_HOST points to host.docker.internal for DooD sibling container access
if grep -q '^DB_HOST=' .env; then
  sed -i 's/^DB_HOST=.*/DB_HOST=host.docker.internal/' .env
else
  echo 'DB_HOST=host.docker.internal' >> .env
fi

generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 32
  else
    python - <<'PY'
import base64, os
print(base64.b64encode(os.urandom(32)).decode('ascii'))
PY
  fi
}

# Ensure SECRET_KEY exists and is non-empty/non-placeholder
if grep -q '^SECRET_KEY=' .env; then
  current_secret="$(grep '^SECRET_KEY=' .env | cut -d= -f2-)"
  if [ -z "${current_secret}" ] || [ "${current_secret}" = "changeme" ] || [ "${current_secret}" = "REPLACE_ME" ]; then
    new_secret="$(generate_secret)"
    sed -i "s/^SECRET_KEY=.*/SECRET_KEY=${new_secret}/" .env
  fi
else
  echo "SECRET_KEY=$(generate_secret)" >> .env
fi

echo "Environment prepared. DB_HOST set to 'host.docker.internal' and SECRET_KEY ensured."

