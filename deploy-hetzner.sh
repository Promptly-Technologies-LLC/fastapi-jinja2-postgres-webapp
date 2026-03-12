#!/usr/bin/env bash
set -euo pipefail

# --- Configuration ---
SERVER_NAME="${HETZNER_SERVER_NAME:-fastapi-webapp}"
SERVER_TYPE="${HETZNER_SERVER_TYPE:-cpx11}"      # 2 shared vCPU, 2GB RAM
IMAGE="${HETZNER_IMAGE:-ubuntu-24.04}"
LOCATION="${HETZNER_LOCATION:-ash}"               # Ashburn, VA, US
SSH_KEY_NAME="${HETZNER_SSH_KEY_NAME:-deploy-key}"
FIREWALL_NAME="${SERVER_NAME}-fw"
ENV_FILE="${1:-.env.production}"

# --- Preflight checks ---
if ! command -v hcloud &>/dev/null; then
    echo "Error: hcloud CLI not found. Install it first:"
    echo "  https://github.com/hetznercloud/cli"
    exit 1
fi

if ! hcloud context active &>/dev/null; then
    echo "Error: No active hcloud context. Run: hcloud context create <name>"
    exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
    echo "Error: Environment file '$ENV_FILE' not found."
    echo "Copy .env.example to $ENV_FILE and fill in production values."
    exit 1
fi

# Source env file to get DOMAIN for display
set -a
source "$ENV_FILE"
set +a

# DOMAIN is optional — if unset, will be set to server IP after provisioning

# --- SSH Key ---
echo "==> Ensuring SSH key '$SSH_KEY_NAME' exists..."
if ! hcloud ssh-key describe "$SSH_KEY_NAME" &>/dev/null; then
    if [ ! -f ~/.ssh/id_ed25519.pub ]; then
        echo "Generating SSH key..."
        ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
    fi
    hcloud ssh-key create --name "$SSH_KEY_NAME" --public-key-from-file ~/.ssh/id_ed25519.pub
    echo "    SSH key created."
else
    echo "    SSH key already exists."
fi

# --- Firewall ---
echo "==> Ensuring firewall '$FIREWALL_NAME' exists..."
if ! hcloud firewall describe "$FIREWALL_NAME" &>/dev/null; then
    hcloud firewall create --name "$FIREWALL_NAME"
    hcloud firewall add-rule "$FIREWALL_NAME" --direction in --protocol tcp --port 22 --source-ips 0.0.0.0/0 --source-ips ::/0 --description "SSH"
    hcloud firewall add-rule "$FIREWALL_NAME" --direction in --protocol tcp --port 80 --source-ips 0.0.0.0/0 --source-ips ::/0 --description "HTTP"
    hcloud firewall add-rule "$FIREWALL_NAME" --direction in --protocol tcp --port 443 --source-ips 0.0.0.0/0 --source-ips ::/0 --description "HTTPS"
    hcloud firewall add-rule "$FIREWALL_NAME" --direction in --protocol icmp --source-ips 0.0.0.0/0 --source-ips ::/0 --description "Ping"
    echo "    Firewall created with SSH, HTTP, HTTPS, and ICMP rules."
else
    echo "    Firewall already exists."
fi

# --- Cloud-init script ---
CLOUD_INIT_FILE=$(mktemp)
trap "rm -f '$CLOUD_INIT_FILE'" EXIT
cat > "$CLOUD_INIT_FILE" <<'CLOUD_INIT_EOF'
#!/bin/bash
set -euo pipefail

# Install Docker
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

# Install Docker Compose plugin
apt-get install -y docker-compose-plugin

# Create app directory
mkdir -p /opt/app
CLOUD_INIT_EOF

# --- Create or reuse server ---
echo "==> Ensuring server '$SERVER_NAME' exists..."
if ! hcloud server describe "$SERVER_NAME" &>/dev/null; then
    echo "    Creating server ($SERVER_TYPE in $LOCATION)..."
    hcloud server create \
        --name "$SERVER_NAME" \
        --type "$SERVER_TYPE" \
        --image "$IMAGE" \
        --location "$LOCATION" \
        --ssh-key "$SSH_KEY_NAME" \
        --firewall "$FIREWALL_NAME" \
        --user-data-from-file "$CLOUD_INIT_FILE"
    echo "    Server created. Waiting for cloud-init to finish..."
    sleep 30
else
    echo "    Server already exists."
fi

SERVER_IP=$(hcloud server ip "$SERVER_NAME")
echo "    Server IP: $SERVER_IP"

# Track whether we're using a real domain or just the IP
if [ -z "${DOMAIN:-}" ]; then
    USE_IP_MODE=true
    echo "    No DOMAIN set — using server IP ($SERVER_IP) with HTTP-only."
else
    USE_IP_MODE=false
fi

# --- Wait for SSH ---
echo "==> Waiting for SSH to become available..."
for i in $(seq 1 30); do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@"$SERVER_IP" true 2>/dev/null; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "Error: SSH not available after 150 seconds."
        exit 1
    fi
    sleep 5
done
echo "    SSH is ready."

# --- Wait for cloud-init ---
echo "==> Waiting for cloud-init to complete..."
ssh -o StrictHostKeyChecking=no root@"$SERVER_IP" "cloud-init status --wait" 2>/dev/null || true

# --- Deploy application ---
echo "==> Deploying application..."

# Copy project files to server
rsync -az --delete \
    --exclude '.venv' \
    --exclude '__pycache__' \
    --exclude '.mypy_cache' \
    --exclude '.pytest_cache' \
    --exclude '.git' \
    --exclude '.specstory' \
    --exclude '_docs' \
    --exclude '_environment' \
    --exclude 'artifacts' \
    --exclude 'node_modules' \
    --exclude '.env' \
    --exclude '.env.local' \
    --exclude '.env.development' \
    --exclude '.env.production' \
    --exclude 'tests' \
    --exclude 'docs' \
    -e "ssh -o StrictHostKeyChecking=no" \
    ./ root@"$SERVER_IP":/opt/app/

# Prepare env file contents locally (adjust DOMAIN and BASE_URL)
ENV_CONTENTS=$(cat "$ENV_FILE")

if [ "$USE_IP_MODE" = "true" ]; then
    # No domain: remove DOMAIN so Caddy defaults to :80, set BASE_URL to IP
    ENV_CONTENTS=$(echo "$ENV_CONTENTS" | grep -v '^DOMAIN=')
    ENV_CONTENTS=$(echo "$ENV_CONTENTS" | sed "s|^BASE_URL=.*|BASE_URL=http://$SERVER_IP|")
else
    # Real domain: set it for Caddy auto-TLS
    if echo "$ENV_CONTENTS" | grep -q '^DOMAIN='; then
        ENV_CONTENTS=$(echo "$ENV_CONTENTS" | sed "s|^DOMAIN=.*|DOMAIN=$DOMAIN|")
    else
        ENV_CONTENTS=$(printf '%s\nDOMAIN=%s' "$ENV_CONTENTS" "$DOMAIN")
    fi
    ENV_CONTENTS=$(echo "$ENV_CONTENTS" | sed "s|^BASE_URL=$|BASE_URL=https://$DOMAIN|")
    ENV_CONTENTS=$(echo "$ENV_CONTENTS" | sed "s|^BASE_URL=http://localhost.*|BASE_URL=https://$DOMAIN|")
fi

# Write secrets to tmpfs (RAM-only, never touches disk) via SSH pipe
echo "$ENV_CONTENTS" | ssh -o StrictHostKeyChecking=no root@"$SERVER_IP" 'cat > /dev/shm/.env.deploy'

# Build and start services using the tmpfs env file, then remove it
ssh -o StrictHostKeyChecking=no root@"$SERVER_IP" \
    'cd /opt/app && docker compose -f docker-compose.prod.yml --env-file /dev/shm/.env.deploy up -d --build; rm -f /dev/shm/.env.deploy'

echo ""
echo "==> Deployment complete!"
echo "    Server IP: $SERVER_IP"
if [ "$USE_IP_MODE" = "true" ]; then
    echo "    URL:       http://$SERVER_IP"
    echo ""
    echo "    To enable HTTPS, set DOMAIN in $ENV_FILE and redeploy."
else
    echo "    Domain:    ${DOMAIN}"
    echo ""
    echo "    Point your DNS A record for '${DOMAIN}' to $SERVER_IP"
    echo "    Caddy will automatically provision a TLS certificate once DNS propagates."
fi
echo ""
echo "    Useful commands:"
echo "      ssh root@$SERVER_IP                              # SSH into server"
echo "      ssh root@$SERVER_IP 'cd /opt/app && docker compose -f docker-compose.prod.yml logs -f'  # View logs"
echo "      ssh root@$SERVER_IP 'cd /opt/app && docker compose -f docker-compose.prod.yml restart'   # Restart"
echo "      hcloud server delete $SERVER_NAME                # Tear down server"
