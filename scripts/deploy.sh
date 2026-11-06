#!/usr/bin/env bash
set -euo pipefail

# Deploy / update Chat Hook on the Contabo VPS. Secrets come only from Infisical.

REPO_DIR="${REPO_DIR:-/opt/src/chat_hook}"
STACK_DIR="${STACK_DIR:-/opt/chat_hook}"
INFRA_DIR="${INFRA_DIR:-/opt/src/self_hosting/infra}"
INFISICAL_PROJECT="${INFISICAL_PROJECT:-contabo-chat-hook}"
INFISICAL_AGENT_ENV="${INFISICAL_AGENT_ENV:-/opt/config/infisical-agent.env}"
BRANCH="${BRANCH:-main}"

if [[ "${SKIP_GIT_PULL:-}" != "1" ]]; then
    cd "$REPO_DIR"
    git fetch --prune origin "$BRANCH"
    git checkout -B "$BRANCH" "origin/$BRANCH"
fi

mkdir -p "$STACK_DIR"
cp "$REPO_DIR/compose/docker-compose.yml" "$STACK_DIR/docker-compose.yml"

if [[ -f "$INFISICAL_AGENT_ENV" ]] && [[ -f "$INFRA_DIR/scripts/infisical-env.sh" ]]; then
    # shellcheck disable=SC1091
    source "$INFRA_DIR/scripts/infisical-env.sh"
    infisical_fetch "$INFISICAL_PROJECT" "$STACK_DIR/.env" prod
elif [[ ! -f "$STACK_DIR/.env" ]]; then
    echo "No Infisical agent and no $STACK_DIR/.env; refusing to start with placeholder secrets." >&2
    exit 1
fi

# Fail before starting if a required secret is missing or still a placeholder.
for key in CHAT_HOOK_ADMIN_TOKEN CHAT_HOOK_SOURCE_ROOT CHAT_HOOK_DATA_KEY CHAT_HOOK_OWNER_PASSWORD; do
    value="$(grep -E "^${key}=" "$STACK_DIR/.env" | tail -n1 | cut -d= -f2- || true)"
    if [[ ${#value} -lt 32 || "$value" == *CHANGE_ME* ]]; then
        echo "Missing or weak $key in Infisical project $INFISICAL_PROJECT" >&2
        exit 1
    fi
done

docker network create caddy-net 2>/dev/null || true

cd "$STACK_DIR"
export CHAT_HOOK_SRC="$REPO_DIR"
docker compose up -d --build --remove-orphans

for _ in $(seq 1 30); do
    if [[ "$(docker inspect -f '{{.State.Health.Status}}' chat-hook 2>/dev/null)" == "healthy" ]]; then
        docker compose ps
        echo "Chat Hook deploy complete"
        exit 0
    fi
    sleep 2
done
docker compose ps
docker compose logs --tail=30 chat-hook chat-hook-worker
echo "Chat Hook did not become healthy" >&2
exit 1
