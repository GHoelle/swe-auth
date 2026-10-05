#!/usr/bin/env bash
#
# Generates .env with fresh random secrets.
#
# Nothing in this project has default credentials: ENVIRONMENT, DATABASE_URL and REDIS_URL
# are required with no fallbacks, and Compose refuses to start if a secret is missing. That
# is deliberate (a forgotten default is how "changeme" reaches production), so first-time
# setup needs a generator instead of being zero-config.

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
    echo "error: .env already exists. Refusing to overwrite it." >&2
    echo "       Delete it first if you want new secrets, but note that existing Postgres" >&2
    echo "       and Redis containers keep the old password: 'docker compose down -v' too." >&2
    exit 1
fi

if [[ ! -f .env.example ]]; then
    echo "error: .env.example not found. Run this from inside the repository." >&2
    exit 1
fi

# URL-safe output only. These values are interpolated into postgresql:// and redis:// URLs,
# where a '/', '@' or ':' would silently change what the URL means.
generate_secret() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
    elif command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n'
    else
        echo "error: need python3 or openssl to generate secrets." >&2
        exit 1
    fi
}

postgres_password="$(generate_secret)"
redis_password="$(generate_secret)"

while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
        POSTGRES_PASSWORD=*) printf 'POSTGRES_PASSWORD=%s\n' "$postgres_password" ;;
        REDIS_PASSWORD=*)    printf 'REDIS_PASSWORD=%s\n' "$redis_password" ;;
        *)                   printf '%s\n' "$line" ;;
    esac
done < .env.example > .env

# Owner read/write only. The file holds live credentials.
chmod 600 .env

echo "Wrote .env with freshly generated secrets (file mode 600)."
echo "It is covered by .gitignore and must never be committed."
echo
echo "Next: docker compose up --build"
