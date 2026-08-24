#!/usr/bin/env bash
set -euo pipefail

force=false
youtrack_url=""

while (($#)); do
    case "$1" in
        --url)
            youtrack_url="${2:-}"
            shift 2
            ;;
        --force)
            force=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--url https://youtrack.example.com] [--force]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
deploy_dir="$repo_root/deploy"
secrets_dir="$deploy_dir/secrets"

write_private_file() {
    local path="$1"
    local value="$2"
    if [[ -e "$path" && "$force" != true ]]; then
        echo "File already exists: $path. Use --force to replace it." >&2
        exit 1
    fi
    umask 077
    printf '%s' "$value" >"$path"
    chmod 600 "$path"
}

if [[ -z "$youtrack_url" ]]; then
    read -r -p "YouTrack URL (for example https://youtrack.company.ru): " youtrack_url
fi
youtrack_url="${youtrack_url%/}"
if [[ ! "$youtrack_url" =~ ^https:// ]]; then
    echo "Production YouTrack URL must use HTTPS" >&2
    exit 1
fi

mkdir -p "$secrets_dir"

for name in mcp-sanitized mcp-plain; do
    target="$deploy_dir/$name.env"
    if [[ -e "$target" && "$force" != true ]]; then
        echo "File already exists: $target. Use --force to replace it." >&2
        exit 1
    fi
    content="$(<"$deploy_dir/$name.env.example")"
    content="${content//https:\/\/youtrack.example.com/$youtrack_url}"
    write_private_file "$target" "$content"
done

read -r -s -p "Read-only YouTrack token for sanitized MCP: " sanitized_token
echo
if [[ -z "$sanitized_token" ]]; then
    echo "The sanitized MCP token cannot be empty" >&2
    exit 1
fi

read -r -p "Use the same read-only token for plain MCP? [Y/n]: " reuse
if [[ -z "$reuse" || "$reuse" =~ ^[Yy] ]]; then
    plain_token="$sanitized_token"
else
    read -r -s -p "Read-only YouTrack token for plain MCP: " plain_token
    echo
fi
if [[ -z "$plain_token" ]]; then
    echo "The plain MCP token cannot be empty" >&2
    exit 1
fi

if command -v openssl >/dev/null 2>&1; then
    pseudonym_key="$(openssl rand -hex 32)"
else
    pseudonym_key="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
fi

write_private_file "$secrets_dir/youtrack-sanitized.token" "$sanitized_token"
write_private_file "$secrets_dir/youtrack-plain.token" "$plain_token"
write_private_file "$secrets_dir/sanitizer-pseudonym.key" "$pseudonym_key"

unset sanitized_token plain_token pseudonym_key

echo "Production files created. Next command:"
echo "docker compose -f docker-compose.production.yml config --quiet"
