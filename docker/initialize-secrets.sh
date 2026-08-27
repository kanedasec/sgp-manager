#!/bin/sh
set -eu

secret_dir=/run/generated-secrets
mkdir -p "$secret_dir"
umask 077

ensure_secret() {
  secret_name="$1"
  explicit_value="$2"
  byte_count="$3"
  target="$secret_dir/$secret_name"
  if [ -s "$target" ]; then
    return
  fi
  temporary="$target.tmp.$$"
  if [ -n "$explicit_value" ]; then
    printf '%s\n' "$explicit_value" > "$temporary"
  else
    head -c "$byte_count" /dev/urandom | base64 | tr -d '\n' > "$temporary"
    printf '\n' >> "$temporary"
  fi
  chmod 0444 "$temporary"
  mv "$temporary" "$target"
}

ensure_secret postgres_password "${POSTGRES_PASSWORD_OVERRIDE:-}" 36
ensure_secret jwt_secret "${JWT_SECRET_OVERRIDE:-}" 48
ensure_secret api_key_pepper "${API_KEY_PEPPER_OVERRIDE:-}" 48

echo "Runtime secrets are initialized. Secret values were not logged."
