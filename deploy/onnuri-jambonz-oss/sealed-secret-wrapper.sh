#!/bin/sh
# Starts services that cannot consume password files natively without placing a
# secret in an argument vector or process environment.
set -eu

fail() {
  printf '%s\n' "g009 sealed secret wrapper: $1" >&2
  exit 1
}

case "${1:-}" in
  redis)
    test "$#" = 2 || fail "redis requires exactly one password file"
    password_file=$2
    test -f "$password_file" && test -r "$password_file" || fail "Redis password file is unreadable"
    umask 077
    redis_config=/run/recova-redis.conf
    {
      printf '%s\n' 'save ""'
      printf '%s\n' 'appendonly no'
      printf '%s\n' 'protected-mode yes'
      printf '%s' 'requirepass '
      cat "$password_file"
      printf '\n'
    } > "$redis_config"
    exec redis-server "$redis_config"
    ;;
  redis-health)
    test "$#" = 2 || fail "redis-health requires exactly one password file"
    password_file=$2
    test -f "$password_file" && test -r "$password_file" || fail "Redis password file is unreadable"
    exec python - "$password_file" <<'PY'
import socket
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    password = stream.read().rstrip("\r\n")
if not password:
    raise SystemExit("g009 sealed secret wrapper: Redis password is empty")
with socket.create_connection(("127.0.0.1", 6379), timeout=2) as connection:
    password_bytes = password.encode()
    connection.sendall(
        b"*2\r\n$4\r\nAUTH\r\n$" + str(len(password_bytes)).encode()
        + b"\r\n" + password_bytes + b"\r\n*1\r\n$4\r\nPING\r\n"
    )
    if b"+PONG\r\n" not in connection.recv(128):
        raise SystemExit(1)
PY
    ;;
  backend)
    test "$#" = 3 || fail "backend requires PostgreSQL and Redis password files"
    mode=$1
    postgres_password_file=$2
    redis_password_file=$3
    ;;
  migrate)
    test "$#" = 2 || fail "migrate requires exactly one PostgreSQL password file"
    mode=$1
    postgres_password_file=$2
    redis_password_file=
    ;;
  *)
    fail "unsupported mode"
    ;;
esac

test -f "$postgres_password_file" && test -r "$postgres_password_file" || fail "PostgreSQL password file is unreadable"
if test "$mode" = backend; then
  test -f "$redis_password_file" && test -r "$redis_password_file" || fail "Redis password file is unreadable"
fi
exec python - "$mode" "$postgres_password_file" "$redis_password_file" <<'PY'
import os
import sys
from urllib.parse import quote

mode, postgres_password_path, redis_password_path = sys.argv[1:]

def read_secret(path: str, label: str) -> str:
    with open(path, encoding="utf-8") as stream:
        value = stream.read().rstrip("\r\n")
    if not value:
        raise SystemExit(f"g009 sealed secret wrapper: {label} is empty")
    return value

# Rebind Python's environment mapping only. This does not update the C process
# environment, so credentials are absent from /proc/<pid>/environ and argv.
environment = dict(os.environ)
environment["DATABASE_URL"] = (
    "postgresql+asyncpg://recova:"
    + quote(read_secret(postgres_password_path, "PostgreSQL password"), safe="")
    + "@recova-postgres:5432/recova"
)
if mode == "backend":
    environment["REDIS_URL"] = (
        "redis://:"
        + quote(read_secret(redis_password_path, "Redis password"), safe="")
        + "@recova-redis:6379/0"
    )
os.environ = environment

if mode == "backend":
    from api.app import app

    environment.pop("DATABASE_URL")
    environment.pop("REDIS_URL")
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
elif mode == "migrate":
    # Alembic imports api.constants once; remove the private URLs immediately
    # afterward so neither process-level nor child environments inherit them.
    import api.constants  # noqa: F401

    environment.pop("DATABASE_URL")
    from alembic.config import CommandLine

    CommandLine(prog="alembic").main(["-c", "api/alembic.ini", "upgrade", "head"])
else:
    raise SystemExit("g009 sealed secret wrapper: unsupported mode")
PY
