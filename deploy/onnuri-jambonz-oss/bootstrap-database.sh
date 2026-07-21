#!/bin/sh
# Initialise the pinned upstream schema and private G009 seed, or the separately
# proof-gated registration template when G009_REGISTRATION_BOOTSTRAP=1.
# Secrets never appear in output, shell tracing, or a process argument.
set -eu

fail() {
  printf '%s\n' "g009 database bootstrap: $1" >&2
  exit 1
}

require_file() {
  test -n "${2:-}" || fail "$1 path is required"
  test -f "$2" && test -r "$2" || fail "$1 is not a readable regular file"
}

read_secret() {
  value=$(LC_ALL=C tr -d '\r\n' < "$1")
  test -n "$value" || fail "$2 is empty"
  printf '%s' "$value"
}

sql_hex() {
  LC_ALL=C od -An -v -tx1 | tr -d ' \n'
}

create_mysql_defaults_file() {
  umask 077
  g009_mysql_defaults_file=$(mktemp /run/g009-mysql-defaults.XXXXXX) || fail "cannot create MariaDB credential file"
  {
    printf '%s\n' '[client]'
    printf '%s' 'password='
    LC_ALL=C tr -d '\r\n' < "$G009_MARIADB_ROOT_PASSWORD_FILE"
    printf '\n'
  } > "$g009_mysql_defaults_file"
  trap 'rm -f "$g009_mysql_defaults_file"' EXIT HUP INT TERM
}

mysql_client() {
  g009_mysql_client=$1
  shift
  "$g009_mysql_client" --defaults-extra-file="$g009_mysql_defaults_file" "$@"
}


if test "${G009_REGISTRATION_BOOTSTRAP:-}" = "1"; then
  test -r /bootstrap/20-g009-registration-template.sql || fail "G009 registration template is unavailable"
  test -n "${G009_REGISTRATION_CARRIER_SID:-}" || fail "registration carrier SID is required"
  test -n "${G009_REGISTRATION_GATEWAY_SID:-}" || fail "registration gateway SID is required"
  require_file "registration username" "${G009_REGISTRATION_USERNAME_FILE:-}"
  require_file "registration SIP realm" "${G009_REGISTRATION_SIP_REALM_FILE:-}"
  require_file "registration password" "${G009_REGISTRATION_PASSWORD_FILE:-}"
  test -n "${G009_REGISTRATION_GATEWAY_IPV4:-}" || fail "registration gateway IPv4 is required"
  for g009_registration_value in \
    "$G009_REGISTRATION_CARRIER_SID" \
    "$G009_REGISTRATION_GATEWAY_SID" \
    "$G009_REGISTRATION_GATEWAY_IPV4"
  do
    case "$g009_registration_value" in
      *[!A-Za-z0-9.:-]*) fail "registration identifier contains unsupported characters" ;;
    esac
  done
  g009_registration_username=$(read_secret "$G009_REGISTRATION_USERNAME_FILE" "registration username")
  g009_registration_sip_realm=$(read_secret "$G009_REGISTRATION_SIP_REALM_FILE" "registration SIP realm")
  g009_registration_password=$(read_secret "$G009_REGISTRATION_PASSWORD_FILE" "registration password")
  g009_registration_username_hex=$(printf '%s' "$g009_registration_username" | sql_hex)
  g009_registration_sip_realm_hex=$(printf '%s' "$g009_registration_sip_realm" | sql_hex)
  g009_registration_password_hex=$(printf '%s' "$g009_registration_password" | sql_hex)
else
  require_file "upstream schema" "${G009_UPSTREAM_SCHEMA_FILE:-}"
  require_file "webhook secret" "${G009_WEBHOOK_SECRET_FILE:-}"
  require_file "account API token" "${G009_ACCOUNT_API_TOKEN_FILE:-}"
  test -r /bootstrap/10-g009-minimal-seed.sql || fail "G009 seed is unavailable"
  test -n "${G009_JAMBONES_MYSQL_USER:-}" || fail "Jambonz database user is required"
  require_file "Jambonz database password" "${G009_JAMBONES_MYSQL_PASSWORD_FILE:-}"
  case "$G009_JAMBONES_MYSQL_USER" in
    *[!A-Za-z0-9_]*|?|'') fail "Jambonz database user contains unsupported characters" ;;
  esac
fi
require_file "MariaDB root password" "${G009_MARIADB_ROOT_PASSWORD_FILE:-}"
create_mysql_defaults_file
if test "${G009_REGISTRATION_BOOTSTRAP:-}" != "1"; then
  g009_jambones_mysql_password=$(read_secret "$G009_JAMBONES_MYSQL_PASSWORD_FILE" "Jambonz database password")
  g009_jambones_mysql_password_hex=$(printf '%s' "$g009_jambones_mysql_password" | sql_hex)
  g009_webhook_secret=$(read_secret "$G009_WEBHOOK_SECRET_FILE" "webhook secret")
  g009_account_api_token=$(read_secret "$G009_ACCOUNT_API_TOKEN_FILE" "account API token")
fi

g009_database_attempt=0
until mysql_client mariadb-admin ping \
  --protocol=tcp \
  --host="${G009_DATABASE_HOST:-mariadb}" \
  --port="${G009_DATABASE_PORT:-3306}" \
  --user=root \
  --silent
do
  g009_database_attempt=$((g009_database_attempt + 1))
  test "$g009_database_attempt" -lt 60 || fail "MariaDB TCP readiness timed out"
  sleep 1
done

if test "${G009_REGISTRATION_BOOTSTRAP:-}" = "1"; then
  {
    printf "SET @g009_registration_carrier_sid = '%s';\n" "$G009_REGISTRATION_CARRIER_SID"
    printf "SET @g009_registration_gateway_sid = '%s';\n" "$G009_REGISTRATION_GATEWAY_SID"
    printf "SET @g009_registration_account_sid = '70090000-0000-4000-8000-000000000002';\n"
    printf "SET @g009_registration_application_sid = '70090000-0000-4000-8000-000000000006';\n"
    printf "SET @g009_registration_username = CONVERT(0x%s USING utf8mb4);\n" "$g009_registration_username_hex"
    printf "SET @g009_registration_sip_realm = CONVERT(0x%s USING utf8mb4);\n" "$g009_registration_sip_realm_hex"
    printf "SET @g009_registration_password = CONVERT(0x%s USING utf8mb4);\n" "$g009_registration_password_hex"
    printf "SET @g009_registration_gateway_ipv4 = '%s';\n" "$G009_REGISTRATION_GATEWAY_IPV4"
    printf '%s\n' "DELIMITER //"
    printf '%s\n' "CREATE PROCEDURE g009_require_empty_registration_rows() BEGIN IF (SELECT COUNT(*) FROM voip_carriers WHERE voip_carrier_sid = @g009_registration_carrier_sid) <> 0 OR (SELECT COUNT(*) FROM sip_gateways WHERE sip_gateway_sid = @g009_registration_gateway_sid) <> 0 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'G009 registration rows already exist'; END IF; END//"
    printf '%s\n' "CALL g009_require_empty_registration_rows()//"
    printf '%s\n' "DROP PROCEDURE g009_require_empty_registration_rows//"
    printf '%s\n' "DELIMITER ;"
    cat /bootstrap/20-g009-registration-template.sql
    printf '%s\n' "DELIMITER //"
    printf '%s\n' "CREATE PROCEDURE g009_require_registration_cardinality() BEGIN IF (SELECT COUNT(*) FROM voip_carriers WHERE voip_carrier_sid = @g009_registration_carrier_sid AND requires_register = 1) <> 1 OR (SELECT COUNT(*) FROM sip_gateways WHERE sip_gateway_sid = @g009_registration_gateway_sid AND voip_carrier_sid = @g009_registration_carrier_sid) <> 1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'G009 registration template cardinality mismatch'; END IF; END//"
    printf '%s\n' "CALL g009_require_registration_cardinality()//"
    printf '%s\n' "DROP PROCEDURE g009_require_registration_cardinality//"
    printf '%s\n' "DELIMITER ;"
  } | mysql_client mysql \
    --protocol=tcp \
    --host="${G009_DATABASE_HOST:-mariadb}" \
    --port="${G009_DATABASE_PORT:-3306}" \
    --user=root \
    --database="${G009_DATABASE_NAME:-jambones}" \
    --batch \
    --skip-column-names
else
  # Secrets are streamed on stdin and client authentication uses a mode-0600
  # temporary defaults file, never command-line or environment credentials.
  {
    printf "SET @g009_webhook_secret = '%s';\n" "$g009_webhook_secret"
    printf "SET @g009_account_api_token = '%s';\n" "$g009_account_api_token"
    printf "CREATE USER IF NOT EXISTS '%s'@'%%' IDENTIFIED BY CONVERT(0x%s USING utf8mb4);\n" "$G009_JAMBONES_MYSQL_USER" "$g009_jambones_mysql_password_hex"
    printf "GRANT ALL PRIVILEGES ON \`%s\`.* TO '%s'@'%%';\n" "${G009_DATABASE_NAME:-jambones}" "$G009_JAMBONES_MYSQL_USER"
    printf "FLUSH PRIVILEGES;\n"
    cat "$G009_UPSTREAM_SCHEMA_FILE"
    cat /bootstrap/10-g009-minimal-seed.sql
  } | mysql_client mysql \
    --protocol=tcp \
    --host="${G009_DATABASE_HOST:-mariadb}" \
    --port="${G009_DATABASE_PORT:-3306}" \
    --user=root \
    --database="${G009_DATABASE_NAME:-jambones}" \
    --batch \
    --skip-column-names
fi
