#!/bin/bash
# Runs once, the first time the Postgres container starts with an empty data
# folder.
#
# We need two databases on one server: ours and authentik's. authentik manages its
# own tables and shouldn't be sharing ours.
#
# Ours already exists by the time this runs, the Postgres image creates it.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
	CREATE USER authentik WITH PASSWORD '${AUTHENTIK_POSTGRES_PASSWORD:-authentik}';
	CREATE DATABASE authentik OWNER authentik;
EOSQL

echo "init: created authentik role and database"
