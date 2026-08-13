#!/bin/bash
# Runs once, on first initialisation of the Postgres data volume.
#
# The compose stack needs two logical databases on one server: ours, and
# authentik's. authentik owns its schema entirely and must not share ours.
#
# POSTGRES_DB (ours) is created by the official entrypoint before this runs.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
	CREATE USER authentik WITH PASSWORD '${AUTHENTIK_POSTGRES_PASSWORD:-authentik}';
	CREATE DATABASE authentik OWNER authentik;
EOSQL

echo "init: created authentik role and database"
