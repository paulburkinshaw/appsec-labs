#!/bin/sh

dotnet build secure/backend/Secure.sln
docker compose -f secure/backend/docker-compose.yml -f secure/backend/docker-compose.override.yml build
docker compose -p sql-injection -f secure/backend/docker-compose.yml -f secure/backend/docker-compose.override.yml up --force-recreate