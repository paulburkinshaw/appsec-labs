#!/bin/sh

dotnet build secure/backend/Secure.sln
docker compose -f secure/backend/docker-compose.yml -f secure/backend/docker-compose.override.yml build
docker compose -p missing_function_level_access_control_secure -f secure/backend/docker-compose.yml -f secure/backend/docker-compose.override.yml up --force-recreate