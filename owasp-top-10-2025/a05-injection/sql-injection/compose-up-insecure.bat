dotnet build insecure/backend/Insecure.sln
docker compose -f insecure/backend/docker-compose.yml -f insecure/backend/docker-compose.override.yml build
docker compose -p sql-injection -f insecure/backend/docker-compose.yml -f insecure/backend/docker-compose.override.yml up --force-recreate