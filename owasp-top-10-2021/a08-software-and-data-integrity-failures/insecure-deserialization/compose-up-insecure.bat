dotnet build insecure/backend/Insecure.sln
docker compose -f insecure/backend/docker-compose.yml -f insecure/backend/docker-compose.override.yml build
docker compose -p insecure-deserialization -f insecure/backend/docker-compose.yml -f insecure/backend/docker-compose.override.yml up --force-recreate