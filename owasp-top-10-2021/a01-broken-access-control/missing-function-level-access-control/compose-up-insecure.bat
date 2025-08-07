dotnet build insecure/backend/Insecure.sln
docker compose -f ../../../shared/appsec-labs-idp/docker-compose.yml -f ../../../shared/appsec-labs-idp/docker-compose.override.yml build
docker compose -f insecure/backend/docker-compose.yml -f insecure/backend/docker-compose.override.yml build
docker compose -p missing_function_level_access_control_insecure -f ../../../shared/appsec-labs-idp/docker-compose.yml -f ../../../shared/appsec-labs-idp/docker-compose.override.yml -f insecure/backend/docker-compose.yml -f insecure/backend/docker-compose.override.yml up --force-recreate