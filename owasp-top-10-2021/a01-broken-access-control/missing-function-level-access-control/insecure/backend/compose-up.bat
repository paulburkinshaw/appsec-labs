dotnet build Insecure.sln
docker compose -f ../../../../../shared/appsec-labs-idp/docker-compose.yml build
docker compose -f docker-compose.yml build
docker compose -p missing_function_level_access_control_insecure -f ../../../../../shared/appsec-labs-idp/docker-compose.yml -f docker-compose.yml up --force-recreate