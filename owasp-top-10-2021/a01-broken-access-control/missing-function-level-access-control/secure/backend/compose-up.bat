dotnet build Secure.sln
docker compose -f ../../../../../shared/appsec-labs-idp/docker-compose.yml -f ../../../../../shared/appsec-labs-idp/docker-compose.override.yml build
docker compose -f docker-compose.yml -f docker-compose.override.yml build
docker compose -p missing_function_level_access_control_secure -f ../../../../../shared/appsec-labs-idp/docker-compose.yml -f ../../../../../shared/appsec-labs-idp/docker-compose.override.yml -f docker-compose.yml -f docker-compose.override.yml up --force-recreate