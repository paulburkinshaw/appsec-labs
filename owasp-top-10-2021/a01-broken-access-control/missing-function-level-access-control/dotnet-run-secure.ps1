dotnet build insecure/backend/Secure.sln
Start-Process "dotnet" "run --project secure\backend\src\Secure.API"
Start-Process "dotnet" "run --project secure\backend\src\Secure.Web"