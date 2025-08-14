dotnet build insecure/backend/Insecure.sln
Start-Process "dotnet" "run --project insecure\backend\src\Insecure.API"
Start-Process "dotnet" "run --project insecure\backend\src\Insecure.Web"