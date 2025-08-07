dotnet build insecure/backend/Insecure.sln

start dotnet run --project ..\..\..\shared\appsec-labs-idp\Authentication.API
start dotnet run --project insecure\backend\src\Insecure.API
start dotnet run --project insecure\backend\src\Insecure.Web