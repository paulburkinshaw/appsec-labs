dotnet build insecure/backend/Secure.sln

start dotnet run --project ..\..\..\shared\appsec-labs-idp\Authentication.API
start dotnet run --project secure\backend\src\Secure.API
start dotnet run --project secure\backend\src\Secure.Web