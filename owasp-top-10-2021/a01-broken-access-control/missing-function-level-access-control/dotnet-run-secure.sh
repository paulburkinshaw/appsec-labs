#!/bin/bash

dotnet build insecure/backend/Secure.sln &
dotnet run --project ..\..\..\shared\sappsec-labs-idp\Authentication.API &
dotnet run --project secure/backend/src/Secure.API &
dotnet run --project secure/backend/src/Secure.Web &