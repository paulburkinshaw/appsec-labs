#!/bin/bash

dotnet build insecure/backend/Insecure.sln &
dotnet run --project insecure/backend/src/Insecure.API &
dotnet run --project insecure/backend/src/Insecure.Web &