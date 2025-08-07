# Missing Function Level Access Control

## Table of Contents
<details>
<summary>Show</summary>

- [Missing Function Level Access Control](#missing-function-level-access-control)
  - [Table of Contents](#table-of-contents)
  - [Summary](#summary)
  - [Lab Application](#lab-application)
    - [Application Flow](#application-flow)
  - [Security Requirements](#security-requirements)
  - [Insecure Version](#insecure-version)
    - [Vulnerability](#vulnerability)
    - [Exploiting Vulnerability](#exploiting-vulnerability)
  - [Secure Version](#secure-version)
  - [Running the Lab](#running-the-lab)
    - [Prerequisites](#prerequisites)
    - [Docker CLI](#docker-cli)
    - [Docker in Visual Studio](#docker-in-visual-studio)
    - [Visual Studio (without Docker)](#visual-studio-without-docker)
    - [.NET CLI](#net-cli)
      - [Windows](#windows)
      - [Linux/macOS](#linuxmacos)
  - [Further Enhancements](#further-enhancements)
  - [Disclaimer](#disclaimer)
  - [References](#references)
    - [Links](#links)

</details>

## Summary
Missing function level access control occurs when an application fails to properly restrict access to certain functions based on user roles or permissions. In other words, users—whether logged in or not—can access functions or endpoints they should not be able to reach. This oversight can allow unauthorized users to perform privileged actions, access sensitive data, or even take control of critical parts of the application.

## Lab Application
The example app is made up of: 
- An ASP.NET Core Web API app with two endpoints: `user/dashboard` and `admin/dashboard`.
- An ASP.NET Core Web App that displays a simple dropdown selection with login button that allows selection between a basic user and an admin user. Once authenticated, a dashboard page is displayed with data from either the `user/dashboard` endpoint, or `admin/dashboard` endpoint depending on which user was selected.
- An ASP.NET Core Web API authentication app with a `/login` endpoint used to simulate login functionality [[1]](#references). 
  
### Application Flow
- Selecting a user from the login dropdown sends a request to the authentication app's `/login` endpoint. 
- An access token is returned from the `/login` endpoint which contains either a `User` or `Admin` role claim. 
- The access token is used in a request to either `user/dashboard` or `admin/dashboard` depending on the role claim.
- The data in the response to `user/dashboard` or `admin/dashboard` is displayed on a dashboard page.
 
## Security Requirements
1. The `user/dashboard` can be accessed by any logged in user. 
2. The `admin/dashboard` should only be accessible to an admin user only.
3. Neither `user/dashboard` or `admin/dashboard` should be accessible to anonymous users.

## Insecure Version 
In the insecure version the two endpoints have been secured with a basic level of authorization -  only authenticated users are allowed to execute the endpoints. This has been implemented by decorating the controller actions with the `Authorize` attribute: 

```C#
 [Authorize]
 [HttpGet("/admin/dashboard")]
 public Dashboard GetAdminDashboard()
 {
     return new Dashboard
     {
         WorkItems = [
         "Admin Work Item 1",
         "Admin Work Item 2",
         "Admin Work Item 3"
         ]
     };
 }

 [Authorize]
 [HttpGet("/user/dashboard")]
 public Dashboard Get()
 {
     return new Dashboard
     {
         WorkItems = [
         "Work Item 1",
         "Work Item 2",
         "Work Item 3"
         ]
     };
 }
```

### Vulnerability
With the `[Authorize]` attribute applied, if an anonymous user makes a request to `user/dashboard` or `admin/dashboard`, a `401 Unauthorized` response will be returned. However, although the Insecure.Web app does not directly allow a basic user to view the admin dashboard, there is nothing stopping them from calling the admin/dashboard endpoint directly.
This can be done by simply making a **GET** request to the endpoint via cURL, or using an API testing tool like Postman.

### Exploiting Vulnerability
1. Ensure all the individual apps are running (see the [Running the Lab](#running-the-lab) section below)
2. Open a browser and navigate to `http://localhost:5082`
3. Select User 1 from the dropdown and click the Login button.
    <details>
    <summary>Show screenshot</summary>
    <img src="./images/insecure1-login.png" alt="" width="100%"/>
    </details>
4. Copy the query string value from the browser address bar (everything after `http://localhost:5082/Dashboard?jwt=`).
    <details>
    <summary>Show screenshot</summary>
    <img src="./images/insecure2-token-querystring.png" alt="" width="100%"/>
    </details>
5. Open a command window and execute: `curl --location "http://localhost:5059/user/dashboard" --header "Authorization: Bearer [jwt]"` replacing `[jwt]` with the token you copied above. You should get the dashboard items for a basic user which is expected and the same data you get when logging in to the web app.
    <details>
    <summary>Show screenshot</summary>
    <img src="./images/curl-request-user-dashboard.png" alt="" width="100%"/>
    </details>
6. Execute the cURL command again with the same jwt but this time update the URL to point to the `admin/dashboard` endpoint: `curl --location "http://localhost:5059/admin/dashboard" --header "Authorization: Bearer [jwt]"`. You should now get the dashboard items for the admin user which is obviously not desirable and violates the [2nd Security requirement](#security-requirements): **The `admin/dashboard` endpoint should only be accessible to an admin user.**
    <details>
    <summary>Show screenshot</summary>
    <img src="./images/curl-request-admin-dashboard.png" alt="" width="100%"/>
    </details>

---

## Secure Version
In the secure version of the app Claims-based authorization[[2]](#references) has been used to protect the `admin/dashboard` endpoint from being accessed by any user that doesn't have the `Admin` role claim. This has been implemented by applying the `IsAdmin` policy to the `GetAdminDashboard` action using the `Authorize` attribute.
```C#
 [Authorize(Policy = "IsAdmin")]
 [HttpGet("/admin/dashboard")]
 public Dashboard GetAdminDashboard()
 {
     return new Dashboard
     {
         WorkItems = [
         "Admin Work Item 1",
         "Admin Work Item 2",
         "Admin Work Item 3"
         ]
     };
 }
```

The policy has been configured in Program.cs as part of the call to `AddAuthorization()` in ConfigureServices.

```C#
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("IsAdmin", policyBuilder
        => policyBuilder.RequireClaim(ClaimTypes.Role, "Admin"));
});
```
This policy is used by the AuthorizationMiddleware to determine whether the user is allowed to execute the endpoint.
If the user is not authenticated, a **401 Unauthorized** response will be returned. If the user is authenticated but doesn't have the required claims, a **403 Forbidden** response will be returned.

>For production-grade security see the Further Enhancements section below. 
---

## Running the Lab
>Note: This lab is designed to run entirely on local machines. No internet access is required for its functionality once dependencies are installed.

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/en-us/download) or later
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- Visual Studio 2022+ (with Docker and ASP.NET Core workloads) — for Visual Studio scenarios

### Docker CLI
- Ensure you have [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.
- Open a terminal (Command Prompt on Windows or a shell on Linux/macOS) in [this](./) folder  
- Run `compose-up-insecure.bat` or `compose-up-secure.bat` on Windows  
- or `./compose-up-insecure.sh` or `./compose-up-secure.sh` on Linux/macOS
- Open a browser window and enter `http://localhost:5082` in the address bar.
- You should see a login dropdown selection. 

>This is the quickest way to get the app up and running, however if you would like to debug the app and step through the code see 
>- [Docker in Visual Studio](#docker-in-visual-studio) if you'd like to debug **and** run the apps in containers.
>- [Visual Studio](#visual-studio) if you'd just like to debug on your local host.

### Docker in Visual Studio
- Ensure you have [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.
- First start the **Authentication.API** app in a container by opening an instance of Visual Studio and clicking File/Open/Project/Solution and select the **Appsec-Labs-IDP.sln** located in the [**Authentication.API**](../../../shared/appsec-labs-idp/Authentication.API/) project folder.
- Ensure the docker-compose project is selected as the startup project (you’ll see it in bold in Solution Explorer). If not, right click on it and select Set as Startup Project.
- Press F5 to start up a container for the Authentication.API project in debugging mode (or click the green debug button).
- Next start the Insecure/Secure API and Web apps in containers by opening another instance of Visual Studio and clicking File/Open/Project/Solution and select either **Insecure.sln** or **Secure.sln** located in [/insecure/backend/](./insecure/backend/) or [/secure/backend/](./secure/backend/) depending on which version of the app you'd like to run.
- Ensure the docker-compose project is set as the startup project as above and press F5 to start up containers for the web api and web app projects in debugging mode (or click the green debug button).
- You should see a login dropdown selection. 

### Visual Studio (without Docker)
- First start the **Authentication.API** app by opening an instance of Visual Studio and clicking File/Open/Project/Solution and select the **Appsec-Labs-IDP.sln** located in the [**Authentication.API**](../../../shared/appsec-labs-idp/Authentication.API/) project folder.
- Press F5 to start the Authentication.API project in debugging mode (or click the green debug button).
- Next start the Insecure/Secure API and Web apps by opening another instance of Visual Studio and clicking File/Open/Project/Solution and select either **Insecure.sln** or **Secure.sln** located in [/insecure/backend/](./insecure/backend/) or [/secure/backend/](./secure/backend/) depending on which version of the app you'd like to run.
- With the solution open in Visual Studio, right click on the Solution node in Solution Explorer and select **Configure Startup Projects**
- Click on Multiple startup projects.
- Select Start from the Action dropdown for the two projects and click Apply.
- Click Yes when prompted to save the changes.
- Press F5 to start running both projects in debugging mode (or click the green run button).
- Open a browser window and enter `http://localhost:5082` in the address bar.
- You should see a login dropdown selection. 

### .NET CLI
You can run the applications using the .NET CLI without an IDE or Docker:

#### Windows
Open a Command Prompt or Powershell window in [this](./) folder  
Then run either: 
```cmd
dotnet-run-insecure.bat
```
or 
```
dotnet-run-secure.bat
```

#### Linux/macOS
Open a terminal in [this](./) folder    
Then run either:
```bash
./dotnet-run-insecure.sh
```
 or 
 ```bash
 ./dotnet-run-secure.sh
 ```  
 Make sure the .sh files are executable:  
 ```bash
chmod +x dotnet-run-insecure.sh dotnet-run-secure.sh
 ```
 
Each app will be launched in its own terminal window (or background process), allowing you to observe each service independently.

## Further Enhancements

> **Cryptographic Key Storage:**  
> For demonstration purposes, cryptographic keys are generated and stored in configuration.  
> **In production, always use a secure key vault (such as Azure Key Vault or AWS KMS) and protect key management/rotation with strict access control.**  

> **Logging & Monitoring:**  
> Sensitive endpoints (such as key rotation) should be logged and monitored for unauthorized access attempts.  
> This helps detect and respond to potential security incidents.

## Disclaimer  
>This application is for demonstration and educational purposes only.    
>Do not use these patterns as-is in production.

## References
[1]: Login functionality has been implemented as a simple dropdown selection with login button with two users (a basic user and an admin user) hard coded in the Authentication.API app. It has been implemented this way in order to show how the app functions when logging in as different users without needing a complete identity provider solution.

[2]: Claims-based authorization uses the current user’s claims to determine access rights. Policies define which claims are required to execute specific actions. Claims-based authorization enforces access control at the function level, not just authentication. This ensures that only users with the correct role or permission can access sensitive endpoints, reducing the risk of privilege escalation. This approach aligns with [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) controls for access control and key management

### Links
- [OWASP Top 10 link](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- External links for further reading
