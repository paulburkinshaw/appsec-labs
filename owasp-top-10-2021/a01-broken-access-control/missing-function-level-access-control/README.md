# Missing Function Level Access Control
Missing function level access control occurs when an application fails to properly restrict access to certain functions based on user roles or permissions. In other words, users—whether logged in or not—can access functions or endpoints they should not be able to reach. This oversight can allow unauthorized users to perform privileged actions, access sensitive data, or even take control of critical parts of the application.

## Example ASP.NET Core app
The example ASP.NET Core API app has two endoints: `Dasboard` and `AdminDashboard`

## Insecure Version 
In the [/Insecure](./Insecure/) folder is a 

### Exploitation

## Secure Version

### Remediation


## References
- [OWASP Top 10 link](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- External links for further reading
