# AppSec Labs

This repository contains hands-on labs demonstrating common application security vulnerabilities, their exploitation, and secure remediation. Labs are organized by OWASP Top 10 categories and additional custom scenarios.

## Structure

Each folder typically includes:

- `insecure/`: vulnerable version of the app
- `secure/`: remediated version
- `README.md`: Explanation of the vulnerability, how it works, and how it's fixed

---

## Completed Labs
| Lab | OWASP Category | Skills Demonstrated |
| --- | -------------- | ------------------- |
| [Missing Function Level Access Control](./owasp-top-10-2021/a01-broken-access-control/missing-function-level-access-control/README.md) | A01: Broken Access Control | AppSec, Access Control, Secure Coding, Exploitation & Remediation |

---

## Quick Start

Run the featured vulnerable lab locally using Docker:

```bash
git clone https://github.com/paulburkinshaw/appsec-labs.git
cd appsec-labs/owasp-top-10-2021/a01-broken-access-control/missing-function-level-access-control  

./compose-up-insecure.sh   # Linux/macOS
# or
compose-up-insecure.bat    # Windows
```

- App will be available at: **http://localhost:5082**
- A **login dropdown** selection will appear on load.

To run the secure (remediated) version, replace insecure with secure in the script name.