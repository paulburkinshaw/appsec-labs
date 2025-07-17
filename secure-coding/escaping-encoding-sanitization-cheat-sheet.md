# Escaping, Encoding, and Sanitization Cheat Sheet

## Table Of Contents
<details>
<summary>Show</summary>

- [Escaping, Encoding, and Sanitization Cheat Sheet](#escaping-encoding-and-sanitization-cheat-sheet)
  - [Table Of Contents](#table-of-contents)
  - [Intro](#intro)
  - [Rule of Thumb](#rule-of-thumb)
  - [Common Contexts](#common-contexts)
  - [Practical Scenarios](#practical-scenarios)
  - [Common Escaping/Encoding Functions](#common-escapingencoding-functions)
  - [Further Reading](#further-reading)

</details>

## Intro
This cheat sheet serves as a quick reference for **escaping** and **encoding** with examples and suggestions for common contexts — including what to do when you need to handle or strip unsafe input (e.g., script tags, dangerous characters, or injection vectors).

> **Note:** This guide is a starting point and should not be used as a substitute for context-aware security controls. Every situation is subtly different. Always validate your approach based on the environment, data flow, and interpreter.

## Rule of Thumb
Escaping and encoding often work **hand-in-hand**:
- **Escape** input when building queries, scripts, or code
- **Encode** output when sending data to browsers, networks, or APIs
- **Escape** when inserting data *into code* (e.g., JavaScript, SQL, Bash).
- **Encode** when outputting data *into markup or protocols* (e.g., HTML, URL, XML).
- Always consider the **target interpreter or consumer**:  
  Is it a **code parser**? Escape.  
  Is it a **browser, server, or transport protocol**? Encode.

## Common Contexts

| Execution Context | Input Example                 | Escaping                  | Output Encoding                   | Sanitization                                     |
|-------------------|-------------------------------|---------------------------|-----------------------------------|--------------------------------------------------|
| JavaScript        | `'` inside `'`-quoted string  | `\'`                      | N/A (JS strings aren't "encoded") |                                                  |
| SQL               | `O'Reilly`                    | `O\'Reilly`               | N/A                               |                                                  |
| HTML              | `<div>`                       | N/A                       | `&lt;div&gt;`                     | Remove or allow via safe list (e.g., DOMPurify)  |
| URL               | `hello world`                 | N/A                       | `hello%20world`                   |                                                  |
| JSON              | newline                       | `\n`                      | N/A (already escaped)             |                                                  |
| Shell/Bash        | file name with space          | `my\ file.txt`            | `my%20file.txt` (for URLs)        |                                                  |

## Practical Scenarios
Todo add scenarios such as "display script tags on a web page", "remove script tag from user input etc"

| Scenario                                 | Raw Input                       | Escaping                    | Output Encoding                         | Sanitization                                                  |
|------------------------------------------|---------------------------------|-----------------------------|-----------------------------------------|---------------------------------------------------------------|
| Display script tags in a web page        | `<script>alert(1)</script>`     | N/A                         | `&lt;script&gt;alert(1)&lt;/script&gt;` |                                                               |
| Prevent SQL injection                    | `Robert'); DROP TABLE users;--` | `Robert\'); DROP...`        | N/A                                     |                                                               |
| Embed user comment in HTML               | `5 > 3 && 3 < 7`                | N/A                         | `5 &gt; 3 &amp;&amp; 3 &lt; 7`          |                                                               |
| Pass data in a URL query string          | `name=John & Jane`              | N/A                         | `name=John%20%26%20Jane`                |                                                               |
| Store Unicode safely in a JS string      | `© 2025`                        | `\u00A9 2025`               | N/A                                     |                                                               |
| Display JSON safely inside HTML          | `{"name": "O'Reilly"}`          | N/A                         | `&#123;&quot;name&quot;:...&#125;`      |                                                               |
| Escape Bash argument with spaces         | `My File.txt`                   | `My\ File.txt`              | N/A                                     |                                                               |
| Strip `<script>` from user input         | `<script>alert('x')</script>`   | N/A                         | N/A                                     | `alert('x')` (using a sanitizer like DOMPurify, bleach, etc.) |

## Common Escaping/Encoding Functions

| Language | Escape Function                  | Encode Function                   | Sanitization                            |
|----------|----------------------------------|-----------------------------------|-----------------------------------------|
| JS       | `JSON.stringify()`, `replace()`  | `encodeURIComponent()`            | `DOMPurify.sanitize()`                  |
| Python   | `re.escape()`, `html.escape()`   | `urllib.parse.quote()`            | `bleach.clean()`                        |
| PHP      | `addslashes()`                   | `htmlspecialchars()`              | `HTMLPurifier`                          |
| Bash     | `printf %q`                      | N/A                               |  N/A                                    |

---

## Further Reading
> See [Validation, Escaping, Encoding, and Sanitization](./validation-escaping-encoding-sanitization.md) for detailed explanations and examples.

---