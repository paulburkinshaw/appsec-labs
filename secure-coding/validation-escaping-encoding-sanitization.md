# Validation, Escaping, Encoding, and Sanitization

## Table of Contents
<details>
<summary>Show</summary>

- [Validation, Escaping, Encoding, and Sanitization](#validation-escaping-encoding-and-sanitization)
  - [Table of Contents](#table-of-contents)
  - [Validation](#validation)
    - [Validation Types](#validation-types)
  - [Sanitization](#sanitization)
  - [Escaping](#escaping)
    - [Control Characters](#control-characters)
    - [Programming Context](#programming-context)
    - [More Escaping in Programming Examples](#more-escaping-in-programming-examples)
    - [Security Context](#security-context)
    - [More Escaping in Security Examples](#more-escaping-in-security-examples)
    - [When to use Escaping](#when-to-use-escaping)
  - [Encoding](#encoding)
  - [Comparing Escaping and Encoding](#comparing-escaping-and-encoding)
    - [Key Traits](#key-traits)
    - [Key differences](#key-differences)
  - [Summary - Validate First, Sanitize If You Must, Escape When Needed, Encode Always](#summary---validate-first-sanitize-if-you-must-escape-when-needed-encode-always)
  - [Further Reading](#further-reading)

</details>  

## Validation

Validation is your **first line of defense**. It ensures that incoming data conforms to expected formats before it is processed, stored, or rendered.

### Validation Types
- **Type checking**: Is it a number? A string?
- **Format checking**: Does it match a pattern? (e.g., email regex)
- **Value checking**: Is it in the allowed range or set?

Validate on both client and server — but **never trust client-side validation alone.**

## Sanitization

Sanitization means **cleaning** input by removing, modifying, or neutralizing unwanted or potentially harmful content. It’s used when you **can’t strictly validate** all input, especially in use cases where users are allowed to submit *some* HTML, formatting, or rich text.

For example we might employ sanitization to:
- Remove potentially dangerours tags such as `<script>` from user-submitted comments or posts that may include HTML.
- Sanitize rich text fields where some tags are allowed (`<b>`, `<i>`, `<ul>`).
- Clean up filenames or user-generated data before saving.

Sanitize *before* storing or rendering, but still encode *before* output — sanitization is not a replacement for output encoding.

## Escaping
The term "escaping" can be used in two opposite ways, depending on context:

- Programming languages use escape sequences to represent special behaviors (e.g., `\n`, `\t`, `\\`) in source code.
- Security contexts (e.g., SQL, HTML) use escaping to neutralize behavior — so special characters such as `<` `>` become harmless text.

So escaping can either:
- Introduce control behavior (like newline via `\n`) — programming
- Cancel control behavior (like `'` via `\'`) — security/syntax preservation

### Control Characters
Control characters are characters that do not represent a printable symbol, but instead instruct the system to perform some action. They originated from typewriters and teletypes.
They are used as in-band signaling to cause effects other than the addition of a symbol to the text

### Programming Context
An escape sequence, in computing, is a combination of characters that has a meaning other than the literal characters contained therein.  

For example, we can use the **Newline** escape sequence to insert a line break:  
`Some text.\nSome more text on a new line.`  

- The escape sequence (combination of characters) is `\n`.
- Its literal characters are a backslash and a lowercase letter "n".
- Together `\n` means: Insert a line break (newline character, ASCII code 10).
- So instead of printing `\n`, the system moves to a new line when it encounters this.

### More Escaping in Programming Examples
- `\\` — to insert a literal backslash
- `\'` — to insert a literal single quote
- `\"` — to insert a literal double quote
- `\t` — to insert a tab character
- `\u00A9` — Unicode escape for © symbol

### Security Context
Escaping in a security context means prefixing special characters with an escape character (often a backslash \) so that they are treated as literal characters, not as syntax or code.

For example, in SQL:
`SELECT * FROM users WHERE name = 'O\'Reilly';`  

Without escaping, the `'` inside the name would break the syntax.

Escaping in this context is about telling the interpreter/compiler:
>“This character is special — treat it as literal, not functional.”

In this sense, escaping removes the special powers of a character that would otherwise be interpreted by an interpreter (e.g., browser, SQL engine, JavaScript VM).

### More Escaping in Security Examples
- In JavaScript: `const s = 'It\'s working!';`
- In shell scripts: `rm file\ name.txt`
- In regex: `\.` — matches a literal dot instead of “any character”

### When to use Escaping

In **programming**, use escaping:
- To Insert control characters (e.g., `\n`, `\t`)
- To Write characters that would otherwise break string literals (e.g., `'`, `\`)
- When the context still interprets characters, but you want them to be treated as plain text.

In **security**, use escaping to:
- Prevent injection attacks (SQL, shell, etc.)
- Output user-generated data safely in contexts where special characters have meaning
- *Note: In web contexts, HTML/XML/URL escaping is more accurately called encoding, and requires different handling, for example `\<script>` does not escape `<`, but `&lt;` encodes it instead. (see Encoding below).*

---

## Encoding
Encoding means converting characters into a different representation, usually so they are safe to transmit, store, or render—without being interpreted as code or commands.

For example:  
- The `<` character in HTML becomes `&lt;`
- A space in a URL becomes `%20`
- The copyright symbol © becomes `\u00A9` in Unicode or `&copy;` in HTML

Encoding is about telling the system:  
>“This character must be translated to a different form so it can be safely stored, transmitted, or displayed.”

Use encoding when the output is going to a different format or protocol (e.g., HTML, URL, XML) and should never be interpreted as code.

---

## Comparing Escaping and Encoding

### Key Traits 

| Trait                                                  | Escaping                                             | Encoding                                                  |
|--------------------------------------------------------|------------------------------------------------------|-----------------------------------------------------------|
| Scope                                                  | Only special characters are escaped                  | Often many (or all) characters are encoded                |
| Representation                                         | Uses an escape sequence (e.g., `\n`, `\'`)           | Converts to a safe, format-specific representation        |
| Readability                                            | Still mostly human-readable                          | Often less readable (e.g., `%3C`, `&#60;`, `\u00A9`)      |
| Context-awareness                                      | Highly context-specific (e.g., SQL, JS)              | Highly format-specific (e.g., HTML, URL, Base64)          |
| Decoder required?                                      | Not always                                           | Yes — must be decoded to restore original data            |


### Key differences 
Escaping and encoding are both used to **safely handle special characters**, but they work differently and are used in different scenarios.

| Aspect            | Escaping                                             | Encoding                                               |
|------------------ |------------------------------------------------------|--------------------------------------------------------|
| Purpose           | Prevent interpretation by **neutralizing syntax**    | Prevent interpretation by **translating characters**   |
| Target audience   | Interpreters/compilers (e.g., JS engine, SQL parser) | Systems and protocols (e.g., browser, server, network) |
| Changes to data   | Only escapes certain characters                      | May encode entire data string                          |
| Reversible?       | Yes (removes escape character)                       | Yes (must be decoded with format-specific decoder)     |
| Common uses       | Prevent syntax breakage in code strings              | Prevent XSS, encode URLs, output HTML safely           |

---

## Summary - Validate First, Sanitize If You Must, Escape When Needed, Encode Always

Use a layered defense strategy to safely handle untrusted input and prevent injection vulnerabilities:

- **Input Validation**  
  Define and enforce what *should* be allowed. This might mean:
  - Letters only for names
  - Digits only for IDs
  - Allowed formats for emails or dates  
  Validation reduces the risk by rejecting dangerous input early.

- **Sanitization / Escaping**  
  If validation can’t reject all risky content — such as when accepting HTML or special characters — sanitize the input to remove or neutralize it.  
  Escaping may also be necessary when injecting data into interpreters (e.g., SQL, shell, regex) to ensure characters are treated as literals, not code.

- **Output Encoding**  
  Always encode untrusted data **just before output**, based on the context:
  - HTML entity encoding for HTML pages
  - URL encoding for query strings
  - JSON encoding for JavaScript
  Even if input is validated or sanitized, encoding prevents code execution at render time.

> **Layered Strategy Recap**  
> 1. **Validate** to reduce the attack surface  
> 2. **Sanitize or Escape** when risky characters must be allowed  
> 3. **Encode** before output to neutralize interpretation by the target context

[ User Input ]  
      ↓  
[ Validation ]  
      ↓  
[ Sanitization / Escaping ]  
      ↓  
[ Output Encoding ]  
      ↓  
[ Safe Display or Execution ]  

---

## Further Reading
> See [escaping and encoding cheat sheet](./escaping-and-encoding-cheat-sheet.md) for examples of when to use each.

---