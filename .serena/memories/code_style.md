# Code Style and Conventions

- **Naming Conventions:**
  - **Classes:** `PascalCase` (e.g., `KeGen`, `PaddedRSA`).
  - **Methods:** `camelCase` (e.g., `getPrivateKey`, `encrypt`).
  - **Variables:** `camelCase` (e.g., `keyPair`, `originalMessage`).
- **Comments:**
  - Single-line comments are used to explain specific code sections.
- **Formatting:**
  - **Indentation:** Tabs are used.
  - **Braces:** Opening braces are placed on the same line as the class or method declaration.
  - **Spacing:** Code is well-formatted with whitespace for readability.
- **Error Handling:**
  - Errors are printed to the standard error stream using `System.err.println`.
  - The application exits with a non-zero status code on error.