# Contributing to SimpleSAMLphp Module OIDC

Thank you for your interest in contributing to `simplesamlphp-module-oidc`!

## Target Branch

Open pull requests against the `master` branch, which tracks the currently released version.

## Development & Quality Checks

Before submitting a Pull Request, please make sure your changes adhere to the project's coding standards and pass all automated checks:

1. **Line Endings:** Use Unix-style LF (`\n`) line endings across all files.
2. **Quality & Test Suite:** Run the pre-commit suite defined in `composer.json`:

   ```bash
   composer pre-commit
   ```

   This executes:
   * **PHP_CodeSniffer** (`vendor/bin/phpcbf` and `vendor/bin/phpcs`)
   * **Psalm** (`vendor/bin/psalm`)
   * **PHPUnit** (`vendor/bin/phpunit`)

   `phpcbf` fixes coding-standard violations in place. If it changes any files, review the changes and run the command again until it passes.

3. **Targeted Tests:** You can also run unit and integration suites separately:

   ```bash
   composer unit-tests
   composer integration-tests
   ```

   The integration tests start their dependencies in containers (Testcontainers), so they need a running Docker daemon.

## Reporting Security Vulnerabilities

Please do not report security vulnerabilities in public issues or pull requests. Report them privately through [GitHub's private vulnerability reporting](https://github.com/simplesamlphp/simplesamlphp-module-oidc/security/advisories/new) for this repository instead.

## AI-Assisted Contributions Policy

We welcome the responsible use of Large Language Models (LLMs) and AI coding assistants, provided that **human accountability** and **transparency** are maintained.

### 1. Human Accountability

* **You are the author:** The human contributor bears 100% responsibility for the correctness, licensing compliance, and security of the submitted code.
* **Understand what you submit:** Because this module implements security-critical authentication and authorization protocols (OAuth 2.0 / OpenID Connect), you must personally review, test, and understand every line of code in your contribution. Unverified or unreviewed AI-generated pull requests will be closed.

### 2. Mandatory Disclosure

If AI tools materially assisted with your contribution (for example: drafting code, writing unit/integration tests, refactoring, or automated code reviews whose findings you acted on—beyond basic single-line IDE autocomplete), you must disclose their use.

#### In Commit Messages (Preferred)

Include one or more `Assisted-by:` trailers at the bottom of your commit message specifying the tool, the model (its exact identifier, as the tool reports it), and optionally the scope of assistance:

```text
Assisted-by: <Tool Name> (<Model ID>, <optional scope>)
```

Examples:

```text
Assisted-by: Claude Code (claude-opus-5-5, implementation & unit tests)
Assisted-by: OpenAI Codex (gpt-6.1-sol, xhigh review)
Assisted-by: Google Antigravity (gemini-3.8-flash-high, review)
```

#### In Pull Requests

Fill out the **AI Usage Disclosure** section in the Pull Request template when opening a PR (especially if you did not include `Assisted-by:` trailers in individual commits).

### 3. Avoid `Co-Authored-By:` for AI Tools

Please **do not** use `Co-Authored-By:` (e.g., `Co-Authored-By: ... <noreply@...>`) or `Reviewed-by:` trailers for AI models. In Git history, authorship and formal review sign-off are reserved for human contributors; use `Assisted-by:` instead to record AI tool provenance.
