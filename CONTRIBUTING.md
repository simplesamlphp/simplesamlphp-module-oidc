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
   * **Rector** (`vendor/bin/rector`)
   * **PHP_CodeSniffer** (`vendor/bin/phpcbf` and `vendor/bin/phpcs`)
   * **Psalm** (`vendor/bin/psalm`)
   * **PHPUnit** (`vendor/bin/phpunit`)

   Rector and `phpcbf` rewrite files in place, so review their changes before you commit.

3. **Targeted Tests:** You can also run unit and integration suites separately:

   ```bash
   composer unit-tests
   composer integration-tests
   ```

   The integration tests start their dependencies in containers (Testcontainers), so they need a running Docker daemon.

4. **End-to-End Suites:** CI also runs the OpenID conformance suite and the proxied introspection harness on every push and pull request. Both need Docker; see [OpenID Conformance](docs/5-oidc-conformance.md) and [Using Docker](docs/4-oidc-docker.md) to run them locally. The harness has its own Composer script:

   ```bash
   composer harness-tests
   ```

## Reporting Security Vulnerabilities

Please do not report security vulnerabilities in public issues or pull requests. Report them privately through [GitHub's private vulnerability reporting](https://github.com/simplesamlphp/simplesamlphp-module-oidc/security/advisories/new) for this repository instead.

## AI-Assisted Contributions Policy

We welcome the responsible use of Large Language Models (LLMs) and AI coding assistants, provided that **human accountability** and **transparency** are maintained.

### 1. Human Review & Ownership

* **You own what you submit:** AI tools are assistants, not authors; you are the author of your contribution and remain accountable for it. Before opening a Pull Request, you are expected to personally review, test, and understand the changes you submit, and be prepared to explain or revise them during code review. Unreviewed AI-generated pull requests will be closed.
* **Security & protocol care:** Because this module implements security-critical authentication and authorization protocols (OAuth 2.0 / OpenID Connect), please pay extra attention to edge cases, cryptographic handling, and specification compliance when verifying AI-assisted code.
* **Licensing:** Contributions are accepted under the project's [MIT License](LICENSE). AI tools can reproduce existing code verbatim, so make sure everything you submit, whether written by hand or with a tool's help, is compatible with that license.

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
