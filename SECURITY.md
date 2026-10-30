# Security policy

YorvoGate stands between its clients and root on the machine, so we treat reports about it with priority.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions or pull requests.**

Report them privately through GitHub instead:

1. Go to the [Security tab](https://github.com/yorvolabs/yorvogate/security) of this repository.
2. Click **Report a vulnerability**.
3. Describe the issue. Include as much of the following as you can:
   - the version (`yorvogate version`) or commit, and Docker's version;
   - the listener's mode and the relevant part of the configuration or scope;
   - the request (method, path, body) that gets through, or steps to reproduce;
   - the impact: what a client reaches that its policy should have refused.

Only the maintainers can see your report.

## What happens next

- We acknowledge your report within **3 working days**.
- We confirm or rule out the issue, and keep you updated while we work on a fix.
- We aim to release a fix within **90 days** of the report, much sooner for anything that gets a scoped client to the host or to another scope.
- Once a fix is released, we publish a security advisory with a CVE ID, and credit you unless you prefer to stay anonymous.

Please give us a reasonable chance to fix the issue before you disclose it publicly.

## Supported versions

YorvoGate is in early development and hasn't had a release yet. Until 1.0, security fixes go only into the latest code on the `main` branch.

## Scope

What YorvoGate is meant to hold, and what it isn't, is in [docs/threat-model.md](docs/threat-model.md): a way through a scoped listener's policy is a vulnerability; what a trusted listener allows is its configuration.

Vulnerabilities in Docker, runc or the kernel should be reported to those projects. If you're not sure where an issue belongs, report it here and we'll help route it.
