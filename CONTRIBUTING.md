# Contributing to MCP Gate

Thank you for your interest in contributing to MCP Gate!

## Developer Certificate of Origin (DCO)

All contributions to this project **must** be signed off under the
[Developer Certificate of Origin v1.1](https://developercertificate.org/).

By adding a `Signed-off-by` line to your commit messages you certify that:

1. The contribution was created in whole or in part by you and you have the
   right to submit it under the AGPL-3.0-or-later license; or
2. The contribution is based upon previous work that, to the best of your
   knowledge, is covered under an appropriate open-source license and you have
   the right to submit that work with modifications under the same license; or
3. The contribution was provided directly to you by some other person who
   certified (1) or (2) and you have not modified it.

### How to sign off

Use `git commit -s` (or `git commit --signoff`):

```
git commit -s -m "fix: correct approval routing logic"
```

This appends a trailer like:

```
Signed-off-by: Your Name <your.email@example.com>
```

**Pull requests without a valid `Signed-off-by` on every commit will not be
merged.**

## Contribution Agreement

By submitting a pull request you agree that:

- Your contribution is licensed under **AGPL-3.0-or-later**, the same license
  as the project.
- You grant the project maintainer (Sergej Napalkov) a perpetual,
  irrevocable, worldwide, royalty-free license to use, modify, sublicense,
  and relicense your contribution as part of MCP Gate or any successor
  project. This clause exists solely to allow potential future relicensing
  (e.g., from AGPL to Apache-2.0) without needing to contact every past
  contributor.
- You represent that you are legally entitled to grant the above license.
- You understand that your contribution is public and that a record of it
  (including your sign-off and personal information) is maintained
  indefinitely.

## Code Style

- Python: follow existing patterns, use type hints where practical.
- Commit messages: use [Conventional Commits](https://www.conventionalcommits.org/) format.
- One logical change per commit.

## Reporting Issues

Open an issue on GitHub. Include:
- MCP Gate version (`/api/health` → `version` field)
- Steps to reproduce
- Expected vs. actual behavior
- Relevant logs (redact secrets!)

## Security Vulnerabilities

**Do NOT open a public issue.** See [SECURITY.md](SECURITY.md) for responsible
disclosure instructions.
