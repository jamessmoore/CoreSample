# Contributing

Thanks for your interest in this project. It's currently maintained solo by James Moore, with Claude (Anthropic) used as a development collaborator — see [CONTRIBUTORS.md](CONTRIBUTORS.md) for details on how AI tooling is used here.

## Current Status

This is an actively developed solo project. There's no formal contribution process yet, but the guidelines below will apply once outside contributions are accepted.

## How to Contribute

1. **Open an issue first** for anything beyond a trivial fix (typos, broken links, small docs corrections). This avoids duplicate work and lets us agree on approach before you write code.
2. **Fork the repo** and create a feature branch off `main`:
   ```bash
   git checkout -b fix/short-description
   ```
3. **Keep PRs focused.** One fix or feature per PR. Large, multi-purpose PRs are harder to review and more likely to get bounced back.
4. **Write clear commit messages.** Imperative mood, short summary line, body if needed:
   ```
   Fix EC2 audit security group port-range parsing
   ```
5. **Include tests where applicable.** If you're fixing a bug, a regression test is appreciated. If you're adding a feature, basic coverage is expected.
6. **Update documentation** if your change affects setup, configuration, or usage.

## Code Style

- Match the existing style/formatting conventions already in the codebase.
- Prefer clarity over cleverness — this codebase favors readable, maintainable code over dense one-liners.
- Run any linters/formatters configured in the repo before submitting.

## Pull Request Process

1. Ensure your branch is up to date with `main` before opening the PR.
2. Describe **what** changed and **why** in the PR description — link the related issue if one exists.
3. Be responsive to review feedback. PRs that go stale without updates may be closed.
4. One approval from the maintainer is required before merge.
5. The `test` CI check (lint/tests/`terraform validate` — see `.github/workflows/test.yml`) must pass before merge. `main` is protected: no direct pushes, no force-pushes, no bypassing the PR requirement, even for repo admins.

## Reporting Bugs

Open an issue with:
- A clear, descriptive title
- Steps to reproduce
- Expected vs. actual behavior
- Environment details (OS, version, relevant config) if relevant

## Code of Conduct

Be respectful and constructive. Disagreements about technical approach are fine and expected — personal attacks or bad-faith engagement are not.

---

Questions? Open an issue or reach out via [webtechhq.com](https://webtechhq.com).
