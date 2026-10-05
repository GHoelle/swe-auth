# Security

## What this project is

A portfolio project, written to learn how authentication is built correctly and to be able to
explain those decisions. It is **not production software**, it has never been deployed, and it is
not feature-complete — rate limiting, CSRF tokens, email verification, password reset and MFA are
all still on the roadmap in [README.md](README.md#known-gaps-tracked).

Do not use it to protect real accounts in its current state.

## Reporting a flaw

If you spot a vulnerability or a mistake in the security reasoning, I would genuinely like to know —
being corrected is the point of building this in public.

- **Ordinary bugs and design critiques:** open a GitHub issue.
- **Something you would rather not post publicly:** use GitHub's private vulnerability reporting on
  the Security tab of this repository.

There is no bug bounty.

## Scope

In scope: anything in `app/`, the database schema in `db/`, the Docker and Compose configuration,
and the CI workflow. Gaps already listed in the README's known-gaps table are known rather than
findings, though a note that one of them is worse than documented is very welcome.

Out of scope: the absence of features listed as Phase 2, 3 or 4 work.

## How security is checked today

- 169 tests asserting security behavior, run in CI on every push against real PostgreSQL and Redis.
  CI fails if any test is skipped, so a passing badge means the full suite ran.
- `ruff` with the flake8-bandit (`S`) rules, including `S608`, which rejects SQL built by string
  formatting. An AST test independently asserts that every `execute()` call receives a literal SQL
  string.
- An independent adversarial review of Phase 1 produced six findings, all fixed, each with a
  regression test confirmed to fail against the old code.
- Dependencies are pinned to exact versions and monitored by Dependabot. Hash-locking is Phase 4.
