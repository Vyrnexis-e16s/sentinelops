# Contributing

Thanks for wanting to poke at this. A few things before you open a PR.

## Ground rules

- One logical change per PR. A "refactor + feature + lint fix" PR is three PRs.
- New code needs tests. The exception is throwaway scripts under `ml/notebooks/`.
- Run `make lint test` before you push. CI will catch you if you don't.
- Don't add runtime dependencies without justifying them in the PR description. Each one is a future pin to update.

## Setup

See the `Developing without Docker` section of the [README](README.md). If anything in those instructions is wrong on your OS, that's itself a good first PR.

## Style

- Python: `ruff` + `black` + `mypy --strict` on the modules that have type hints landed. New modules should be strict from day one.
- TypeScript: `eslint` + `prettier` + `tsc --noEmit`. No `any` without a `// eslint-disable-next-line` and a comment explaining why.
- Commits: imperative mood, under ~72 chars for the summary, wrap the body at 100. If the PR has a theme, squash to one commit on merge.

## What I'm especially happy to take

- New SIEM detection rules (see `backend/app/modules/siem/rules/`).
- Additional CPE matchers in the recon CVE lookup.
- Bug fixes in the Vault audit-log chain verifier.
- UI polish that makes the 3D scenes more accessible (reduced-motion support, better contrast).

## What I'm less likely to accept

- New modules. Four is already a lot. If there's a compelling case, open an issue first.
- Major framework swaps (e.g., "rewrite the backend in Go"). The stack is intentional.
- Drive-by formatting PRs that touch files unrelated to a behaviour change.

## Security issues

See [SECURITY.md](SECURITY.md). Don't file them here.
