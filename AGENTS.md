# Repository Contribution Contract

## Git identity and commit subjects

All repository commits must use:

`BackRunner <dev@backrunner.top>`

Commit subjects must use the exact lower-case form `xxx(comp): desc`:

- `xxx` is a short lower-case type such as `feat`, `fix`, `docs`, `test`, `build`, `security`, or `refactor`.
- `comp` is the affected lower-case component.
- `desc` is a concise English description with no trailing period or newline.

Before committing, inspect the staged diff for secrets, generated files, unrelated formatting churn, and unsupported product claims.

## Open-source repository

The canonical repository is the public GitHub repository `backrunner/maskman`.
It is licensed under Apache License 2.0. Do not commit private keys, bearer
secrets, development certificates, local environment files, build output,
coverage output, or release signing material; the root `.gitignore` covers
these classes of files.

## Engineering guard

Maskman protocol, security, platform, configuration, update, release, and
commit changes must follow `.agents/skills/maskman-guard/SKILL.md` and its
checklist. The guard's hard stops and verification gates are part of this
repository contract.
