---
name: maskman-guard
description: "Guard Maskman Rust protocol, security, platform, configuration, and release changes before implementation or commit."
---

# Maskman Guard

Use this skill for any Maskman implementation, code review, configuration schema change, protocol change, privilege/platform change, release/update change, or commit preparation.

## Required outcome

Keep the change small, auditable, and consistent with the Maskman implementation contract. The guard does not replace tests or a security review; it makes the relevant checks explicit and stops a change that silently expands the product profile.

## Workflow

1. Inspect the worktree and identify the affected boundary: protocol, server, config/CLI, platform, update, or docs.
2. Read the relevant reference before editing:
   - protocol or interoperability: .agents/01-research-and-scope.md
   - runtime/data path or module ownership: .agents/02-architecture.md and .agents/03-modules.md
   - TOML/JSON, CLI, service, or update: .agents/04-configuration-and-cli.md
   - authentication, authorization, packet filtering, privileges, or secrets: .agents/05-security.md
   - tests, CI, release, performance, or incident response: .agents/06-quality-and-release.md
   - scope or release planning: .agents/07-milestones.md
3. Preserve the HTTP/3-only v1 profile unless the user explicitly expands it. RFC 9484 means CONNECT-IP; CONNECT-UDP is RFC 9298. Do not claim HTTP/1.1 or HTTP/2 support without a separate completed profile and interoperability evidence.
4. Trace every untrusted input through length, syntax, semantic, authorization, and resource-limit checks. Never allow authentication or policy checks to happen after DNS, socket, TUN, firewall, or other expensive side effects.
5. Keep protocol code sans-I/O and keep h3/Quinn types behind the server transport adapter. Keep platform mutation inside the platform crate. Do not add a catch-all common, utils, or helpers module.
6. Add or update focused tests at the risk boundary. For protocol input, include malformed/truncated/unknown cases and a no-panic property or fuzz case where appropriate. For security or update changes, include negative tests and rollback/error paths.
7. Run the smallest meaningful verification before handing off: formatting, targeted tests, workspace tests when shared contracts change, and the skill validator when the skill itself changes.

## Hard stops

Stop and report the issue instead of weakening the requirement when a change:

- accepts unauthenticated proxying by default;
- allows localhost, private, link-local, multicast, broadcast, or management destinations without an explicit policy;
- forwards an IP packet without per-session source and scope checks;
- parses attacker-controlled capsule lengths with an unbounded allocation;
- introduces unbounded queues, per-packet task spawning, or secret-bearing logs;
- mutates system routes, TUN, NAT, service files, or privileges outside a journaled platform boundary;
- installs an update without independent signature verification and a tested rollback path;
- introduces a file over 500 lines or a function over roughly 60 lines without an explicit ownership reason;
- uses a commit subject that does not match xxx(comp): desc or uses an identity other than BackRunner <dev@backrunner.top>.

## Commit gate

Before committing, check the diff for generated files, secrets, unrelated formatting churn, and claims that are not backed by tests. Use one concise lower-case subject such as fix(protocol): reject truncated route capsule; do not put a period or newline in the subject. Set the author and committer identity to BackRunner <dev@backrunner.top> for the requested repository work.

For detailed boundaries and checklists, read references/checklist.md.
