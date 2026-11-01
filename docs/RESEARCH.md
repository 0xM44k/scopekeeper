# Research record (2026-10-26)

Method: web searches plus fetch attempts. Search results gave titles only; two fetches (a "scope-guard" agent page and a PyPI page) failed, so nothing is claimed from them.

## Observed

- A search for scope-enforcement tooling surfaced a "scope-guard" agent definition inside an AI pentest-agents collection and a markdown reference on scope enforcement. I could not fetch either, so I do not know what they implement or whether they keep a tamper-evident log.
- No fetched page covered a standalone, dependency-free CLI that both gates a command against a written scope and keeps a hash-chained record of what ran. That is an absence in what I read, not proof that none exists.

## Problem and design

Authorised testers work from a written scope and a time window. Mistakes that matter happen at the command line: a typo'd IP, a wildcard that was meant to exclude a host, a scan run a day after the window closed. And after the engagement the client may ask what was run, when, against what, under which scope version.

scopekeeper checks every target in a command against the scope file before running it, fails closed when it cannot classify something, and writes each decision to an append-only SHA-256 hash chain that records the scope file's hash.

## Decisions

- Exclusions override inclusions. Window enforced to the second, UTC.
- No DNS. A hostname in scope may resolve to an address outside what you are authorised to test, so hostnames match only domain entries; list IPs/CIDRs for address-level scope.
- No shell. The command is run from an argument list, so shell metacharacters in arguments are inert.
- Hash chain, not a signature: no dependencies and no key management. Consequence: tail truncation or a whole-file rewrite is undetectable unless the head hash was recorded elsewhere (`verify --expect-head`). Tests encode this limitation.

## Not verified

- Target extraction is heuristic. Tools read targets from config files, environment variables, stdin or DNS lists that this cannot see. It is a guard rail against mistakes, not a sandbox and not a control against a determined user.
- Not tested on Windows, and the log's file locking (fcntl) is POSIX only.
- Not reviewed by a lawyer or against any specific contract format.
