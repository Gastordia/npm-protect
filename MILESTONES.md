# Milestones

Date: August 8, 2026

## Milestone 1: Runnable Scaffold

Status: Complete in this repo

Deliverables:

- local CLI entrypoint
- command surface scaffold
- project and lockfile loading
- review, diff, policy, and publish-check commands
- architecture and product docs

Exit criteria:

- `node ./bin/npm-protect.js --help` works
- `review` produces a structured report on the current repo

## Milestone 2: Stronger Local Review

Status: Mostly complete in this repo

Deliverables:

- test suite for lockfile parsing and policy logic
- safer legacy lockfile handling
- better install-script reporting
- richer typosquat and metadata heuristics
- SARIF output
- markdown PR-comment output
- CycloneDX SBOM export

Exit criteria:

- stable output on multiple representative npm repos
- findings have predictable exit codes and machine-readable structure

## Milestone 3: External Trust Signals

Status: Partially complete in this repo

Deliverables:

- OSV-backed vulnerability lookup
- npm registry signature checks
- publish-age heuristics from registry metadata
- npm provenance verification support
- local cache for remote lookups

Exit criteria:

- external lookups are optional but integrated into verdicts
- network failures degrade gracefully instead of breaking the CLI

## Milestone 4: Safer Install Workflow

Status: Mostly complete in this repo

Deliverables:

- explicit safe-install plan generation
- reviewed install-script approvals
- optional `npm rebuild` guidance for approved packages
- optional tarball-backed recovery of hidden lifecycle scripts
- better CI-mode behavior

Exit criteria:

- a team can run `npm-protect install` as a documented replacement for an unsafe default install flow

## Milestone 5: Publisher Hardening

Status: Started in this repo

Deliverables:

- trusted publishing checks
- long-lived token detection in workflows and config
- provenance posture checks
- signed release and SBOM checks

Exit criteria:

- maintainers can use `publish-check` to harden release workflows before publishing

## Milestone 6: CI And Platform Integration

Status: Started in this repo

Deliverables:

- GitHub Action wrapper
- markdown PR summaries
- repository policy templates
- better diff support against branches or commits

Exit criteria:

- teams can enforce dependency policy on pull requests without custom scripting

## Milestone 7: Higher-Fidelity Malware Detection

Status: Started in this repo

Deliverables:

- tarball inspection
- suspicious API usage heuristics
- child-process and network behavior heuristics
- optional sandbox detonation mode

Exit criteria:

- the tool catches more malicious package patterns than policy-only review

## Milestone 8: Multi-Ecosystem Expansion

Deliverables:

- shared graph and policy interfaces
- PyPI support
- GitHub Actions dependency checks
- later evaluation for containers and other ecosystems

Exit criteria:

- the npm-first architecture generalizes without a rewrite
