# Architecture

Date: August 8, 2026

## Goal

The first architecture target is a **policy-driven local CLI** that can answer:

**"Is this dependency set safe enough to allow into the project or CI pipeline?"**

The initial implementation is intentionally local-first and zero-dependency so it is easy to run and extend.

## Runtime Shape

The scaffold uses plain Node.js ESM and is organized into three layers:

1. `commands/`
   Orchestrates CLI flows such as `review`, `diff`, and `publish-check`.

2. `lib/`
   Contains parsing, policy, reporting, filesystem logic, and external intelligence collectors.

3. `data/`
   Stores local reference datasets such as the curated package-name list for typosquat heuristics.

## Current Module Layout

- `bin/npm-protect.js`
  Entry point with process-level error handling.

- `src/cli.js`
  Command dispatch, lightweight argument parsing, and help text.

- `src/commands/review.js`
  Loads a project, evaluates policy, and prints a report.

- `src/commands/install.js`
  Builds a reviewed install plan from lockfile metadata and optional tarball-derived lifecycle-script evidence.

- `src/commands/diff.js`
  Compares two snapshots built from project directories, lockfiles, or git refs.

- `src/commands/policy.js`
  Creates and validates local policy config.

- `src/commands/publish-check.js`
  Checks local package and workflow posture signals before publish hardening work is expanded.

- `src/commands/sbom.js`
  Exports a CycloneDX JSON SBOM from the local project snapshot.

- `src/lib/project.js`
  Locates manifests and lockfiles, loads git-ref lockfiles, and builds normalized project snapshots.

- `src/lib/lockfile.js`
  Parses npm lockfiles into package records.

- `src/lib/config.js`
  Loads config from YAML or JSON, validates it, and merges with defaults.

- `src/lib/cache.js`
  Stores optional local cache entries for remote review data such as OSV results, packuments, and tarballs.

- `src/lib/github-action.js`
  Builds a GitHub Action execution plan from `INPUT_*` environment variables.

- `src/lib/policy.js`
  Turns evidence into findings and a verdict.

- `src/lib/intelligence.js`
  Collects optional OSV, registry metadata, tarball-analysis, and npm audit-signatures evidence for `review` and tarball-aware install planning.

- `src/lib/tarball-analysis.js`
  Expands and inspects published tarballs for suspicious lifecycle command and file patterns.

- `src/lib/typosquat.js`
  Applies a local string-similarity heuristic to package names.

- `src/lib/reporters.js`
  Formats text, JSON, SARIF, and markdown reports.

- `src/lib/output.js`
  Resolves formats and file output behavior for report-producing commands.

- `src/lib/sbom.js`
  Builds CycloneDX SBOM documents from the normalized snapshot model.

- `scripts/github-action.js`
  Runs the CLI behind the composite GitHub Action wrapper and writes action outputs and step summaries.

## Core Data Model

### Project Snapshot

```js
{
  dir,
  manifestPath,
  lockfilePath,
  packageName,
  packageVersion,
  repository,
  dependencies,
  lockfile: {
    lockfileVersion,
    packageCount,
    packages: [...]
  }
}
```

### Package Record

```js
{
  name,
  version,
  path,
  resolved,
  integrity,
  dev,
  optional,
  hasInstallScript,
  dependencyCount
}
```

### Finding

```js
{
  severity, // "error" | "warn" | "info"
  code,
  message,
  packageName,
  packageVersion,
  packagePath,
  details
}
```

## Review Flow

1. Resolve the project directory.
2. Load package manifest.
3. Load and normalize npm lockfile if present.
4. Load and validate policy config.
5. Collect local evidence:
   - lockfile presence
   - integrity coverage
   - install-script metadata
   - repository metadata
   - typosquat heuristic results
6. Optionally collect external evidence:
   - OSV vulnerability matches
   - registry integrity mismatches
   - registry signature presence
   - package publish age from registry metadata
   - suspicious lifecycle behavior from published tarballs
   - lifecycle scripts recovered from published tarballs when lockfile metadata is incomplete
   - npm audit-signatures verification results
   - cached reuse of previous remote lookups
7. Evaluate policy into findings.
8. Aggregate findings into a verdict:
   - `allow`
   - `warn`
   - `block`
9. Emit terminal or JSON output.

`diff` uses the same normalized lockfile records and now treats same-version source or
integrity drift as first-class change types, rather than only looking at add/remove/version churn.

## Policy Model

The scaffold uses a merged config model:

- hardcoded defaults
- optional repo config
- optional explicit `--config` path

The config currently supports:

- `mode`
- `trustedScopes`
- `allowedInstallScripts`
- `services`
- `blockRules`
- `warnRules`

This is still intentionally small, but it now carries enough detail to control the main trust signals without hiding policy in hardcoded constants.

## Why A Local-First Scaffold

The next implementation phase needs stable internal contracts before network-backed integrations are added.

A local-first scaffold gives that:

- deterministic output
- easy testing
- no registry or API assumptions
- faster iteration on the review model

## Extension Points

The code is laid out so the following can be added without rewriting the CLI surface:

1. Git-based dependency diffing
2. richer GitHub Action outputs and annotations
3. richer publisher posture checks
4. deeper transitive tarball analysis
5. sandboxed install-time behavior inspection
6. richer cache invalidation and offline workflows

## Short-Term Technical Direction

### Phase 1

- Make review stable on real npm repos
- Improve legacy lockfile parsing
- Add test coverage for policy and parser behavior
- Completed in this repo: SARIF, markdown, SBOM, OSV, registry metadata, tarball analysis, and npm audit-signatures integration

### Phase 2

- Add richer install-script risk heuristics
- Add more registry-metadata heuristics beyond age/signature/integrity checks
- Expand tarball inspection beyond direct lifecycle-file pattern scanning
- Expand local cache management beyond the current opt-in directory + TTL model

### Phase 3

- Support sandbox execution and richer package-behavior inspection
- Expand beyond npm once the model is stable
