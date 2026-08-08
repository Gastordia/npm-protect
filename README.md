# npm-protect

`npm-protect` is a local-first dependency firewall for npm projects.

The current repository implements the first useful slice:

- project and lockfile discovery
- dependency graph extraction from npm lockfiles
- install-script, integrity, and direct dependency checks
- typosquat heuristics for direct dependencies
- optional OSV vulnerability lookups
- optional npm registry integrity and signature checks
- fresh-package age heuristics from registry publish metadata
- optional tarball inspection for suspicious install-time behavior
- recovery of hidden lifecycle scripts from published tarballs
- optional npm CLI signature and provenance verification
- opt-in local caching for remote review data
- GitHub Action wrapper for CI usage
- policy loading and validation
- dependency diff summaries
- basic publisher posture checks
- SARIF export for review-oriented commands
- CycloneDX SBOM export
- file output support for report commands
- automated tests for core parsing, policy, and CLI flows

## Run

```bash
node ./bin/npm-protect.js --help
node ./bin/npm-protect.js review
node ./bin/npm-protect.js review --online
node ./bin/npm-protect.js review --inspect-tarballs
node ./bin/npm-protect.js review --audit-signatures
node ./bin/npm-protect.js review --online --cache-dir .npm-protect-cache
node ./bin/npm-protect.js diff --project . --before-ref main --after-ref HEAD --json
node ./bin/npm-protect.js review --format sarif --output report.sarif
node ./bin/npm-protect.js diff --before . --after .
node ./bin/npm-protect.js publish-check
node ./bin/npm-protect.js sbom --output bom.json
node ./scripts/github-action.js
npm test
```

## GitHub Action

This repo now ships a GitHub Action wrapper in [action.yml](/home/wisepoo/npm-scan/action.yml).

Example:

```yaml
- uses: actions/checkout@v4
- uses: your-org/npm-protect@main
  with:
    command: diff
    before-ref: origin/main
    after-ref: HEAD
    format: sarif
    write-summary: "true"
```

The action writes the main result to a file in `RUNNER_TEMP` by default and, for commands
that support markdown, appends a summary to the GitHub step summary. For `review`,
`verify`, `diff`, and `publish-check`, it can also emit GitHub workflow annotations.

## Commands

- `review`: inspect a project directory and produce a risk report
- `verify`: alias of `review` with the same current behavior
- `diff`: compare two project snapshots, lockfiles, or git refs
- `install`: print a safer install plan based on policy and optional tarball evidence
- `publish-check`: inspect local publisher posture signals
- `sbom`: export a CycloneDX JSON SBOM for the local npm snapshot
- `policy init`: create a sample `npm-protect.yml`
- `policy validate`: validate `npm-protect.yml` or use defaults

## Output Formats

`review`, `verify`, `diff`, and `publish-check` support:

- text output by default
- `--json` for the current JSON schema
- `--format sarif` for SARIF 2.1.0
- `--format markdown` for PR comments and CI summaries
- `--output <path>` to write reports to disk

`install` supports:

- text output by default
- `--json` for the current JSON schema
- `--format markdown` for CI summaries and review comments
- `--output <path>` to write plans to disk

`sbom` emits CycloneDX JSON by default and also supports `--output <path>`.

## Review Semantics

`review` reports both:

- `riskVerdict`: the raw risk based on findings
- `verdict`: the enforced outcome after applying policy mode

In `warn` mode, blocking findings are still surfaced, but the enforced verdict is downgraded to `warn`.
In `enforce` mode, blocking findings produce a `block` verdict and a process exit code of `2`.

When remote collectors are enabled, `review` also reports:

- `sources`: status for each external intelligence collector
- vulnerability counts
- direct-package registry verification coverage
- fresh-package counts
- tarball inspection counts
- verified provenance attestation counts

`review --inspect-tarballs` fetches published tarballs for direct registry
dependencies and packages already marked with install-time lifecycle hooks in the
lockfile. It scans those files for suspicious downloader, inline-eval,
child-process, environment-access, and network-use patterns, and it can recover
hidden lifecycle scripts that were missing from lockfile metadata.

`install --inspect-tarballs` uses the same tarball evidence so reviewed install
plans stay aligned with `review`. Recovered lifecycle-script packages are counted
in the plan and can be approved through `allowedInstallScripts`.

`review --audit-signatures` also runs `npm audit signatures --json --include-attestations`
against the local install when `node_modules` is present and the npm CLI can reach the
registry services it needs. This provides stronger evidence for verified registry signatures
and npm provenance attestations than packument metadata alone.

`review --cache-dir <dir>` caches OSV responses, registry packuments, and inspected
tarballs so repeated reviews can reuse remote data instead of refetching it.

`diff --before-ref <git ref> --after-ref <git ref>` reads npm lockfiles directly from
git objects, which makes it usable in branch and pull-request gating workflows without
checking out extra working trees.

`diff` also flags same-version artifact drift:

- resolved tarball/source URL changes produce warnings
- integrity changes for the same package version produce blocking results

`publish-check` now evaluates:

- trusted-publishing posture such as `id-token: write`, `contents: read`, and `actions/setup-node`
- long-lived token references
- local `.npmrc` token and provenance posture
- provenance-disabling config
- repository/provider mismatches for GitHub publishing
- SBOM file presence and workflow generation signals

## Config

Create a starter config with:

```bash
node ./bin/npm-protect.js policy init
node ./bin/npm-protect.js policy init --github-actions
```

The scaffold supports `npm-protect.yml`, `npm-protect.yaml`, or `npm-protect.json`.

`policy init --github-actions` also scaffolds `.github/workflows/npm-protect.yml` with a
pull-request review workflow that uses the local action wrapper.

Example:

```yaml
mode: enforce

services:
  osv:
    enabled: true
  registry:
    enabled: true
    warnPackageAgeDays: 14
  tarballs:
    enabled: true
  auditSignatures:
    enabled: true

allowedInstallScripts:
  - esbuild@0.25.0

blockRules:
  requireLockfile: true
  unreviewedInstallScripts: true
  vulnerabilitySeverityThreshold: high
  requireRegistrySignatures: true
  requireVerifiedAttestations: false
  minPackageAgeDays: 30
  suspiciousTarballIndicators: true

warnRules:
  suspiciousTyposquats: true
  knownVulnerabilities: true
  missingRegistrySignatures: true
  missingVerifiedAttestations: true
  freshPackages: true
  suspiciousTarballIndicators: true
```

You can also enable the default collectors without changing config:

```bash
node ./bin/npm-protect.js review --online
```

And override their endpoints for testing or internal mirrors:

```bash
node ./bin/npm-protect.js review \
  --online \
  --osv-url https://api.osv.dev/v1/querybatch \
  --registry-url https://registry.npmjs.org
```

And inspect published install-hook tarballs:

```bash
node ./bin/npm-protect.js review --inspect-tarballs
node ./bin/npm-protect.js install --inspect-tarballs
```

And explicitly verify installed package signatures and attestations:

```bash
node ./bin/npm-protect.js review --audit-signatures
```

## Testing

Run the full suite with:

```bash
npm test
```

Coverage currently includes:

- config parsing and merge behavior
- npm lockfile normalization
- external intelligence collection with mocked fetch responses
- local cache reuse across repeated review runs
- fresh-package registry heuristics with injected time
- tarball inspection with mocked tarball responses
- tarball-backed recovery of hidden lifecycle scripts into install planning
- npm audit signatures collection with mocked runner responses
- git-ref diff loading with injected git object readers
- GitHub Action argument planning
- GitHub Action runner orchestration
- policy evaluation
- CLI command execution against fixture projects
- SARIF export and report file writing
- CycloneDX SBOM generation

## Current Limitations

- npm ecosystem only
- npm provenance verification depends on `node_modules`, network access for `npm audit signatures`, and npm CLI support
- tarball inspection currently prioritizes direct registry dependencies and packages already marked with install-time lifecycle hooks in the lockfile; it does not fetch every transitive tarball
- publisher workflow checks are text heuristics, not full YAML semantic parsing
- SBOM dependency edges currently include root-to-direct dependencies only
