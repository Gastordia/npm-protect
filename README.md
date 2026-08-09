# npm-protect

`npm-protect` is a local-first dependency firewall for npm projects. It is built to reduce
the chance that a malicious, hijacked, or simply unsafe package install turns into code
execution on a Linux workstation, CI runner, or developer shell.

It can run in two modes:

- manual review, where you explicitly run `review`, `diff`, or `install`
- always-on protection, where `npm-protect` installs package-manager wrappers and mediates risky commands automatically

The always-on mode is meant to stay in front of the real package-manager binaries, so even if
an LLM, script, or helper tool tries to run `npm install`, `npx`, `pnpm dlx`, or `yarn dlx`,
the package request is still intercepted before unsafe code is allowed to run.

## What It Protects From

`npm-protect` focuses on supply-chain and install-time risk. Its current coverage is aimed at:

- install-time malware hidden in `preinstall`, `install`, `postinstall`, or `prepare`
- typosquatted direct dependencies that are easy to mistake for trusted packages
- direct `git+`, `http(s)`, or `file:` dependencies that bypass normal registry trust signals
- newly published packages or versions that are too fresh to trust by default
- same-version artifact drift, where a package tarball or integrity hash changes unexpectedly
- known vulnerable dependencies reported through OSV
- missing or invalid npm registry signatures and provenance attestations
- suspicious published tarballs that look like droppers, credential grabbers, or install-time loaders
- one-off remote package execution through `npx`, `npm exec`, `npm create`, `pnpm dlx`, or `yarn dlx`
- stale or overly broad install-script exceptions that stay approved forever
- unsafe global installs performed outside a project review context

## Attack Coverage And Mitigations

| Attack type | Typical attacker move | What `npm-protect` does | Mitigation technique |
| --- | --- | --- | --- |
| Lifecycle-script malware | Hide payloads in `preinstall` or `postinstall` | Blocks unapproved install-script packages and never runs install scripts during the first install pass | Forces `--ignore-scripts`, recovers hidden lifecycle hooks from tarballs, then rebuilds only allowlisted packages |
| Typosquatting | Publish a lookalike package name | Warns or blocks suspicious direct dependency names | Direct-dependency similarity heuristics with configurable thresholds |
| Non-registry dependency smuggling | Use `git+`, tarball URLs, or local file specs | Flags direct dependencies that bypass registry review signals | Direct specifier classification and policy enforcement |
| Fresh-package hijacks | Publish a malicious version minutes before install | Warns on very new packages and can enforce minimum package age | Registry publish-date checks with `warnPackageAgeDays` and `minPackageAgeDays` |
| Same-version artifact drift | Change tarball content without changing the semver version | Blocks integrity drift and reports artifact URL drift | Lockfile integrity comparison, registry `dist.integrity` verification, and before/after diffing |
| Known vulnerable dependencies | Pull in a package with a public security advisory | Warns or blocks based on policy severity | OSV batch lookup against resolved dependencies |
| Missing signatures or provenance | Publish unsigned or unattested releases | Warns or blocks when registry signature or attestation evidence is missing or invalid | Registry metadata verification plus optional `npm audit signatures --include-attestations` |
| Hidden tarball behavior | Ship downloader, eval, child-process, or network logic in published files | Surfaces suspicious packages even when the lockfile metadata looks normal | Tarball inspection for downloader, inline-eval, environment-access, child-process, and network-use indicators |
| Long-lived install-script exceptions | Approve a package once and forget it forever | Supports stored approvals with optional expiry and revoke flows | Approval store entries with timestamps, expiry, and operator review notes |
| One-off package execution | Use `npx`, `npm exec`, `pnpm dlx`, or `yarn dlx` to fetch and run a package immediately | Reviews the requested package spec in a temporary project before execution | Preflight lockfile resolution with `--ignore-scripts`, then the normal review pipeline |
| Unsafe automation installs | Let an agent run `npm install` blindly | Intercepts package-changing npm commands and reviews the resulting dependency state first | Always-on wrapper that previews changes, evaluates risk, and restores files on block |
| Unsupported package-manager mutation | Use `yarn install` when native lockfile mediation is not available yet | Blocks the command instead of pretending it is safely reviewed | Fail-closed interception for unsupported mutating managers |
| Unmanaged global installs | Run `npm install -g` without a reviewable project context | Blocks the command in service mode | Hard fail for global installs in the current protection model |

## How It Works

For manual review, `npm-protect` loads the local manifest and a supported lockfile, normalizes
the dependency graph, applies offline policy checks, optionally enriches the result with OSV,
registry, tarball, and signature evidence, and then emits a risk report.

For always-on protection, the service currently covers three classes of commands:

- full npm and pnpm install mediation for `npm install`, `npm i`, `npm ci`, `npm add`, `npm update`, `pnpm install`, `pnpm add`, and `pnpm update`
- one-off execution preflight for `npx`, `npm exec`, `npm create`, `npm init <initializer>`, `pnpm dlx`, `pnpx`, `yarn dlx`, and `yarn create`
- fail-closed blocking for mutating `yarn` install flows until native lockfile support is added

For dependency-changing npm installs it first resolves the requested change with
`--package-lock-only --ignore-scripts`. For pnpm installs it uses
`--lockfile-only --ignore-scripts`. In both cases it reviews the resulting dependency state,
restores the original files if the change is blocked, and only then performs the real install
with `--ignore-scripts`. If specific install scripts are approved, they are re-enabled later
through a targeted rebuild step.

The current repository already implements:

- project and lockfile discovery
- dependency graph extraction from npm and pnpm lockfiles
- install-script, integrity, and direct dependency checks
- optional OSV, registry, tarball, and signature intelligence
- hidden lifecycle-script recovery from published tarballs
- safer install planning and always-on `npm`, `pnpm`, and `npx`-family mediation
- approval-store backed install-script exceptions with expiry and revoke flows
- GitHub Action, SARIF, markdown, and file output support
- CycloneDX SBOM export
- local policy loading and validation
- dependency diff summaries and publisher posture checks
- automated tests for core parsing, policy, CLI, and service flows

## Quick Start

Install always-on protection:

```bash
node ./bin/npm-protect.js service install
node ./bin/npm-protect.js service status
node ./bin/npm-protect.js service doctor
```

Review a project manually:

```bash
node ./bin/npm-protect.js review --online --inspect-tarballs
node ./bin/npm-protect.js review --inspect-tarballs=all
node ./bin/npm-protect.js review --audit-signatures
```

Generate change-review output:

```bash
node ./bin/npm-protect.js diff --project . --before-ref main --after-ref HEAD --format sarif
node ./scripts/github-action.js
```

## More Examples

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
- `service`: install always-on wrappers that mediate `npm` and `pnpm` installs and preflight `npx`-style execution
- `publish-check`: inspect local publisher posture signals
- `sbom`: export a CycloneDX JSON SBOM for the local npm snapshot
- `policy init`: create a sample `npm-protect.yml`
- `policy validate`: validate `npm-protect.yml` or use defaults
- `policy approve-install-script`: create a reviewed install-script approval, optionally with expiry
- `policy list-approvals`: list active and expired stored approvals
- `policy revoke-install-script`: remove a stored install-script approval

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

## Always-On Protection

The service mode is the seamless option: you install it once, put the wrapper directory in
front of your `PATH`, and from that point forward normal package-manager commands flow
through the guard automatically.

Install the shim with:

```bash
node ./bin/npm-protect.js service install
node ./bin/npm-protect.js service status
node ./bin/npm-protect.js service doctor
npm run service:install
npm run service:status
```

When the service is active, `npm-protect` installs wrappers for `npm`, `npx`, `pnpm`,
`pnpx`, `yarn`, and `yarnpkg`.

It fully mediates `npm install`, `npm i`, `npm ci`, `npm add`, `npm update`, `pnpm install`,
`pnpm add`, and `pnpm update`. It also preflights one-off package execution for `npx`,
`npm exec`, `npm create`, `pnpm dlx`, `pnpx`, `yarn dlx`, and `yarn create`. This is the
path that protects against accidental or automated unsafe installs, including installs
initiated by an LLM or local scripting tool.

For dependency-changing installs, it:

1. Resolves the requested dependency change with `--package-lock-only --ignore-scripts`
2. Reviews the resulting dependency state with online registry checks and tarball inspection
3. Restores the original `package.json` and lockfile if the review blocks the change
4. Runs the real install with `--ignore-scripts` when the dependency state is allowed
5. Rebuilds only explicitly approved install-script packages

For `npm ci`, it reviews the existing lockfile first, then installs with `--ignore-scripts`,
then rebuilds only approved packages.

For `npx`-style commands, it resolves the requested package spec in a temporary project with
`--package-lock-only --ignore-scripts`, runs the normal review pipeline on that temporary
lockfile, and only allows execution when the result passes policy.

For `pnpm`, the service uses the same mediated-install model as npm, but previews with
`--lockfile-only` instead of `--package-lock-only`.

For mutating `yarn` install-like commands, the current service behavior is still fail-closed:
those commands are intercepted and blocked until native lockfile-accurate mediation exists.

The guard also blocks unmanaged global installs (`npm install -g`) by default, because they
cannot be reviewed safely with the current project-based model.

`service doctor` gives an operator-focused health check for wrapper installation, PATH
ordering, and per-tool activation so you can confirm whether the always-on guard is truly
active or being bypassed by shell configuration.

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

`review --inspect-tarballs=all` expands that inspection scope to every resolved registry
package in the current lockfile. That gives wider transitive coverage at the cost of more
network and analysis work.

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

approvals:
  path: ".npm-protect/approvals.json"

services:
  osv:
    enabled: true
  registry:
    enabled: true
    warnPackageAgeDays: 14
  tarballs:
    enabled: true
    selection: focused
    maxPackages: 0
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
  expiredInstallScriptApprovals: true
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
node ./bin/npm-protect.js review --inspect-tarballs=all
node ./bin/npm-protect.js install --inspect-tarballs
```

And explicitly verify installed package signatures and attestations:

```bash
node ./bin/npm-protect.js review --audit-signatures
```

And manage stored install-script approvals:

```bash
node ./bin/npm-protect.js policy approve-install-script esbuild@0.25.0 --expires-days 7 --reason "reviewed native build"
node ./bin/npm-protect.js policy list-approvals
node ./bin/npm-protect.js policy revoke-install-script esbuild@0.25.0
```

## Testing

Run the full suite with:

```bash
npm test
```

Coverage currently includes:

- config parsing and merge behavior
- npm and pnpm lockfile normalization
- external intelligence collection with mocked fetch responses
- local cache reuse across repeated review runs
- fresh-package registry heuristics with injected time
- tarball inspection with mocked tarball responses
- approval-store backed install-script exceptions and service doctor output
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
- full lockfile-accurate install mediation is currently implemented for npm and pnpm
- mutating `yarn` install flows are still intercepted and blocked fail-closed until native support lands
- npm provenance verification depends on `node_modules`, network access for `npm audit signatures`, and npm CLI support
- tarball inspection defaults to a focused subset; `--inspect-tarballs=all` expands to every resolved registry package but increases cost
- publisher workflow checks are text heuristics, not full YAML semantic parsing
- SBOM dependency edges currently include root-to-direct dependencies only
