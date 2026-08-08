# npm-protect Product Plan

Date: August 8, 2026

## Working Product Name

`npm-protect` should be positioned as a **dependency firewall** for modern software supply chains.

That framing matters. A scanner reports problems after the fact. A firewall enforces trust policy **before install, before merge, and before publish**.

## 1. Problem Statement

The current package-security model is too advisory-driven:

- Vulnerability feeds are useful, but they lag behind active malware campaigns.
- Developers still execute untrusted dependency code during install.
- CI systems still carry secrets that malicious packages can steal.
- Trust decisions are often based on package popularity instead of verifiable origin and behavior.

Recent npm attacks show the real issue:

- Typosquatted packages trick users into installing the wrong dependency.
- Install hooks execute automatically at `npm install` time.
- Stolen cloud, GitHub, and npm credentials let attackers pivot into CI and package publishing.
- A single compromised maintainer account or leaked token can poison downstream users quickly.

## 2. Product Thesis

The product should answer one question:

**"Should this dependency be allowed to execute or enter our codebase?"**

That means the tool must combine:

- Dependency intelligence
- Behavioral inspection
- Origin verification
- Policy enforcement
- Incident evidence generation

## 3. Target Users

### Primary

- Security-conscious JavaScript teams
- Platform / DevSecOps teams managing CI policies
- Open source maintainers publishing npm packages
- Startups that need strong controls without building an internal AppSec team

### Secondary

- Enterprises standardizing software supply-chain controls across repos
- Internal developer platform teams
- Security consultancies auditing client repos and CI pipelines

## 4. Positioning

### What it is

- A dependency firewall for npm-based projects
- A policy engine for dependency trust
- A pre-install and pre-merge gate

### What it is not

- Not just another CVE scanner
- Not just another SBOM generator
- Not just malware signature matching
- Not an EDR replacement

## 5. Core Product Principles

1. **Fail before execution**
   Block or isolate risky packages before install scripts run.

2. **Trust provenance over popularity**
   Prefer verifiable source, signatures, and publish workflow identity over stars and downloads.

3. **Inspect dependency changes, not just dependency state**
   The highest-value decision point is when a package is first introduced or changed.

4. **Explain every verdict**
   Security tools get bypassed when they act like black boxes.

5. **Default to least privilege**
   Secrets, install scripts, and publish rights should all be constrained.

## 6. Ideal User Workflows

### Workflow A: Local dependency review

Developer runs:

```bash
npm-protect review
```

The tool:

- Reads `package.json` and lockfiles
- Resolves full dependency tree
- Finds new or changed packages
- Flags install scripts, provenance gaps, typosquat risk, suspicious metadata, and known vulns
- Returns `allow`, `warn`, or `block`

### Workflow B: CI gate on pull requests

CI runs:

```bash
npm-protect diff --before-ref main --after-ref HEAD
```

The tool:

- Diffs dependency graph changes
- Fails if policy is violated
- Produces a machine-readable SARIF/JSON report and a human-readable summary

### Workflow C: Safe install mode

Developer or CI runs:

```bash
npm-protect install
npm-protect install --inspect-tarballs
```

The tool:

- Enforces `ignore-scripts` or reviewed script policy
- Can recover hidden lifecycle scripts from published tarballs when enabled
- Verifies signatures/provenance where supported
- Uses a reviewed allowlist for packages that genuinely need install scripts

### Workflow D: Publisher hardening

Maintainer runs:

```bash
npm-protect publish-check
```

The tool checks:

- Trusted publishing / OIDC usage
- 2FA policy
- Token exposure risks
- Signed release / provenance expectations
- SBOM presence

## 7. MVP Scope

The MVP should be intentionally narrow:

- npm ecosystem only
- Lockfile-aware
- CLI-first
- CI-friendly
- Policy engine first, UI later

### MVP Capabilities

1. Dependency graph resolution from:
   - `package.json`
   - `package-lock.json`
   - `npm-shrinkwrap.json`

2. Dependency diffing:
   - added packages
   - removed packages
   - version changes
   - source/repository changes

3. Risk signals:
   - install scripts present
   - `preinstall` / `install` / `postinstall` / `prepare`
   - package age
   - suspicious version jumps
   - typosquat similarity to high-confidence popular packages
   - unscoped package collision risk for known internal names
   - missing provenance
   - missing registry signatures
   - known vulnerabilities
   - suspicious metadata mismatches

4. Policy decisions:
   - allow
   - warn
   - block

5. Outputs:
   - terminal summary
   - JSON
   - SARIF
   - markdown PR comment

## 8. Feature Chart

| Feature | MVP | Phase 2 | Phase 3 | Why it matters |
|---|---|---|---|---|
| Full dependency tree parsing | Yes |  |  | Direct dependencies are not enough |
| Lockfile diffing | Yes |  |  | Best point to catch malicious changes |
| Install script detection | Yes |  |  | Many npm attacks start here |
| Allowlist for install scripts | Yes |  |  | Lets teams run only reviewed scripts |
| Strict policy enforcement | Yes |  |  | Needed for CI blocking |
| JSON/SARIF output | Yes |  |  | CI and code scanning integration |
| OSV vulnerability lookup | Yes |  |  | Baseline known-risk coverage |
| Registry signature verification | Yes |  |  | Detects tampering / integrity gaps |
| Provenance verification | Yes |  |  | Verifies where package came from |
| Typosquat detection | Yes |  |  | Common initial access path |
| Tarball lifecycle-script recovery | Yes |  |  | Catches install hooks missing from lockfile metadata |
| Tarball static install-time heuristics | Yes |  |  | Adds behavioral signal beyond metadata-only review |
| Publisher posture checks | Yes |  |  | Trusted publishing, SBOM, and token hygiene |
| Suspicious metadata detection | Yes |  |  | Catches spoofed repo/homepage fields |
| Package age / freshness heuristics | Yes |  |  | New lookalike packages are riskier |
| Maintainer reputation scoring |  | Yes |  | Useful, but noisy and gameable |
| Sandboxed package detonation |  | Yes |  | Stronger behavior evidence |
| Secret access pattern detection |  | Yes |  | Detect env/credential theft attempts |
| Egress/network rule checks for install |  | Yes |  | Helps reduce exfiltration risk |
| GitHub PR bot |  | Yes |  | Better developer workflow |
| Web dashboard |  | Yes |  | Helpful later, not essential now |
| Multi-ecosystem support |  |  | Yes | PyPI, crates, Maven, containers |
| Org-wide trust graph |  |  | Yes | Enterprise visibility and policy |
| Cross-repo incident blast-radius analysis |  |  | Yes | Needed after a widespread supply-chain event |

## 9. Feature Prioritization

### Must-have in MVP

- Dependency diffing
- Lockfile parsing
- Install-script detection
- Policy engine
- Signature and provenance verification
- OSV integration
- Typosquat heuristics
- CI output formats

### Should-have soon after MVP

- Static behavioral analysis of package tarballs
- GitHub integration
- Publisher posture checks
- Reviewed install-script approval workflow

### Explicitly out of MVP

- Full web UI
- Cross-ecosystem support
- Runtime endpoint monitoring
- Enterprise procurement workflows

## 10. Threat Model Coverage

| Threat | MVP Coverage | Notes |
|---|---|---|
| Typosquatting | Partial-Strong | Heuristic detection, not perfect |
| Dependency confusion | Partial | Stronger when users declare trusted scopes/registries |
| Known vulnerable package | Strong | Via OSV and lockfile matching |
| Malicious install hook | Strong | Presence-based blocking plus policy |
| Malicious code hidden without hooks | Weak-Partial | Better in Phase 2 with code heuristics and sandboxing |
| Compromised maintainer publish token | Partial | Better addressed via provenance and publisher posture |
| Registry tampering | Partial-Strong | Signature verification helps |
| Compromised CI runner secrets | Partial | Tool can reduce risk, not replace CI hardening |

## 11. Product Architecture

### Core components

1. **Resolver**
   - Parses manifests and lockfiles
   - Builds normalized dependency graph

2. **Evidence collectors**
   - OSV lookup
   - npm signature verification
   - provenance verification
   - metadata collection
   - package script extraction

3. **Heuristics engine**
   - typosquat similarity
   - suspicious versioning
   - suspicious repo/homepage mismatch
   - high-risk script patterns

4. **Policy engine**
   - maps evidence to verdict
   - configurable org/team rules

5. **Output adapters**
   - CLI formatter
   - JSON
   - SARIF
   - GitHub comment markdown

### Suggested implementation order

1. CLI scaffold
2. Lockfile parser
3. Dependency graph + diff engine
4. Policy engine
5. OSV integration
6. Signature/provenance verification
7. Script and metadata analysis
8. CI output formats

## 12. Suggested CLI Surface

```bash
npm-protect review
npm-protect diff --before-ref main --after-ref HEAD
npm-protect verify
npm-protect install
npm-protect publish-check
npm-protect policy init
npm-protect policy validate
```

### Suggested config file

`npm-protect.yml`

Example:

```yaml
mode: enforce

trustedScopes:
  - "@mycompany"

allowedInstallScripts:
  - esbuild@0.25.0
  - sharp@0.34.0

blockRules:
  missingProvenanceForHighRisk: true
  missingRegistrySignature: true
  newPackageWithInstallScript: true
  typosquatScoreThreshold: 0.92
  maxPackageAgeDaysForAutoTrust: 30

warnRules:
  newMaintainer: true
  suspiciousRepositoryMismatch: true
```

## 13. Detection Logic Recommendations

### High-confidence block signals

- New package with `preinstall` or `postinstall`
- Invalid or missing registry signature where signature support exists
- Invalid provenance attestation
- Dependency name strongly matching a popular package but different source
- Package attempting to run install scripts without explicit approval

### Medium-confidence review signals

- Brand-new package with low age and low usage
- Repo metadata does not match package identity
- Large version jump with little history
- Package includes bundled executable or minified/obfuscated installer
- New maintainer or abrupt ownership changes if observable

### Lower-confidence warnings

- No SBOM
- No signed releases
- No branch protection
- No dependency update tooling

These are important trust signals, but they should not be hard blockers for normal consumers in MVP.

## 14. Recommended Tech Stack

### Core language

Use **TypeScript on Node.js** for the first version.

Reasons:

- Native fit for npm ecosystem
- Easy parsing of package metadata and lockfiles
- Lower friction for contributing and dogfooding
- Easier packaging as an npm CLI

### Supporting libraries

- `commander` or `yargs` for CLI
- `ajv` for config schema validation
- `fast-levenshtein` or custom similarity logic for typosquatting
- native fetch / `undici` for API access

## 15. Metrics For Success

### Product metrics

- Time to verdict on a medium-sized repo
- False positive rate on common legitimate packages
- Percentage of dependency changes classified automatically
- Number of blocked risky installs before execution

### Security metrics

- Packages with unreviewed install scripts prevented
- Invalid provenance/signature detections
- High-risk dependency changes caught at PR time
- Time to identify blast radius for a malicious package advisory

## 16. Risks

1. **False positives**
   If the tool blocks too much, teams will bypass it.

2. **Data source gaps**
   Provenance and signature coverage are still incomplete across the ecosystem.

3. **Adversarial adaptation**
   Attackers can reduce obvious signals once defenders focus on install hooks.

4. **Scope creep**
   Supporting every ecosystem too early will slow delivery and weaken the npm-first product.

## 17. MVP Roadmap

### Phase 0: 1 week

- Define CLI commands
- Define config schema
- Define policy model
- Build normalized dependency data model

### Phase 1: 2 to 3 weeks

- Parse manifests and lockfiles
- Build dependency graph and diff engine
- Add install-script inspection
- Add policy evaluator
- Add JSON and terminal output

### Phase 2: 2 weeks

- Add OSV checks
- Add signature verification
- Add provenance verification
- Add typosquat heuristics

### Phase 3: 1 to 2 weeks

- Add SARIF and markdown reports
- Add CI examples
- Add reviewed install-script workflow
- Harden error handling and caching

### Phase 4: post-MVP

- Static code heuristics
- Sandboxed execution
- GitHub App or Action
- Publisher posture checks

## 18. Competitive Advantage

The strongest differentiator is:

**"We decide trust before dependency code executes."**

Most tools do one of these well:

- vuln scanning
- SBOM generation
- package reputation
- CI policy

Very few combine:

- dependency diffing
- install-script control
- provenance/signature checks
- trust policy enforcement

That combination is the product.

## 19. Recommended Next Build Step

Do not start with UI.

Start by building:

1. `npm-protect review`
2. lockfile parsing
3. dependency diff engine
4. install-script policy enforcement
5. JSON report output

That is the smallest version that proves the product thesis.
