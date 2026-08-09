import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

import { isInstallScriptPackageApproved } from "./approvals.js";
import { buildCacheKey, readCache, resolveCacheSettings, writeCache } from "./cache.js";
import { fileExists } from "./project.js";
import { inspectPackageTarball } from "./tarball-analysis.js";

const execFileAsync = promisify(execFile);

const SEVERITY_RANKS = {
  unknown: 0,
  none: 0,
  low: 1,
  moderate: 2,
  medium: 2,
  high: 3,
  critical: 4,
};

export async function collectExternalIntelligence(
  project,
  config,
  options = {},
) {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const auditSignaturesRunner =
    options.auditSignaturesRunner ?? runNpmAuditSignatures;
  const now = options.now ?? new Date();
  const flags = options.flags ?? {};
  const cache = resolveCacheSettings(flags);
  const settings = resolveCollectorSettings(config, flags);
  const findings = [];
  const sources = [];
  const recoveredLifecycleScriptPackages = [];
  const stats = {
    vulnerabilities: 0,
    directPackagesCheckedAgainstRegistry: 0,
    verifiedAttestations: 0,
    freshPackages: 0,
    tarballsInspected: 0,
    recoveredLifecycleScriptPackages: 0,
    suspiciousTarballPackages: 0,
  };

  if (settings.osv.enabled && fetchImpl) {
    try {
      const osvResult = await collectOsvVulnerabilities(
        project,
        config,
        settings.osv,
        fetchImpl,
        cache,
      );
      findings.push(...osvResult.findings);
      stats.vulnerabilities += osvResult.stats.vulnerabilities;
      sources.push({
        name: "osv",
        status: "ok",
        checkedPackages: osvResult.stats.checkedPackages,
        vulnerabilities: osvResult.stats.vulnerabilities,
        cacheHits: osvResult.stats.cacheHits,
        cacheWrites: osvResult.stats.cacheWrites,
        url: settings.osv.url,
      });
    } catch (error) {
      sources.push({
        name: "osv",
        status: "error",
        url: settings.osv.url,
        message: error instanceof Error ? error.message : String(error),
      });
      if (config.warnRules.externalServiceFailures) {
        findings.push({
          severity: "warn",
          code: "external_service_failure",
          message: `OSV lookup failed: ${error instanceof Error ? error.message : String(error)}`,
          details: {
            source: "osv",
          },
        });
      }
    }
  }

  if (settings.registry.enabled && fetchImpl) {
    try {
      const registryResult = await collectRegistryMetadata(
        project,
        config,
        settings.registry,
        fetchImpl,
        now,
        cache,
      );
      findings.push(...registryResult.findings);
      stats.directPackagesCheckedAgainstRegistry +=
        registryResult.stats.directPackagesChecked;
      stats.freshPackages += registryResult.stats.freshPackages;
      sources.push({
        name: "registry",
        status: "ok",
        checkedPackages: registryResult.stats.directPackagesChecked,
        freshPackages: registryResult.stats.freshPackages,
        cacheHits: registryResult.stats.cacheHits,
        cacheWrites: registryResult.stats.cacheWrites,
        url: settings.registry.url,
      });
    } catch (error) {
      sources.push({
        name: "registry",
        status: "error",
        url: settings.registry.url,
        message: error instanceof Error ? error.message : String(error),
      });
      if (config.warnRules.externalServiceFailures) {
        findings.push({
          severity: "warn",
          code: "external_service_failure",
          message: `Registry metadata lookup failed: ${error instanceof Error ? error.message : String(error)}`,
          details: {
            source: "registry",
          },
        });
      }
    }
  }

  if (settings.tarballs.enabled && fetchImpl) {
    try {
      const tarballResult = await collectTarballIntelligence(
        project,
        config,
        settings.tarballs,
        fetchImpl,
        cache,
      );
      findings.push(...tarballResult.findings);
      stats.tarballsInspected += tarballResult.stats.inspectedPackages;
      stats.recoveredLifecycleScriptPackages +=
        tarballResult.stats.recoveredLifecycleScriptPackages;
      recoveredLifecycleScriptPackages.push(
        ...(tarballResult.recoveredLifecycleScriptPackages ?? []),
      );
      stats.suspiciousTarballPackages += tarballResult.stats.suspiciousPackages;
      sources.push({
        name: "tarballs",
        status: tarballResult.stats.failedPackages > 0 ? "issues" : "ok",
        inspectedPackages: tarballResult.stats.inspectedPackages,
        recoveredLifecycleScriptPackages:
          tarballResult.stats.recoveredLifecycleScriptPackages,
        suspiciousPackages: tarballResult.stats.suspiciousPackages,
        failedPackages: tarballResult.stats.failedPackages,
        cacheHits: tarballResult.stats.cacheHits,
        cacheWrites: tarballResult.stats.cacheWrites,
      });
    } catch (error) {
      sources.push({
        name: "tarballs",
        status: "error",
        message: error instanceof Error ? error.message : String(error),
      });
      if (config.warnRules.externalServiceFailures) {
        findings.push({
          severity: "warn",
          code: "external_service_failure",
          message: `Tarball inspection failed: ${error instanceof Error ? error.message : String(error)}`,
          details: {
            source: "tarballs",
          },
        });
      }
    }
  }

  if (settings.auditSignatures.enabled) {
    try {
      const auditResult = await collectAuditSignatures(
        project,
        config,
        settings.auditSignatures,
        auditSignaturesRunner,
        {
          skipInstallCheck: options.auditSignaturesRunner !== undefined,
        },
      );
      findings.push(...auditResult.findings);
      stats.verifiedAttestations += auditResult.stats.verifiedAttestations;
      sources.push({
        name: "audit-signatures",
        status:
          auditResult.stats.invalidEntries > 0 || auditResult.stats.missingEntries > 0
            ? "issues"
            : "ok",
        verifiedAttestations: auditResult.stats.verifiedAttestations,
        invalidEntries: auditResult.stats.invalidEntries,
        missingEntries: auditResult.stats.missingEntries,
        exitCode: auditResult.stats.exitCode,
      });
    } catch (error) {
      sources.push({
        name: "audit-signatures",
        status: "error",
        message: error instanceof Error ? error.message : String(error),
      });
      if (config.warnRules.auditSignaturesUnavailable) {
        findings.push({
          severity: "warn",
          code: "audit_signatures_unavailable",
          message: `npm audit signatures could not run: ${error instanceof Error ? error.message : String(error)}`,
          details: {
            source: "audit-signatures",
          },
        });
      }
    }
  }

  return { findings, sources, stats, recoveredLifecycleScriptPackages };
}

function resolveCollectorSettings(config, flags) {
  const online = Boolean(flags.online);

  const osvEnabled = online || Boolean(config.services.osv.enabled);
  const registryEnabled = online || Boolean(config.services.registry.enabled);
  const tarballsEnabled =
    Boolean(flags["inspect-tarballs"]) || Boolean(config.services?.tarballs?.enabled);
  const auditSignaturesEnabled =
    Boolean(flags["audit-signatures"]) || Boolean(config.services?.auditSignatures?.enabled);

  return {
    osv: {
      enabled: osvEnabled,
      url: String(flags["osv-url"] ?? config.services?.osv?.url ?? "https://api.osv.dev/v1/querybatch"),
      timeoutMs: Number(config.services?.osv?.timeoutMs ?? 5000),
    },
    registry: {
      enabled: registryEnabled,
      url: String(flags["registry-url"] ?? config.services?.registry?.url ?? "https://registry.npmjs.org"),
      timeoutMs: Number(config.services?.registry?.timeoutMs ?? 5000),
      warnPackageAgeDays: Number(config.services?.registry?.warnPackageAgeDays ?? 14),
    },
    tarballs: {
      enabled: tarballsEnabled,
      timeoutMs: Number(config.services?.tarballs?.timeoutMs ?? 10000),
      maxFilesPerPackage: Number(config.services?.tarballs?.maxFilesPerPackage ?? 6),
      maxFileBytes: Number(config.services?.tarballs?.maxFileBytes ?? 65536),
      selection: resolveTarballSelection(
        flags["inspect-tarballs"],
        config.services?.tarballs?.selection,
      ),
      maxPackages: Number(config.services?.tarballs?.maxPackages ?? 0),
    },
    auditSignatures: {
      enabled: auditSignaturesEnabled,
      includeAttestations: Boolean(
        config.services?.auditSignatures?.includeAttestations ?? true,
      ),
      timeoutMs: Number(config.services?.auditSignatures?.timeoutMs ?? 15000),
    },
  };
}

async function collectAuditSignatures(
  project,
  config,
  settings,
  auditSignaturesRunner,
  options = {},
) {
  const nodeModulesPath = path.join(project.dir, "node_modules");
  if (!options.skipInstallCheck && !(await fileExists(nodeModulesPath))) {
    throw new Error("node_modules not found; run npm ci or npm install before --audit-signatures");
  }

  const execution = await auditSignaturesRunner(project.dir, settings);
  const parsed = parseAuditSignaturesJson(execution.stdout);
  const invalidEntries = Array.isArray(parsed.invalid) ? parsed.invalid : [];
  const missingEntries = Array.isArray(parsed.missing) ? parsed.missing : [];
  const verifiedEntries = Array.isArray(parsed.verified) ? parsed.verified : [];
  const findings = [];

  for (const entry of invalidEntries) {
    const normalized = normalizeAuditSignaturesEntry(entry);
    const isAttestation = normalized.kind === "attestation";
    findings.push({
      severity: "error",
      code: isAttestation ? "invalid_provenance_attestation" : "invalid_registry_signature",
      message: buildAuditSignaturesMessage(
        normalized,
        isAttestation
          ? "has an invalid provenance attestation according to npm audit signatures"
          : "failed npm registry signature verification",
      ),
      packageName: normalized.packageName,
      packageVersion: normalized.packageVersion,
      details: {
        source: "audit-signatures",
        raw: entry,
      },
    });
  }

  for (const entry of missingEntries) {
    const normalized = normalizeAuditSignaturesEntry(entry);
    const isAttestation = normalized.kind === "attestation";
    const severity = isAttestation
      ? config.blockRules.requireVerifiedAttestations
        ? "error"
        : "warn"
      : config.blockRules.requireRegistrySignatures
        ? "error"
        : "warn";
    const shouldReport = isAttestation
      ? severity === "error" || config.warnRules.missingVerifiedAttestations
      : severity === "error" || config.warnRules.missingRegistrySignatures;

    if (!shouldReport) {
      continue;
    }

    findings.push({
      severity,
      code: isAttestation
        ? "missing_verified_provenance_attestation"
        : "missing_verified_registry_signature",
      message: buildAuditSignaturesMessage(
        normalized,
        isAttestation
          ? "does not have a verified provenance attestation"
          : "is missing a verified registry signature",
      ),
      packageName: normalized.packageName,
      packageVersion: normalized.packageVersion,
      details: {
        source: "audit-signatures",
        raw: entry,
      },
    });
  }

  return {
    findings,
    stats: {
      exitCode: execution.exitCode,
      invalidEntries: invalidEntries.length,
      missingEntries: missingEntries.length,
      verifiedAttestations: verifiedEntries.length,
    },
  };
}

async function collectOsvVulnerabilities(project, config, settings, fetchImpl, cache = null) {
  const packages = dedupePackages(
    (project.lockfile?.packages ?? [])
      .filter((pkg) => typeof pkg.version === "string" && pkg.version !== "unknown")
      .map((pkg) => ({
        name: pkg.name,
        version: pkg.version,
        packagePath: pkg.path,
      })),
  );

  if (packages.length === 0) {
    return {
      findings: [],
      stats: {
        checkedPackages: 0,
        vulnerabilities: 0,
      },
    };
  }

  const chunks = chunkArray(packages, 200);
  const findings = [];
  let vulnerabilityCount = 0;
  let cacheHits = 0;
  let cacheWrites = 0;

  for (const chunk of chunks) {
    const payload = {
      queries: chunk.map((pkg) => ({
        package: {
          ecosystem: "npm",
          name: pkg.name,
        },
        version: pkg.version,
      })),
    };

    const response = await fetchJson(
      settings.url,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      },
      settings.timeoutMs,
      fetchImpl,
      cache,
      { service: "osv" },
    );
    cacheHits += response.meta.cacheHits;
    cacheWrites += response.meta.cacheWrites;
    const results = Array.isArray(response.data.results) ? response.data.results : [];

    for (let index = 0; index < results.length; index += 1) {
      const pkg = chunk[index];
      const vulnerabilities = results[index]?.vulns ?? [];

      for (const vulnerability of vulnerabilities) {
        vulnerabilityCount += 1;
        const severity = extractSeverity(vulnerability);
        const thresholdRank = getSeverityRank(
          config.blockRules.vulnerabilitySeverityThreshold,
        );
        const severityRank = getSeverityRank(severity);
        const blocks =
          thresholdRank > 0 && severityRank >= thresholdRank && severityRank > 0;

        findings.push({
          severity: blocks ? "error" : "warn",
          code: "known_vulnerability",
          message: `${pkg.name}@${pkg.version} is affected by ${vulnerability.id}${vulnerability.summary ? `: ${vulnerability.summary}` : ""}`,
          packageName: pkg.name,
          packageVersion: pkg.version,
          packagePath: pkg.packagePath,
          details: {
            advisoryId: vulnerability.id,
            severity,
            aliases: vulnerability.aliases ?? [],
          },
        });
      }
    }
  }

  return {
    findings,
    stats: {
      checkedPackages: packages.length,
      vulnerabilities: vulnerabilityCount,
      cacheHits,
      cacheWrites,
    },
  };
}

async function collectRegistryMetadata(project, config, settings, fetchImpl, now, cache = null) {
  const directPackages = dedupePackages(
    (project.lockfile?.packages ?? [])
      .filter((pkg) => pkg.isDirectDependency)
      .filter((pkg) => pkg.version && pkg.version !== "unknown")
      .filter((pkg) =>
        project.directDependencies.some(
          (dependency) => dependency.name === pkg.name && dependency.isRegistryDependency,
        ),
      )
      .map((pkg) => ({
        name: pkg.name,
        version: pkg.version,
        packagePath: pkg.path,
        integrity: pkg.integrity ?? null,
      })),
  );

  const findings = [];
  let freshPackages = 0;
  let cacheHits = 0;
  let cacheWrites = 0;

  for (const pkg of directPackages) {
    const packumentUrl = `${settings.url.replace(/\/+$/u, "")}/${encodeURIComponent(pkg.name)}`;
    const packumentResponse = await fetchJson(
      packumentUrl,
      {},
      settings.timeoutMs,
      fetchImpl,
      cache,
      { service: "registry", packageName: pkg.name },
    );
    cacheHits += packumentResponse.meta.cacheHits;
    cacheWrites += packumentResponse.meta.cacheWrites;
    const packument = packumentResponse.data;
    const versionMetadata = packument?.versions?.[pkg.version];

    if (!versionMetadata) {
      findings.push({
        severity: "warn",
        code: "missing_registry_version_metadata",
        message: `${pkg.name}@${pkg.version} was not found in registry metadata`,
        packageName: pkg.name,
        packageVersion: pkg.version,
        packagePath: pkg.packagePath,
      });
      continue;
    }

    const registryIntegrity = versionMetadata.dist?.integrity ?? null;
    if (
      config.blockRules.integrityMismatch &&
      pkg.integrity &&
      registryIntegrity &&
      pkg.integrity !== registryIntegrity
    ) {
      findings.push({
        severity: "error",
        code: "registry_integrity_mismatch",
        message: `${pkg.name}@${pkg.version} has lockfile integrity ${pkg.integrity} but registry metadata reports ${registryIntegrity}`,
        packageName: pkg.name,
        packageVersion: pkg.version,
        packagePath: pkg.packagePath,
        details: {
          lockfileIntegrity: pkg.integrity,
          registryIntegrity,
        },
      });
    }

    const signatures = versionMetadata.dist?.signatures;
    if (!Array.isArray(signatures) || signatures.length === 0) {
      const severity = config.blockRules.requireRegistrySignatures ? "error" : "warn";
      if (severity === "error" || config.warnRules.missingRegistrySignatures) {
        findings.push({
          severity,
          code: "missing_registry_signatures",
          message: `${pkg.name}@${pkg.version} does not expose registry signatures in packument metadata`,
          packageName: pkg.name,
          packageVersion: pkg.version,
          packagePath: pkg.packagePath,
        });
      }
    }

    const publishedAt = parsePublishedAt(packument?.time?.[pkg.version]);
    if (!publishedAt) {
      continue;
    }

    const ageDays = ageInDays(publishedAt, now);
    const blockAgeDays = Number(config.blockRules.minPackageAgeDays ?? 0);
    const warnAgeDays = Number(settings.warnPackageAgeDays ?? 0);
    const shouldBlock = blockAgeDays > 0 && ageDays < blockAgeDays;
    const shouldWarn =
      !shouldBlock &&
      config.warnRules.freshPackages &&
      warnAgeDays > 0 &&
      ageDays < warnAgeDays;

    if (!shouldBlock && !shouldWarn) {
      continue;
    }

    freshPackages += 1;
    findings.push({
      severity: shouldBlock ? "error" : "warn",
      code: "fresh_package_release",
      message: `${pkg.name}@${pkg.version} was published ${formatAgeDays(ageDays)} ago on ${publishedAt.toISOString()}`,
      packageName: pkg.name,
      packageVersion: pkg.version,
      packagePath: pkg.packagePath,
      details: {
        publishedAt: publishedAt.toISOString(),
        ageDays,
        warnPackageAgeDays: warnAgeDays,
        minPackageAgeDays: blockAgeDays,
      },
    });
  }

  return {
    findings,
    stats: {
      directPackagesChecked: directPackages.length,
      freshPackages,
      cacheHits,
      cacheWrites,
    },
  };
}

async function collectTarballIntelligence(project, config, settings, fetchImpl, cache = null) {
  const packages = dedupePackages(
    (project.lockfile?.packages ?? [])
      .filter((pkg) => shouldInspectTarballPackage(pkg, settings.selection))
      .filter((pkg) => typeof pkg.version === "string" && pkg.version !== "unknown")
      .filter((pkg) => typeof pkg.resolved === "string" && /^https?:\/\//u.test(pkg.resolved))
      .map((pkg) => ({
        name: pkg.name,
        version: pkg.version,
        packagePath: pkg.path,
        resolved: pkg.resolved,
        hasInstallScript: Boolean(pkg.hasInstallScript),
        isDirectDependency: Boolean(pkg.isDirectDependency),
      })),
  );
  const selectedPackages =
    Number(settings.maxPackages ?? 0) > 0
      ? packages.slice(0, Number(settings.maxPackages))
      : packages;

  const findings = [];
  let inspectedPackages = 0;
  let recoveredLifecycleScriptPackages = 0;
  const recoveredPackages = [];
  let suspiciousPackages = 0;
  let failedPackages = 0;
  let cacheHits = 0;
  let cacheWrites = 0;

  for (const pkg of selectedPackages) {
    try {
      const tarballResponse = await fetchBuffer(
        pkg.resolved,
        {},
        settings.timeoutMs,
        fetchImpl,
        cache,
        { service: "tarballs", packageName: pkg.name, version: pkg.version },
      );
      cacheHits += tarballResponse.meta.cacheHits;
      cacheWrites += tarballResponse.meta.cacheWrites;
      const tarballBuffer = tarballResponse.data;
      inspectedPackages += 1;
      const analysis = inspectPackageTarball(tarballBuffer, pkg, config, settings);
      const lifecycleScripts = analysis.metadata?.lifecycleScripts ?? [];

      if (lifecycleScripts.length > 0 && !pkg.hasInstallScript) {
        recoveredLifecycleScriptPackages += 1;
        recoveredPackages.push({
          name: pkg.name,
          version: pkg.version,
          packagePath: pkg.packagePath,
          resolved: pkg.resolved,
          scriptNames: lifecycleScripts,
        });

        if (!isInstallScriptPackageApproved(config, pkg.name, pkg.version)) {
          findings.push({
            severity: config.blockRules.unreviewedInstallScripts ? "error" : "warn",
            code: "tarball_declares_lifecycle_script",
            message: `${pkg.name}@${pkg.version} declares install-time scripts in its published tarball (${lifecycleScripts.join(", ")}), but the lockfile did not mark them`,
            packageName: pkg.name,
            packageVersion: pkg.version,
            packagePath: pkg.packagePath,
            details: {
              source: "tarballs",
              tarballUrl: pkg.resolved,
              scriptNames: lifecycleScripts,
            },
          });
        }
      }

      if (analysis.findings.length > 0) {
        suspiciousPackages += 1;
      }
      findings.push(...analysis.findings);
    } catch (error) {
      failedPackages += 1;
      if (config.warnRules.externalServiceFailures) {
        findings.push({
          severity: "warn",
          code: "tarball_analysis_failed",
          message: `Could not inspect ${pkg.name}@${pkg.version} tarball: ${error instanceof Error ? error.message : String(error)}`,
          packageName: pkg.name,
          packageVersion: pkg.version,
          packagePath: pkg.packagePath,
          details: {
            source: "tarballs",
            tarballUrl: pkg.resolved,
          },
        });
      }
    }
  }

  return {
    findings,
    stats: {
      selectedPackages: selectedPackages.length,
      inspectedPackages,
      recoveredLifecycleScriptPackages,
      suspiciousPackages,
      failedPackages,
      cacheHits,
      cacheWrites,
    },
    recoveredLifecycleScriptPackages: recoveredPackages,
  };
}

async function fetchJson(url, init, timeoutMs, fetchImpl, cache = null, cacheIdentity = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const cacheKey = buildCacheKey({
    type: "json",
    url,
    method: init.method ?? "GET",
    body: init.body ?? null,
    cacheIdentity,
  });

  try {
    const cached = await readCache(cache, cacheKey);
    if (cached?.kind === "json") {
      return {
        data: cached.value,
        meta: {
          cacheHits: 1,
          cacheWrites: 0,
        },
      };
    }

    const response = await fetchImpl(url, {
      ...init,
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} from ${url}`);
    }

    const data = await response.json();
    const wrote = await writeCache(cache, cacheKey, {
      kind: "json",
      value: data,
    });
    return {
      data,
      meta: {
        cacheHits: 0,
        cacheWrites: wrote ? 1 : 0,
      },
    };
  } finally {
    clearTimeout(timer);
  }
}

async function fetchBuffer(url, init, timeoutMs, fetchImpl, cache = null, cacheIdentity = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const cacheKey = buildCacheKey({
    type: "buffer",
    url,
    method: init.method ?? "GET",
    cacheIdentity,
  });

  try {
    const cached = await readCache(cache, cacheKey);
    if (cached?.kind === "buffer" && typeof cached.base64 === "string") {
      return {
        data: Buffer.from(cached.base64, "base64"),
        meta: {
          cacheHits: 1,
          cacheWrites: 0,
        },
      };
    }

    const response = await fetchImpl(url, {
      ...init,
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} from ${url}`);
    }

    const data = Buffer.from(await response.arrayBuffer());
    const wrote = await writeCache(cache, cacheKey, {
      kind: "buffer",
      base64: data.toString("base64"),
    });
    return {
      data,
      meta: {
        cacheHits: 0,
        cacheWrites: wrote ? 1 : 0,
      },
    };
  } finally {
    clearTimeout(timer);
  }
}

async function runNpmAuditSignatures(projectDir, settings) {
  const args = ["audit", "signatures", "--json"];
  if (settings.includeAttestations) {
    args.push("--include-attestations");
  }

  try {
    const result = await execFileAsync("npm", args, {
      cwd: projectDir,
      timeout: settings.timeoutMs,
      maxBuffer: 10 * 1024 * 1024,
    });
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: 0,
    };
  } catch (error) {
    if (error && error.code === "ENOENT") {
      throw new Error("npm CLI was not found in PATH");
    }

    if (error && error.killed) {
      throw new Error(`timed out after ${settings.timeoutMs}ms`);
    }

    if (typeof error?.code === "number") {
      return {
        stdout: error.stdout ?? "",
        stderr: error.stderr ?? "",
        exitCode: error.code,
      };
    }

    throw new Error(error instanceof Error ? error.message : String(error));
  }
}

function parseAuditSignaturesJson(stdout) {
  if (typeof stdout !== "string" || stdout.trim().length === 0) {
    throw new Error("npm audit signatures returned empty JSON output");
  }

  try {
    return JSON.parse(stdout);
  } catch (error) {
    throw new Error(
      `npm audit signatures returned invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function normalizeAuditSignaturesEntry(entry) {
  if (typeof entry === "string") {
    const parsed = entry.match(/^(@?[^@\s]+(?:\/[^@\s]+)?)@([^\s]+)(?:\s+\(([^)]+)\))?$/u);
    const packageName = parsed?.[1] ?? null;
    const packageVersion = parsed?.[2] ?? null;
    const registry = parsed?.[3] ?? null;
    return {
      kind: /attestation|provenance/iu.test(entry) ? "attestation" : "signature",
      packageName,
      packageVersion,
      registry,
      detail: entry,
    };
  }

  if (entry && typeof entry === "object") {
    const detail = extractEntryDetail(entry);
    const registry = extractFirstString(
      entry.registry,
      entry.registryUrl,
      entry.url,
      entry.location,
    );
    const packageName = extractFirstString(
      entry.name,
      entry.package,
      entry.packageName,
      entry.module,
    );
    const packageVersion = extractFirstString(entry.version, entry.packageVersion);
    const kind =
      /attestation|provenance/iu.test(JSON.stringify(entry)) ? "attestation" : "signature";

    return {
      kind,
      packageName: packageName ?? null,
      packageVersion: packageVersion ?? null,
      registry: registry ?? null,
      detail,
    };
  }

  return {
    kind: "signature",
    packageName: null,
    packageVersion: null,
    registry: null,
    detail: String(entry),
  };
}

function extractEntryDetail(entry) {
  return extractFirstString(
    entry.message,
    entry.reason,
    entry.error,
    entry.code,
  );
}

function buildAuditSignaturesMessage(entry, description) {
  const label =
    entry.packageName && entry.packageVersion
      ? `${entry.packageName}@${entry.packageVersion}`
      : entry.packageName ?? "a package";
  const suffix = entry.detail ? `: ${entry.detail}` : entry.registry ? ` (${entry.registry})` : "";
  return `${label} ${description}${suffix}`;
}

function extractFirstString(...values) {
  for (const value of values) {
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }

  return null;
}

function parsePublishedAt(value) {
  if (typeof value !== "string" || value.length === 0) {
    return null;
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }

  return parsed;
}

function ageInDays(then, now) {
  const milliseconds = Math.max(0, now.getTime() - then.getTime());
  return milliseconds / (24 * 60 * 60 * 1000);
}

function formatAgeDays(ageDays) {
  if (ageDays < 1) {
    return "less than 1 day";
  }

  const rounded = Math.floor(ageDays);
  return `${rounded} day${rounded === 1 ? "" : "s"}`;
}

function extractSeverity(vulnerability) {
  const fromDatabase = vulnerability?.database_specific?.severity;
  if (typeof fromDatabase === "string") {
    return normalizeSeverity(fromDatabase);
  }

  const firstSeverity = vulnerability?.severity?.[0]?.score;
  if (typeof firstSeverity === "number") {
    return cvssNumberToSeverity(firstSeverity);
  }

  if (typeof firstSeverity === "string" && /^[0-9]+(\.[0-9]+)?$/u.test(firstSeverity)) {
    return cvssNumberToSeverity(Number(firstSeverity));
  }

  return "unknown";
}

function normalizeSeverity(value) {
  const normalized = value.toLowerCase();
  if (normalized === "medium") {
    return "moderate";
  }

  return normalized;
}

function cvssNumberToSeverity(score) {
  if (score >= 9.0) {
    return "critical";
  }
  if (score >= 7.0) {
    return "high";
  }
  if (score >= 4.0) {
    return "moderate";
  }
  if (score > 0) {
    return "low";
  }

  return "none";
}

function getSeverityRank(severity) {
  return SEVERITY_RANKS[normalizeSeverity(String(severity ?? "unknown"))] ?? 0;
}

function dedupePackages(packages) {
  const seen = new Set();
  const deduped = [];

  for (const pkg of packages) {
    const key = `${pkg.name}@${pkg.version}`;
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    deduped.push(pkg);
  }

  return deduped;
}

function shouldInspectTarballPackage(pkg, selection = "focused") {
  if (selection === "all") {
    return true;
  }

  return Boolean(pkg.hasInstallScript) || Boolean(pkg.isDirectDependency);
}

function resolveTarballSelection(flagValue, configuredSelection) {
  const candidate =
    typeof flagValue === "string" && flagValue.length > 0
      ? flagValue
      : configuredSelection ?? "focused";

  return candidate === "all" ? "all" : "focused";
}

function chunkArray(values, size) {
  const chunks = [];

  for (let index = 0; index < values.length; index += size) {
    chunks.push(values.slice(index, index + size));
  }

  return chunks;
}
