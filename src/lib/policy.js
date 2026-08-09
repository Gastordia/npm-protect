import { POPULAR_PACKAGES } from "../data/popular-packages.js";
import { isInstallScriptPackageApproved } from "./approvals.js";
import { analyzeTyposquats } from "./typosquat.js";

export function evaluateProject(project, config, validationErrors = []) {
  return evaluateProjectWithIntelligence(project, config, {
    validationErrors,
    securityWarnings: [],
    intelligence: {
      findings: [],
      sources: [],
      stats: {
        vulnerabilities: 0,
        directPackagesCheckedAgainstRegistry: 0,
        verifiedAttestations: 0,
        freshPackages: 0,
        tarballsInspected: 0,
        recoveredLifecycleScriptPackages: 0,
        suspiciousTarballPackages: 0,
        trustedScopeCollisions: 0,
      },
    },
  });
}

export function evaluateProjectWithIntelligence(project, config, options = {}) {
  const findings = [];
  const packages = project.lockfile?.packages ?? [];
  const directDependencies = project.directDependencies ?? [];
  const validationErrors = options.validationErrors ?? [];
  const securityWarnings = options.securityWarnings ?? [];
  const intelligence = options.intelligence ?? {
    findings: [],
    sources: [],
    stats: {
      vulnerabilities: 0,
      directPackagesCheckedAgainstRegistry: 0,
      verifiedAttestations: 0,
      freshPackages: 0,
      tarballsInspected: 0,
      recoveredLifecycleScriptPackages: 0,
      suspiciousTarballPackages: 0,
      trustedScopeCollisions: 0,
    },
  };
  const localInstallScriptPackages = packages.filter((pkg) => pkg.hasInstallScript).length;
  const recoveredLifecycleScriptPackages =
    intelligence.stats?.recoveredLifecycleScriptPackages ?? 0;

  for (const error of validationErrors) {
    findings.push({
      severity: "error",
      code: "invalid_config",
      message: error,
    });
  }

  for (const warning of securityWarnings) {
    findings.push({
      severity: "warn",
      code: "insecure_local_policy_file",
      message: warning,
    });
  }

  if (!project.lockfilePath) {
    findings.push({
      severity: config.blockRules.requireLockfile ? "error" : "warn",
      code: "missing_lockfile",
      message: "No supported package-manager lockfile was found in the project root",
    });
  }

  if (!project.repository && config.warnRules.missingRepository) {
    findings.push({
      severity: "warn",
      code: "missing_repository",
      message: "package.json does not declare a repository field",
    });
  }

  if (config.warnRules.expiredInstallScriptApprovals) {
    for (const approval of config.approvalState?.expiredApprovals ?? []) {
      findings.push({
        severity: "warn",
        code: "expired_install_script_approval",
        message: `${approval.name}${approval.version ? `@${approval.version}` : ""} has an expired install-script approval`,
        packageName: approval.name,
        packageVersion: approval.version,
        details: {
          expiredAt: approval.expiresAt ? approval.expiresAt.toISOString() : null,
          source: approval.source,
        },
      });
    }
  }

  if (
    config.warnRules.nonRegistryDirectDependencies ||
    config.blockRules.nonRegistryDirectDependencies
  ) {
    for (const dependency of directDependencies) {
      if (!dependency.isRegistryDependency) {
        findings.push({
          severity: config.blockRules.nonRegistryDirectDependencies ? "error" : "warn",
          code: "non_registry_direct_dependency",
          message: `${dependency.name} uses a non-registry specifier (${dependency.spec})`,
          packageName: dependency.name,
          details: {
            spec: dependency.spec,
            field: dependency.field,
          },
        });
      }
    }
  }

  for (const pkg of packages) {
    if (pkg.hasInstallScript && !isInstallScriptPackageApproved(config, pkg.name, pkg.version)) {
      findings.push({
        severity: config.blockRules.unreviewedInstallScripts ? "error" : "warn",
        code: "unreviewed_install_script",
        message: `${pkg.name}@${pkg.version} has install-time scripts and is not approved`,
        packageName: pkg.name,
        packageVersion: pkg.version,
        packagePath: pkg.path,
      });
    }

    if (!pkg.integrity) {
      findings.push({
        severity: config.blockRules.missingIntegrity ? "error" : "warn",
        code: "missing_integrity",
        message: `${pkg.name}@${pkg.version} is missing lockfile integrity data`,
        packageName: pkg.name,
        packageVersion: pkg.version,
        packagePath: pkg.path,
      });
    }
  }

  if (config.warnRules.suspiciousTyposquats) {
    const directPackages = packages.filter((pkg) => pkg.isDirectDependency);
    const typosquats = analyzeTyposquats(
      directPackages,
      POPULAR_PACKAGES,
      config.blockRules.typosquatScoreThreshold,
    );
    for (const result of typosquats) {
      findings.push({
        severity: result.package.hasInstallScript ? "error" : "warn",
        code: "suspicious_typosquat",
        message: `${result.package.name}@${result.package.version} is close to "${result.target}" (score ${result.score.toFixed(2)})`,
        packageName: result.package.name,
        packageVersion: result.package.version,
        packagePath: result.package.path,
        details: {
          target: result.target,
          score: result.score,
        },
      });
    }
  }

  findings.push(...(intelligence.findings ?? []));

  const errorCount = findings.filter((finding) => finding.severity === "error").length;
  const warnCount = findings.filter((finding) => finding.severity === "warn").length;
  const riskVerdict = errorCount > 0 ? "block" : warnCount > 0 ? "warn" : "allow";
  const enforcementVerdict =
    errorCount > 0 && config.mode === "enforce"
      ? "block"
      : warnCount > 0 || errorCount > 0
        ? "warn"
        : "allow";

  return {
    project: {
      dir: project.dir,
      name: project.packageName,
      version: project.packageVersion,
      manifestPath: project.manifestPath,
      lockfilePath: project.lockfilePath,
    },
    stats: {
      totalPackages: packages.length,
      directDependencyCount: project.dependencyNames.length,
      packagesWithInstallScripts:
        localInstallScriptPackages + recoveredLifecycleScriptPackages,
      recoveredLifecycleScriptPackages,
      packagesMissingIntegrity: packages.filter((pkg) => !pkg.integrity).length,
      directNonRegistryDependencyCount: directDependencies.filter(
        (dependency) => !dependency.isRegistryDependency,
      ).length,
      vulnerabilities: intelligence.stats?.vulnerabilities ?? 0,
      directPackagesCheckedAgainstRegistry:
        intelligence.stats?.directPackagesCheckedAgainstRegistry ?? 0,
      verifiedAttestations: intelligence.stats?.verifiedAttestations ?? 0,
      freshPackages: intelligence.stats?.freshPackages ?? 0,
      tarballsInspected: intelligence.stats?.tarballsInspected ?? 0,
      suspiciousTarballPackages: intelligence.stats?.suspiciousTarballPackages ?? 0,
      trustedScopeCollisions: intelligence.stats?.trustedScopeCollisions ?? 0,
    },
    sources: intelligence.sources ?? [],
    findings,
    riskVerdict,
    verdict: enforcementVerdict,
  };
}
