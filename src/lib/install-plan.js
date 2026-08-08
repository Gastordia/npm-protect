import { collectExternalIntelligence } from "./intelligence.js";

export async function buildInstallPlan(project, config, options = {}) {
  const flags = options.flags ?? {};
  const localPackages = (project.lockfile?.packages ?? [])
    .filter((pkg) => pkg.hasInstallScript)
    .map((pkg) => normalizeLocalInstallScriptPackage(pkg));
  const recoveredPackages =
    options.recoveredPackages?.map(normalizeRecoveredLifecycleScriptPackage) ??
    (await collectRecoveredLifecycleScriptPackages(project, config, flags, options));
  const packagesWithScripts = mergeInstallScriptPackages(localPackages, recoveredPackages);
  const approved = packagesWithScripts.filter((pkg) =>
    isApprovedInstallScriptPackage(config.allowedInstallScripts, pkg.name, pkg.version),
  );
  const unapproved = packagesWithScripts.filter(
    (pkg) => !isApprovedInstallScriptPackage(config.allowedInstallScripts, pkg.name, pkg.version),
  );

  return {
    project: {
      dir: project.dir,
      name: project.packageName,
      version: project.packageVersion,
    },
    mode: config.mode,
    recommendedSteps: buildRecommendedInstallSteps(approved),
    stats: {
      packagesWithInstallScripts: packagesWithScripts.length,
      recoveredLifecycleScriptPackages: recoveredPackages.length,
      approvedPackages: approved.length,
      unapprovedPackages: unapproved.length,
    },
    approved: approved.map(serializePlanPackage),
    unapproved: unapproved.map(serializePlanPackage),
  };
}

export function isApprovedInstallScriptPackage(approvedEntries, packageName, version) {
  const exact = `${packageName}@${version}`;
  return approvedEntries.includes(packageName) || approvedEntries.includes(exact);
}

export function buildRecommendedInstallSteps(approvedPackages) {
  const steps = ["npm ci --ignore-scripts"];

  if (approvedPackages.length > 0) {
    const packageNames = [...new Set(approvedPackages.map((pkg) => pkg.name))];
    steps.push(`npm rebuild ${packageNames.join(" ")}`);
    return steps;
  }

  steps.push("No dependency scripts should be rebuilt until they are reviewed");
  return steps;
}

async function collectRecoveredLifecycleScriptPackages(project, config, flags, options) {
  if (!shouldInspectTarballsForInstall(config, flags)) {
    return [];
  }

  const intelligenceConfig = {
    ...config,
    services: {
      ...config.services,
      osv: {
        ...config.services.osv,
        enabled: false,
      },
      registry: {
        ...config.services.registry,
        enabled: false,
      },
      tarballs: {
        ...config.services.tarballs,
        enabled: true,
      },
      auditSignatures: {
        ...config.services.auditSignatures,
        enabled: false,
      },
    },
  };
  const intelligence = await collectExternalIntelligence(project, intelligenceConfig, {
    flags: {
      ...flags,
      online: false,
      "audit-signatures": false,
    },
    fetchImpl: options.fetchImpl,
    now: options.now,
  });

  return (intelligence.recoveredLifecycleScriptPackages ?? []).map(
    normalizeRecoveredLifecycleScriptPackage,
  );
}

function shouldInspectTarballsForInstall(config, flags) {
  return Boolean(flags["inspect-tarballs"]) || Boolean(config.services?.tarballs?.enabled);
}

function normalizeLocalInstallScriptPackage(pkg) {
  return {
    name: pkg.name,
    version: pkg.version,
    path: pkg.path,
    source: "lockfile",
    scriptNames: [],
  };
}

function normalizeRecoveredLifecycleScriptPackage(pkg) {
  return {
    name: pkg.name,
    version: pkg.version,
    path: pkg.packagePath ?? pkg.path,
    source: "tarball",
    scriptNames: pkg.scriptNames ?? [],
  };
}

function mergeInstallScriptPackages(localPackages, recoveredPackages) {
  const merged = [];
  const seen = new Set();

  for (const pkg of [...localPackages, ...recoveredPackages]) {
    const key = `${pkg.name}@${pkg.version}:${pkg.path}`;
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    merged.push(pkg);
  }

  return merged;
}

function serializePlanPackage(pkg) {
  return {
    name: pkg.name,
    version: pkg.version,
    path: pkg.path,
    source: pkg.source,
    scriptNames: pkg.scriptNames,
  };
}
