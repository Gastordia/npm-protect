import {
  buildApprovalCommand,
  isInstallScriptPackageApproved,
} from "./approvals.js";
import { collectExternalIntelligence } from "./intelligence.js";

export async function buildInstallPlan(project, config, options = {}) {
  const flags = options.flags ?? {};
  const packageManager = normalizePackageManager(project.lockfile?.packageManager);
  const packageManagerFlavor = detectPackageManagerFlavor(project, packageManager, options);
  const rebuildPackageManager =
    options.rebuildPackageManager ??
    (packageManager === "yarn" && packageManagerFlavor === "classic" ? "npm" : packageManager);
  const localPackages = (project.lockfile?.packages ?? [])
    .filter((pkg) => pkg.hasInstallScript)
    .map((pkg) => normalizeLocalInstallScriptPackage(pkg));
  const recoveredPackages =
    options.recoveredPackages?.map(normalizeRecoveredLifecycleScriptPackage) ??
      (await collectRecoveredLifecycleScriptPackages(project, config, flags, options));
  const packagesWithScripts = mergeInstallScriptPackages(localPackages, recoveredPackages);
  const approved = packagesWithScripts.filter((pkg) => isInstallScriptPackageApproved(config, pkg.name, pkg.version));
  const unapproved = packagesWithScripts.filter(
    (pkg) => !isInstallScriptPackageApproved(config, pkg.name, pkg.version),
  );
  const rebuildStrategy = buildRebuildStrategy(rebuildPackageManager, packagesWithScripts, approved);

  return {
    project: {
      dir: project.dir,
      name: project.packageName,
      version: project.packageVersion,
    },
    packageManager,
    mode: config.mode,
    recommendedSteps: buildRecommendedInstallSteps(
      packageManager,
      rebuildStrategy,
      packageManagerFlavor,
    ),
    rebuildStrategy: serializeRebuildStrategy(rebuildStrategy),
    stats: {
      packagesWithInstallScripts: packagesWithScripts.length,
      recoveredLifecycleScriptPackages: recoveredPackages.length,
      approvedPackages: approved.length,
      unapprovedPackages: unapproved.length,
    },
    approved: approved.map(serializePlanPackage),
    unapproved: unapproved.map((pkg) => serializePlanPackage(pkg, project.dir)),
  };
}

export function isApprovedInstallScriptPackage(approvedEntries, packageName, version) {
  const exact = `${packageName}@${version}`;
  return approvedEntries.includes(packageName) || approvedEntries.includes(exact);
}

export function buildRecommendedInstallSteps(packageManager, rebuildStrategy, packageManagerFlavor = null) {
  const steps = [buildInstallCommand(packageManager, packageManagerFlavor)];

  if (rebuildStrategy.status === "safe") {
    steps.push(rebuildStrategy.command);
    return steps;
  }

  if (rebuildStrategy.status === "blocked") {
    steps.push(rebuildStrategy.message);
    return steps;
  }

  steps.push("No dependency scripts should be rebuilt until they are reviewed");
  return steps;
}

export function buildRebuildStrategy(packageManager, packagesWithScripts, approvedPackages) {
  const normalizedManager = normalizePackageManager(packageManager);
  if (normalizedManager === "pnpm" || normalizedManager === "yarn") {
    return buildNameScopedRebuildStrategy(normalizedManager, packagesWithScripts, approvedPackages);
  }

  return buildNpmRebuildStrategy(approvedPackages);
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

function buildInstallCommand(packageManager, packageManagerFlavor = null) {
  const normalizedManager = normalizePackageManager(packageManager);
  if (normalizedManager === "pnpm") {
    return "pnpm install --ignore-scripts";
  }

  if (normalizedManager === "yarn") {
    if (packageManagerFlavor === "classic") {
      return "yarn install --ignore-scripts";
    }
    return "yarn install --mode=skip-build";
  }

  return "npm ci --ignore-scripts";
}

function detectPackageManagerFlavor(project, packageManager, options) {
  if (typeof options.packageManagerFlavor === "string") {
    return options.packageManagerFlavor;
  }

  if (packageManager !== "yarn") {
    return null;
  }

  const packageManagerSpec = project.manifest?.packageManager;
  const majorMatch =
    typeof packageManagerSpec === "string" ? packageManagerSpec.match(/^yarn@(\d+)/u) : null;
  if (majorMatch) {
    return Number(majorMatch[1]) >= 2 ? "modern" : "classic";
  }

  return Number(project.lockfile?.lockfileVersion) === 1 ? "classic" : "modern";
}

function buildNpmRebuildStrategy(approvedPackages) {
  const targets = dedupeRebuildTargets(
    approvedPackages.map((pkg) => buildRebuildTarget(pkg.name, pkg.version)),
  );
  if (targets.length === 0) {
    return {
      status: "none",
      args: [],
      command: null,
      blockedPackages: [],
      packageManager: "npm",
    };
  }

  return {
    status: "safe",
    args: ["rebuild", ...targets],
    command: `npm rebuild ${targets.join(" ")}`,
    blockedPackages: [],
    packageManager: "npm",
  };
}

function buildNameScopedRebuildStrategy(packageManager, packagesWithScripts, approvedPackages) {
  if (approvedPackages.length === 0) {
    return {
      status: "none",
      args: [],
      command: null,
      blockedPackages: [],
      packageManager,
    };
  }

  const allVersionsByName = groupVersionsByName(packagesWithScripts);
  const approvedVersionsByName = groupVersionsByName(approvedPackages);
  const blockedPackages = [];
  const safeTargets = [];

  for (const [name, approvedVersions] of approvedVersionsByName.entries()) {
    const allVersions = allVersionsByName.get(name) ?? new Set();
    if (sameSet(allVersions, approvedVersions)) {
      safeTargets.push(name);
      continue;
    }

    blockedPackages.push({
      name,
      approvedVersions: [...approvedVersions].sort(),
      unapprovedVersions: [...difference(allVersions, approvedVersions)].sort(),
    });
  }

  if (blockedPackages.length > 0) {
    const labels = blockedPackages
      .map(
        (pkg) =>
          `${pkg.name} (approved: ${pkg.approvedVersions.join(", ")}; unapproved: ${pkg.unapprovedVersions.join(", ")})`,
      )
      .join("; ");

    return {
      status: "blocked",
      args: [],
      command: null,
      blockedPackages,
      packageManager,
      message:
        `${packageManager} cannot safely rebuild approved install-script packages by exact version when the same package name is also present at unapproved versions. Resolve or approve every installed version first: ` +
        labels,
    };
  }

  const targets = dedupeRebuildTargets(safeTargets);
  return {
    status: "safe",
    args: ["rebuild", ...targets],
    command: `${packageManager} rebuild ${targets.join(" ")}`,
    blockedPackages: [],
    packageManager,
  };
}

function serializeRebuildStrategy(strategy) {
  return {
    status: strategy.status,
    packageManager: strategy.packageManager,
    command: strategy.command,
    args: [...strategy.args],
    message: strategy.message ?? null,
    blockedPackages: strategy.blockedPackages.map((pkg) => ({
      name: pkg.name,
      approvedVersions: [...pkg.approvedVersions],
      unapprovedVersions: [...pkg.unapprovedVersions],
    })),
  };
}

function serializePlanPackage(pkg, projectDir = null) {
  return {
    name: pkg.name,
    version: pkg.version,
    path: pkg.path,
    source: pkg.source,
    scriptNames: pkg.scriptNames,
    approvalCommand:
      pkg.source === "tarball" || projectDir
        ? buildApprovalCommand(pkg.name, pkg.version, {
            projectDir,
            expiresDays: 7,
          })
        : buildApprovalCommand(pkg.name, pkg.version, {
            expiresDays: 7,
          }),
  };
}

function normalizePackageManager(value) {
  if (value === "pnpm" || value === "yarn") {
    return value;
  }

  return "npm";
}

function buildRebuildTarget(name, version) {
  return version ? `${name}@${version}` : name;
}

function dedupeRebuildTargets(targets) {
  return [...new Set(targets.filter(Boolean))];
}

function groupVersionsByName(packages) {
  const grouped = new Map();

  for (const pkg of packages) {
    if (!grouped.has(pkg.name)) {
      grouped.set(pkg.name, new Set());
    }
    grouped.get(pkg.name).add(pkg.version);
  }

  return grouped;
}

function sameSet(left, right) {
  if (left.size !== right.size) {
    return false;
  }

  for (const value of left) {
    if (!right.has(value)) {
      return false;
    }
  }

  return true;
}

function difference(left, right) {
  const result = new Set();

  for (const value of left) {
    if (!right.has(value)) {
      result.add(value);
    }
  }

  return result;
}
