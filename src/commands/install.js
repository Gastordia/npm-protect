import { loadConfig } from "../lib/config.js";
import { collectExternalIntelligence } from "../lib/intelligence.js";
import {
  assertSupportedFormat,
  emitOutput,
  resolveOutputFormat,
  resolveOutputPath,
} from "../lib/output.js";
import { loadProjectSnapshot } from "../lib/project.js";
import { serializeInstallPlan } from "../lib/reporters.js";

export async function runInstallCommand(args, options = {}) {
  const projectDir = String(args.flags.project ?? process.cwd());
  const configPath = typeof args.flags.config === "string" ? args.flags.config : null;
  const format = resolveOutputFormat(args.flags);
  const outputPath = resolveOutputPath(args.flags);
  assertSupportedFormat("install", format, ["text", "json", "markdown"]);

  const project = await loadProjectSnapshot(projectDir);
  const configState = await loadConfig(projectDir, configPath);
  const localPackages = (project.lockfile?.packages ?? [])
    .filter((pkg) => pkg.hasInstallScript)
    .map((pkg) => normalizeLocalInstallScriptPackage(pkg));
  const recoveredPackages = await collectRecoveredLifecycleScriptPackages(
    project,
    configState.config,
    args.flags,
    options,
  );
  const packagesWithScripts = mergeInstallScriptPackages(localPackages, recoveredPackages);
  const approved = packagesWithScripts.filter((pkg) =>
    isApproved(configState.config.allowedInstallScripts, pkg.name, pkg.version),
  );
  const unapproved = packagesWithScripts.filter(
    (pkg) => !isApproved(configState.config.allowedInstallScripts, pkg.name, pkg.version),
  );

  const plan = {
    project: {
      dir: project.dir,
      name: project.packageName,
      version: project.packageVersion,
    },
    mode: configState.config.mode,
    recommendedSteps: buildRecommendedSteps(approved),
    stats: {
      packagesWithInstallScripts: packagesWithScripts.length,
      recoveredLifecycleScriptPackages: recoveredPackages.length,
      approvedPackages: approved.length,
      unapprovedPackages: unapproved.length,
    },
    approved: approved.map(serializePlanPackage),
    unapproved: unapproved.map(serializePlanPackage),
  };

  await emitOutput(serializeInstallPlan(plan, format), outputPath);
}

function isApproved(approvedEntries, packageName, version) {
  const exact = `${packageName}@${version}`;
  return approvedEntries.includes(packageName) || approvedEntries.includes(exact);
}

function buildRecommendedSteps(approvedPackages) {
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

  return (intelligence.recoveredLifecycleScriptPackages ?? []).map((pkg) => ({
    name: pkg.name,
    version: pkg.version,
    path: pkg.packagePath,
    source: "tarball",
    scriptNames: pkg.scriptNames ?? [],
  }));
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
