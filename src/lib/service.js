import { execFile, spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { buildApprovalCommand } from "./approvals.js";
import { loadConfig } from "./config.js";
import { collectExternalIntelligence } from "./intelligence.js";
import { buildInstallPlan } from "./install-plan.js";
import { evaluateProjectWithIntelligence } from "./policy.js";
import { fileExists, loadProjectSnapshot } from "./project.js";

const execFileAsync = promisify(execFile);
const NPM_INSTALL_COMMANDS = new Set(["install", "i", "ci", "add", "update", "up"]);
const PNPM_MUTATING_COMMANDS = new Set(["add", "install", "i", "update", "up", "upgrade"]);
const YARN_MUTATING_COMMANDS = new Set(["add", "install", "up", "upgrade"]);
const WRAPPED_TOOLS = ["npm", "npx", "pnpm", "pnpx", "yarn", "yarnpkg"];
const SNAPSHOT_FILENAMES = ["package.json", "package-lock.json", "npm-shrinkwrap.json"];
const DEFAULT_SERVICE_FLAGS = {
  online: true,
  "inspect-tarballs": true,
};
const DEFAULT_BIN_DIR = path.join(os.homedir(), ".local", "bin");

export async function installProtectionService(options = {}, deps = {}) {
  const binDir = path.resolve(options.binDir ?? deps.binDir ?? DEFAULT_BIN_DIR);
  const manifestPath = path.join(binDir, "npm-protect-service.json");
  const cliPath = path.resolve(
    options.cliPath ?? deps.cliPath ?? fileURLToPath(new URL("../../bin/npm-protect.js", import.meta.url)),
  );
  const nodePath = path.resolve(options.nodePath ?? deps.nodePath ?? process.execPath);
  const pathValue = options.pathValue ?? deps.pathValue ?? process.env.PATH ?? "";
  const toolNames = normalizeToolNames(options.toolNames ?? deps.toolNames ?? WRAPPED_TOOLS);
  const resolvedExecutablePaths = {};
  const wrappers = [];

  await mkdir(binDir, { recursive: true });

  for (const toolName of toolNames) {
    const wrapperPath = path.join(binDir, toolName);
    await assertSafeWrapperTarget(wrapperPath, toolName);
    await writeFile(
      wrapperPath,
      createToolWrapperScript({
        nodePath,
        cliPath,
        binDir,
        toolName,
      }),
      "utf8",
    );
    await chmod(wrapperPath, 0o755);
    wrappers.push({
      name: toolName,
      wrapperPath,
    });
    resolvedExecutablePaths[toolName] = await safeResolveRealExecutable(toolName, deps, {
      wrapperBinDir: binDir,
    });
  }

  await writeFile(
    manifestPath,
    JSON.stringify(
      {
        manifestPath,
        binDir,
        cliPath,
        nodePath,
        toolNames,
        wrappers,
        resolvedExecutablePaths,
        installedAt: new Date().toISOString(),
      },
      null,
      2,
    ),
    "utf8",
  );

  return {
    wrapperPath: path.join(binDir, "npm"),
    wrapperPaths: Object.fromEntries(wrappers.map((wrapper) => [wrapper.name, wrapper.wrapperPath])),
    wrappers,
    manifestPath,
    binDir,
    cliPath,
    nodePath,
    realNpmPath: resolvedExecutablePaths.npm ?? null,
    resolvedExecutablePaths,
    pathActive: isBinDirAheadInPath(binDir, pathValue),
    shellSnippet: `export PATH="${binDir}:$PATH"`,
  };
}

export async function uninstallProtectionService(options = {}) {
  const binDir = path.resolve(options.binDir ?? DEFAULT_BIN_DIR);
  const manifestPath = path.join(binDir, "npm-protect-service.json");
  const manifest = await loadServiceManifest(manifestPath);
  const toolNames = normalizeToolNames(options.toolNames ?? manifest?.toolNames ?? WRAPPED_TOOLS);
  const removedWrappers = [];
  const skippedWrappers = [];

  for (const toolName of toolNames) {
    const wrapperPath = path.join(binDir, toolName);
    if (!(await fileExists(wrapperPath))) {
      continue;
    }

    const content = await readFile(wrapperPath, "utf8").catch(() => null);
    if (typeof content === "string" && isManagedWrapperContent(content, toolName)) {
      await rm(wrapperPath, { force: true });
      removedWrappers.push({
        name: toolName,
        wrapperPath,
      });
      continue;
    }

    skippedWrappers.push({
      name: toolName,
      wrapperPath,
    });
  }

  await rm(manifestPath, { force: true });

  return {
    wrapperPath: path.join(binDir, "npm"),
    wrapperPaths: Object.fromEntries(removedWrappers.map((wrapper) => [wrapper.name, wrapper.wrapperPath])),
    removedWrappers,
    skippedWrappers,
    manifestPath,
    removed: true,
  };
}

export async function getProtectionServiceStatus(options = {}, deps = {}) {
  const binDir = path.resolve(options.binDir ?? deps.binDir ?? DEFAULT_BIN_DIR);
  const manifestPath = path.join(binDir, "npm-protect-service.json");
  const pathValue = options.pathValue ?? deps.pathValue ?? process.env.PATH ?? "";
  const manifest = await loadServiceManifest(manifestPath);
  const toolNames = normalizeToolNames(manifest?.toolNames ?? options.toolNames ?? WRAPPED_TOOLS);
  const wrappers = [];

  for (const toolName of toolNames) {
    const wrapperPath = path.join(binDir, toolName);
    const wrapperExists = await fileExists(wrapperPath);
    const currentPath = await safeResolveExecutable(toolName, deps);
    wrappers.push({
      name: toolName,
      wrapperPath,
      wrapperExists,
      currentPath,
      active: wrapperExists && currentPath === wrapperPath,
    });
  }

  const npmWrapper = wrappers.find((wrapper) => wrapper.name === "npm");

  return {
    binDir,
    wrapperPath: npmWrapper?.wrapperPath ?? path.join(binDir, "npm"),
    wrapperExists: npmWrapper?.wrapperExists ?? false,
    manifestPath,
    manifestExists: Boolean(manifest),
    pathActive: isBinDirAheadInPath(binDir, pathValue),
    currentNpmPath: npmWrapper?.currentPath ?? null,
    active: npmWrapper?.active ?? false,
    wrappers,
    manifest,
  };
}

export async function runProtectedNpmCommand(argv, options = {}, deps = {}) {
  return runProtectedPackageManagerCommand("npm", argv, options, deps);
}

export async function runProtectedPackageManagerCommand(toolName, argv, options = {}, deps = {}) {
  const args = [...argv];
  const cwd = path.resolve(options.cwd ?? process.cwd());
  const runner = deps.runProcess ?? runProcess;
  const wrapperBinDir = options.wrapperBinDir ?? process.env.NPM_PROTECT_SERVICE_BIN_DIR ?? null;
  const invocation = classifyInvocation(toolName, args);

  if (invocation.kind === "block") {
    console.error(invocation.message);
    return {
      exitCode: 2,
      blocked: true,
      reason: invocation.reason,
    };
  }

  const realToolPath = path.resolve(
    options.realToolPath ??
      (await resolveRealExecutable(toolName, deps, {
        wrapperBinDir,
      })),
  );
  const toolEnv = buildProtectedEnv(toolName, realToolPath, wrapperBinDir);

  if (invocation.kind === "pass-through") {
    return passThroughCommand(realToolPath, args, { cwd, env: toolEnv }, runner);
  }

  if (invocation.kind === "one-shot-exec") {
    const realNpmPath = path.resolve(
      options.realNpmPath ??
        (await resolveRealExecutable("npm", deps, {
          wrapperBinDir,
        })),
    );
    const review = await preflightPackageSpecs(invocation.packageSpecs, {
      cwd,
      realNpmPath,
      fetchImpl: options.fetchImpl,
      now: options.now,
      reviewFlags: options.reviewFlags,
      runner,
      wrapperBinDir,
    });

    if (review.previewResult && review.previewResult.exitCode !== 0) {
      return review.previewResult;
    }

    if (review.report?.riskVerdict === "block") {
      printBlockingFindings(review.report, "one-off package execution", cwd);
      return {
        exitCode: 2,
        blocked: true,
        report: review.report,
      };
    }

    return passThroughCommand(realToolPath, args, { cwd, env: toolEnv }, runner);
  }

  return runProtectedNpmInstall(args, {
    cwd,
    realToolPath,
    fetchImpl: options.fetchImpl,
    now: options.now,
    reviewFlags: options.reviewFlags,
    runner,
    env: toolEnv,
  });
}

export function createToolWrapperScript({ nodePath, cliPath, binDir, toolName }) {
  return `#!/usr/bin/env sh
export NPM_PROTECT_SERVICE_BIN_DIR=${quoteForShell(binDir)}
export NPM_PROTECT_TOOL=${quoteForShell(toolName)}
exec ${quoteForShell(nodePath)} ${quoteForShell(cliPath)} service run --tool ${quoteForShell(toolName)} -- "$@"
`;
}

async function runProtectedNpmInstall(
  args,
  {
    cwd,
    realToolPath,
    fetchImpl,
    now,
    reviewFlags,
    runner,
    env,
  },
) {
  const command = args[0];
  const projectDir = resolveProjectDirFromNpmArgs(cwd, args);

  if (!command) {
    return passThroughCommand(realToolPath, args, { cwd, env }, runner);
  }

  if (hasGlobalInstallFlag(args)) {
    console.error(
      "npm-protect blocked this command: global npm installs are not supported by the protection shim yet.",
    );
    return { exitCode: 2, blocked: true };
  }

  const snapshots = await snapshotProjectFiles(projectDir);

  if (command !== "ci") {
    const previewResult = await runner(realToolPath, buildPreviewArgs(args), {
      cwd: projectDir,
      env,
      stdio: "inherit",
    });
    if (previewResult.exitCode !== 0) {
      await restoreProjectFiles(projectDir, snapshots);
      return previewResult;
    }
  }

  let project;
  let configState;
  let intelligence;
  let report;
  let plan;

  try {
    project = await loadProjectSnapshot(projectDir);
    configState = await loadConfig(projectDir, null);
    intelligence = await collectExternalIntelligence(project, configState.config, {
      flags: {
        ...DEFAULT_SERVICE_FLAGS,
        ...(reviewFlags ?? {}),
      },
      fetchImpl,
      now,
    });
    report = evaluateProjectWithIntelligence(project, configState.config, {
      validationErrors: configState.validationErrors,
      intelligence,
    });

    if (report.riskVerdict === "block") {
      await restoreProjectFiles(projectDir, snapshots);
      printBlockingFindings(report, "install", projectDir);
      return {
        exitCode: 2,
        blocked: true,
        report,
      };
    }

    plan = await buildInstallPlan(project, configState.config, {
      flags: {
        "inspect-tarballs": true,
      },
      recoveredPackages: intelligence.recoveredLifecycleScriptPackages,
      fetchImpl,
      now,
    });
  } catch (error) {
    await restoreProjectFiles(projectDir, snapshots);
    throw error;
  }

  const installResult = await runner(realToolPath, ensureIgnoreScripts(args), {
    cwd: projectDir,
    env,
    stdio: "inherit",
  });
  if (installResult.exitCode !== 0) {
    return {
      ...installResult,
      report,
      plan,
    };
  }

  const approvedPackageNames = [...new Set(plan.approved.map((pkg) => pkg.name))];
  if (approvedPackageNames.length > 0) {
    const rebuildResult = await runner(realToolPath, ["rebuild", ...approvedPackageNames], {
      cwd: projectDir,
      env,
      stdio: "inherit",
    });
    if (rebuildResult.exitCode !== 0) {
      return {
        ...rebuildResult,
        report,
        plan,
      };
    }
  }

  return {
    exitCode: 0,
    report,
    plan,
  };
}

async function preflightPackageSpecs(
  packageSpecs,
  {
    cwd,
    realNpmPath,
    fetchImpl,
    now,
    reviewFlags,
    runner,
    wrapperBinDir,
  },
) {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-preflight-"));

  try {
    await writeFile(
      path.join(tempDir, "package.json"),
      JSON.stringify(
        {
          name: "npm-protect-preflight",
          version: "0.0.0",
          private: true,
        },
        null,
        2,
      ),
      "utf8",
    );

    const previewResult = await runner(
      realNpmPath,
      ["install", "--package-lock-only", "--ignore-scripts", ...packageSpecs],
      {
        cwd: tempDir,
        env: buildProtectedEnv("npm", realNpmPath, wrapperBinDir),
        stdio: "inherit",
      },
    );
    if (previewResult.exitCode !== 0) {
      return {
        previewResult,
      };
    }

    const project = await loadProjectSnapshot(tempDir);
    const configState = await loadConfig(cwd, null);
    const intelligence = await collectExternalIntelligence(project, configState.config, {
      flags: {
        ...DEFAULT_SERVICE_FLAGS,
        ...(reviewFlags ?? {}),
      },
      fetchImpl,
      now,
    });
    const report = evaluateProjectWithIntelligence(project, configState.config, {
      validationErrors: configState.validationErrors,
      intelligence,
    });

    return {
      report,
    };
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

function classifyInvocation(toolName, args) {
  if (toolName === "npm") {
    return classifyNpmInvocation(args);
  }

  if (toolName === "npx") {
    return classifyNpxInvocation(args, "npx");
  }

  if (toolName === "pnpx") {
    return classifyNpxInvocation(args, "pnpx");
  }

  if (toolName === "pnpm") {
    return classifyPnpmInvocation(args);
  }

  if (toolName === "yarn" || toolName === "yarnpkg") {
    return classifyYarnInvocation(toolName, args);
  }

  return {
    kind: "pass-through",
  };
}

function classifyNpmInvocation(args) {
  const command = args[0];
  if (!command) {
    return { kind: "pass-through" };
  }

  if (NPM_INSTALL_COMMANDS.has(command)) {
    return { kind: "npm-install" };
  }

  if (command === "exec") {
    return classifyExplicitExecution("npm exec", args.slice(1));
  }

  if (command === "create") {
    const initializer = firstNonFlagArg(args.slice(1));
    if (!initializer) {
      return { kind: "pass-through" };
    }

    return {
      kind: "one-shot-exec",
      packageSpecs: [mapInitializerToCreatePackage(initializer)],
    };
  }

  if (command === "init") {
    const initializer = firstNonFlagArg(args.slice(1));
    if (!initializer || initializer === "-y" || initializer === "--yes") {
      return { kind: "pass-through" };
    }

    return {
      kind: "one-shot-exec",
      packageSpecs: [mapInitializerToCreatePackage(initializer)],
    };
  }

  return { kind: "pass-through" };
}

function classifyNpxInvocation(args, toolLabel) {
  return classifyExplicitExecution(toolLabel, args);
}

function classifyPnpmInvocation(args) {
  const command = args[0];
  if (!command) {
    return { kind: "pass-through" };
  }

  if (command === "dlx") {
    return classifyExplicitExecution("pnpm dlx", args.slice(1));
  }

  if (command === "create") {
    const initializer = firstNonFlagArg(args.slice(1));
    if (!initializer) {
      return { kind: "pass-through" };
    }

    return {
      kind: "one-shot-exec",
      packageSpecs: [mapInitializerToCreatePackage(initializer)],
    };
  }

  if (PNPM_MUTATING_COMMANDS.has(command)) {
    return unsupportedManagerBlock("pnpm", command);
  }

  return { kind: "pass-through" };
}

function classifyYarnInvocation(toolName, args) {
  const command = args[0];

  if (!command) {
    return unsupportedManagerBlock(toolName, "install");
  }

  if (command === "dlx") {
    return classifyExplicitExecution(`${toolName} dlx`, args.slice(1));
  }

  if (command === "create") {
    const initializer = firstNonFlagArg(args.slice(1));
    if (!initializer) {
      return { kind: "pass-through" };
    }

    return {
      kind: "one-shot-exec",
      packageSpecs: [mapInitializerToCreatePackage(initializer)],
    };
  }

  if (YARN_MUTATING_COMMANDS.has(command)) {
    return unsupportedManagerBlock(toolName, command);
  }

  return { kind: "pass-through" };
}

function classifyExplicitExecution(toolLabel, args, options = {}) {
  if (args.includes("--no-install")) {
    return {
      kind: "pass-through",
    };
  }

  const packageSpecs = collectPackageSpecs(args);
  if (packageSpecs.length > 0) {
    return {
      kind: "one-shot-exec",
      packageSpecs,
    };
  }

  if (hasCallStyleExecution(args) || options.requireExplicitPackage) {
    return {
      kind: "block",
      reason: "implicit_package_execution",
      message: `npm-protect blocked this command: ${toolLabel} can install and execute a package implicitly, but no explicit package spec was provided to review first.`,
    };
  }

  const implicitSpec = firstNonFlagArg(beforeDoubleDash(args));
  if (!implicitSpec) {
    return {
      kind: "pass-through",
    };
  }

  return {
    kind: "one-shot-exec",
    packageSpecs: [implicitSpec],
  };
}

function collectPackageSpecs(args) {
  const packageSpecs = [];

  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];

    if (current === "--") {
      break;
    }

    if (current === "-p" || current === "--package") {
      const next = args[index + 1];
      if (typeof next === "string" && next !== "--") {
        packageSpecs.push(next);
        index += 1;
      }
      continue;
    }

    if (current.startsWith("--package=")) {
      packageSpecs.push(current.split(/=(.+)/, 2)[1]);
    }
  }

  return packageSpecs;
}

function hasCallStyleExecution(args) {
  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];
    if (current === "--") {
      break;
    }

    if (current === "-c" || current === "--call") {
      return true;
    }
  }

  return false;
}

function unsupportedManagerBlock(toolName, command) {
  return {
    kind: "block",
    reason: "unsupported_manager_install",
    message: `npm-protect blocked this command: ${toolName} ${command} changes dependencies, but always-on lockfile-accurate mediation is only implemented for npm right now.`,
  };
}

function ensureIgnoreScripts(args) {
  if (args.includes("--ignore-scripts")) {
    return [...args];
  }

  return insertFlagBeforeDoubleDash(args, "--ignore-scripts");
}

function buildPreviewArgs(args) {
  const previewArgs = ensureIgnoreScripts(args);

  if (!previewArgs.includes("--package-lock-only")) {
    return insertFlagBeforeDoubleDash(previewArgs, "--package-lock-only");
  }

  return previewArgs;
}

function insertFlagBeforeDoubleDash(args, flag) {
  const separatorIndex = args.indexOf("--");
  if (separatorIndex === -1) {
    return [...args, flag];
  }

  return [
    ...args.slice(0, separatorIndex),
    flag,
    ...args.slice(separatorIndex),
  ];
}

function hasGlobalInstallFlag(args) {
  return args.includes("-g") || args.includes("--global");
}

function resolveProjectDirFromNpmArgs(fallbackDir, args) {
  const prefixIndex = args.findIndex((arg) => arg === "--prefix");
  if (prefixIndex !== -1 && typeof args[prefixIndex + 1] === "string") {
    return path.resolve(args[prefixIndex + 1]);
  }

  const inlinePrefix = args.find((arg) => arg.startsWith("--prefix="));
  if (inlinePrefix) {
    return path.resolve(inlinePrefix.split("=", 2)[1]);
  }

  return fallbackDir;
}

async function resolveRealExecutable(name, deps = {}, options = {}) {
  if (typeof deps.realExecutablePaths?.[name] === "string" && deps.realExecutablePaths[name].length > 0) {
    return deps.realExecutablePaths[name];
  }

  const envKey = realExecutableEnvKey(name);
  if (typeof process.env[envKey] === "string" && process.env[envKey].length > 0) {
    return process.env[envKey];
  }

  const candidates = await resolveExecutableCandidates(name);
  const wrapperBinDir = options.wrapperBinDir ? path.resolve(options.wrapperBinDir) : null;
  const filtered = wrapperBinDir
    ? candidates.filter((candidate) => path.dirname(candidate) !== wrapperBinDir)
    : candidates;

  if (filtered.length > 0) {
    return filtered[0];
  }

  if (candidates.length > 0) {
    return candidates[0];
  }

  throw new Error(`unable to resolve a real executable for ${name}`);
}

async function safeResolveRealExecutable(name, deps = {}, options = {}) {
  try {
    return await resolveRealExecutable(name, deps, options);
  } catch (error) {
    return null;
  }
}

async function safeResolveExecutable(name, deps = {}) {
  try {
    if (name === "npm" && typeof deps.currentNpmPath === "string") {
      return deps.currentNpmPath;
    }

    if (typeof deps.currentExecutablePaths?.[name] === "string") {
      return deps.currentExecutablePaths[name];
    }

    const result = await execFileAsync("which", [name]);
    return result.stdout.trim();
  } catch (error) {
    return null;
  }
}

async function resolveExecutableCandidates(name) {
  const result = await execFileAsync("which", ["-a", name]);
  return result.stdout
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
}

function buildProtectedEnv(toolName, realToolPath, wrapperBinDir) {
  const env = {
    ...process.env,
  };

  if (wrapperBinDir) {
    env.NPM_PROTECT_SERVICE_BIN_DIR = wrapperBinDir;
  }

  env.NPM_PROTECT_TOOL = toolName;
  env[realExecutableEnvKey(toolName)] = realToolPath;

  if (toolName === "npm") {
    env.NPM_PROTECT_REAL_NPM = realToolPath;
  }

  return env;
}

function realExecutableEnvKey(name) {
  return `NPM_PROTECT_REAL_${String(name).replace(/[^a-z0-9]+/giu, "_").toUpperCase()}`;
}

async function assertSafeWrapperTarget(wrapperPath, toolName) {
  if (!(await fileExists(wrapperPath))) {
    return;
  }

  const content = await readFile(wrapperPath, "utf8").catch(() => null);
  if (typeof content === "string" && isManagedWrapperContent(content, toolName)) {
    return;
  }

  throw new Error(
    `refusing to overwrite ${wrapperPath} because it is not an npm-protect managed wrapper`,
  );
}

function isManagedWrapperContent(content, toolName) {
  return content.includes("service run --tool") && content.includes(`NPM_PROTECT_TOOL='${toolName}'`);
}

async function loadServiceManifest(manifestPath) {
  if (!(await fileExists(manifestPath))) {
    return null;
  }

  return JSON.parse(await readFile(manifestPath, "utf8"));
}

function normalizeToolNames(toolNames) {
  const source = Array.isArray(toolNames) && toolNames.length > 0 ? toolNames : WRAPPED_TOOLS;
  return [...new Set(source.map((toolName) => String(toolName).trim()).filter(Boolean))];
}

async function passThroughCommand(realToolPath, args, options, runner) {
  return runner(realToolPath, args, {
    cwd: options.cwd,
    env: options.env,
    stdio: "inherit",
  });
}

async function runProcess(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: options.stdio ?? "inherit",
    });

    child.once("error", reject);
    child.once("exit", (exitCode) => {
      resolve({
        exitCode: exitCode ?? 1,
      });
    });
  });
}

async function snapshotProjectFiles(projectDir) {
  const snapshots = new Map();

  for (const filename of SNAPSHOT_FILENAMES) {
    const filePath = path.join(projectDir, filename);
    if (await fileExists(filePath)) {
      snapshots.set(filename, {
        exists: true,
        content: await readFile(filePath, "utf8"),
      });
      continue;
    }

    snapshots.set(filename, {
      exists: false,
      content: null,
    });
  }

  return snapshots;
}

async function restoreProjectFiles(projectDir, snapshots) {
  for (const [filename, snapshot] of snapshots.entries()) {
    const filePath = path.join(projectDir, filename);

    if (!snapshot.exists) {
      await rm(filePath, { force: true });
      continue;
    }

    await writeFile(filePath, snapshot.content, "utf8");
  }
}

function printBlockingFindings(report, actionLabel, projectDir = null) {
  console.error(`npm-protect blocked this ${actionLabel} because the requested dependency state is unsafe:`);

  for (const finding of report.findings.filter((finding) => finding.severity === "error")) {
    console.error(`- ${finding.code}: ${finding.message}`);
  }

  const approvalSuggestions = new Map();
  for (const finding of report.findings) {
    if (!["unreviewed_install_script", "tarball_declares_lifecycle_script"].includes(finding.code)) {
      continue;
    }

    if (!finding.packageName || !finding.packageVersion) {
      continue;
    }

    const command = buildApprovalCommand(finding.packageName, finding.packageVersion, {
      projectDir,
      expiresDays: 7,
    });
    approvalSuggestions.set(`${finding.packageName}@${finding.packageVersion}`, command);
  }

  if (approvalSuggestions.size > 0) {
    console.error("");
    console.error("Suggested review approval commands:");
    for (const [label, command] of approvalSuggestions.entries()) {
      console.error(`- ${label}: ${command}`);
    }
  }
}

function quoteForShell(value) {
  return `'${String(value).replaceAll("'", `'\"'\"'`)}'`;
}

function isBinDirAheadInPath(binDir, pathValue) {
  if (!pathValue) {
    return false;
  }

  const entries = pathValue.split(path.delimiter);
  return entries[0] === binDir;
}

function beforeDoubleDash(args) {
  const separatorIndex = args.indexOf("--");
  return separatorIndex === -1 ? args : args.slice(0, separatorIndex);
}

function firstNonFlagArg(args) {
  for (const arg of beforeDoubleDash(args)) {
    if (!arg.startsWith("-")) {
      return arg;
    }
  }

  return null;
}

function mapInitializerToCreatePackage(initializer) {
  if (initializer.startsWith("@")) {
    const match = initializer.match(/^(@[^/]+)\/([^@]+)(@.+)?$/u);
    if (!match) {
      return initializer;
    }

    const [, scope, name, version = ""] = match;
    if (name.startsWith("create-")) {
      return `${scope}/${name}${version}`;
    }

    return `${scope}/create-${name}${version}`;
  }

  const match = initializer.match(/^([^@]+)(@.+)?$/u);
  if (!match) {
    return initializer;
  }

  const [, name, version = ""] = match;
  if (name.startsWith("create-")) {
    return `${name}${version}`;
  }

  return `create-${name}${version}`;
}
