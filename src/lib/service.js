import { execFile, spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
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
const COREPACK_MANAGED_TOOLS = new Set(["npm", "npx", "pnpm", "pnpx", "yarn", "yarnpkg"]);
const WRAPPED_TOOLS = ["npm", "npx", "pnpm", "pnpx", "yarn", "yarnpkg", "corepack"];
const SNAPSHOT_ROOT_FILENAMES = [
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  "yarn.lock",
];
const SUPPORTED_LOCKFILE_FILENAMES = [
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
];
const DEFAULT_SERVICE_FLAGS = {
  online: true,
  "inspect-tarballs": true,
};
const DEFAULT_BIN_DIR = path.join(os.homedir(), ".local", "bin");
const NODE_CHILD_HOOK_FILENAME = "npm-protect-node-hook.cjs";
const SERVICE_ENV_FILENAME = "npm-protect-service-env.sh";

export async function installProtectionService(options = {}, deps = {}) {
  const binDir = path.resolve(options.binDir ?? deps.binDir ?? DEFAULT_BIN_DIR);
  const manifestPath = path.join(binDir, "npm-protect-service.json");
  const nodeHookPath = path.join(binDir, NODE_CHILD_HOOK_FILENAME);
  const envScriptPath = path.join(binDir, SERVICE_ENV_FILENAME);
  const cliPath = path.resolve(
    options.cliPath ?? deps.cliPath ?? fileURLToPath(new URL("../../bin/npm-protect.js", import.meta.url)),
  );
  const nodePath = path.resolve(options.nodePath ?? deps.nodePath ?? process.execPath);
  const pathValue = options.pathValue ?? deps.pathValue ?? process.env.PATH ?? "";
  const toolNames = normalizeToolNames(options.toolNames ?? deps.toolNames ?? WRAPPED_TOOLS);
  const resolvedExecutablePaths = {};
  const wrappers = [];

  await mkdir(binDir, { recursive: true });
  await writeFile(
    nodeHookPath,
    createNodeChildProcessHookScript({
      binDir,
      toolNames,
    }),
    "utf8",
  );
  await chmod(nodeHookPath, 0o644);
  await writeFile(
    envScriptPath,
    createServiceEnvScript({
      binDir,
      nodeHookPath,
    }),
    "utf8",
  );
  await chmod(envScriptPath, 0o644);

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
        nodeHookPath,
        envScriptPath,
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
    nodeHookPath,
    envScriptPath,
    realNpmPath: resolvedExecutablePaths.npm ?? null,
    resolvedExecutablePaths,
    pathActive: isBinDirAheadInPath(binDir, pathValue),
    pathShellSnippet: `export PATH="${binDir}:$PATH"`,
    shellSnippet: `. ${quoteForShell(envScriptPath)}`,
    activationSnippet: `. ${quoteForShell(envScriptPath)}`,
  };
}

export async function uninstallProtectionService(options = {}) {
  const binDir = path.resolve(options.binDir ?? DEFAULT_BIN_DIR);
  const manifestPath = path.join(binDir, "npm-protect-service.json");
  const manifest = await loadServiceManifest(manifestPath);
  const nodeHookPath = manifest?.nodeHookPath ?? path.join(binDir, NODE_CHILD_HOOK_FILENAME);
  const envScriptPath = manifest?.envScriptPath ?? path.join(binDir, SERVICE_ENV_FILENAME);
  const toolNames = normalizeToolNames(options.toolNames ?? manifest?.toolNames ?? WRAPPED_TOOLS);
  const removedWrappers = [];
  const skippedWrappers = [];
  const removedHelperFiles = [];

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

  for (const helperPath of [nodeHookPath, envScriptPath]) {
    if (await fileExists(helperPath)) {
      await rm(helperPath, { force: true });
      removedHelperFiles.push(helperPath);
    }
  }

  await rm(manifestPath, { force: true });

  return {
    wrapperPath: path.join(binDir, "npm"),
    wrapperPaths: Object.fromEntries(removedWrappers.map((wrapper) => [wrapper.name, wrapper.wrapperPath])),
    removedWrappers,
    skippedWrappers,
    removedHelperFiles,
    manifestPath,
    nodeHookPath,
    envScriptPath,
    removed: true,
  };
}

export async function getProtectionServiceStatus(options = {}, deps = {}) {
  const binDir = path.resolve(options.binDir ?? deps.binDir ?? DEFAULT_BIN_DIR);
  const manifestPath = path.join(binDir, "npm-protect-service.json");
  const pathValue = options.pathValue ?? deps.pathValue ?? process.env.PATH ?? "";
  const processEnv = options.processEnv ?? deps.processEnv ?? process.env;
  const manifest = await loadServiceManifest(manifestPath);
  const nodeHookPath = manifest?.nodeHookPath ?? path.join(binDir, NODE_CHILD_HOOK_FILENAME);
  const envScriptPath = manifest?.envScriptPath ?? path.join(binDir, SERVICE_ENV_FILENAME);
  const toolNames = normalizeToolNames(manifest?.toolNames ?? options.toolNames ?? WRAPPED_TOOLS);
  const wrappers = [];

  for (const toolName of toolNames) {
    const wrapperPath = path.join(binDir, toolName);
    const wrapperState = await inspectWrapperState(wrapperPath, toolName);
    const currentPath = await safeResolveExecutable(toolName, deps);
    wrappers.push({
      name: toolName,
      wrapperPath,
      fileExists: wrapperState.fileExists,
      managed: wrapperState.managed,
      wrapperExists: wrapperState.managed,
      currentPath,
      active: wrapperState.managed && currentPath === wrapperPath,
    });
  }

  const npmWrapper = wrappers.find((wrapper) => wrapper.name === "npm");
  const rebuildSandboxSupport = await getLifecycleSandboxSupport(deps, {
    wrapperBinDir: binDir,
  });
  const absolutePathProtection = await getAbsolutePathProtectionStatus({
    binDir,
    nodeHookPath,
    envScriptPath,
    processEnv,
  });

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
    rebuildSandboxSupport,
    nodeHookPath,
    envScriptPath,
    activationSnippet: `. ${quoteForShell(envScriptPath)}`,
    absolutePathProtection,
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

  if (invocation.kind === "corepack-delegate") {
    const delegateOptions = { ...options };
    delete delegateOptions.realToolPath;
    return runProtectedPackageManagerCommand(invocation.toolName, invocation.args, delegateOptions, deps);
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

  return runProtectedManagedInstall(toolName, args, {
    cwd,
    realToolPath,
    fetchImpl: options.fetchImpl,
    now: options.now,
    reviewFlags: options.reviewFlags,
    runner,
    env: toolEnv,
    executableDeps: deps,
    wrapperBinDir,
  });
}

export function createToolWrapperScript({ nodePath, cliPath, binDir, toolName }) {
  return `#!/usr/bin/env sh
export NPM_PROTECT_SERVICE_BIN_DIR=${quoteForShell(binDir)}
export NPM_PROTECT_TOOL=${quoteForShell(toolName)}
exec ${quoteForShell(nodePath)} ${quoteForShell(cliPath)} service run --tool ${quoteForShell(toolName)} -- "$@"
`;
}

function createServiceEnvScript({ binDir, nodeHookPath }) {
  return `#!/usr/bin/env sh
export PATH=${quoteForShell(binDir)}:\${PATH:-}
export NPM_PROTECT_SERVICE_BIN_DIR=${quoteForShell(binDir)}
export NPM_PROTECT_FORCE_WRAPPERS=1
case "\${NODE_OPTIONS-}" in
  *${quoteForShell(nodeHookPath)}*)
    ;;
  *)
    export NODE_OPTIONS="--require ${nodeHookPath}\${NODE_OPTIONS:+ \${NODE_OPTIONS}}"
    ;;
esac
`;
}

function createNodeChildProcessHookScript({ binDir, toolNames }) {
  return `const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const managedTools = new Set(${JSON.stringify(normalizeToolNames(toolNames))});
const serviceBinDir =
  typeof process.env.NPM_PROTECT_SERVICE_BIN_DIR === "string" &&
  process.env.NPM_PROTECT_SERVICE_BIN_DIR.length > 0
    ? path.resolve(process.env.NPM_PROTECT_SERVICE_BIN_DIR)
    : ${JSON.stringify(path.resolve(binDir))};
const forceWrappers = process.env.NPM_PROTECT_FORCE_WRAPPERS === "1";

if (forceWrappers && serviceBinDir && process.env.NPM_PROTECT_BYPASS_HOOK !== "1") {
  const wrapperPaths = new Map(
    [...managedTools].map((toolName) => [toolName, path.join(serviceBinDir, toolName)]),
  );
  const originalSpawn = childProcess.spawn;
  const originalSpawnSync = childProcess.spawnSync;
  const originalExecFile = childProcess.execFile;
  const originalExecFileSync = childProcess.execFileSync;

  childProcess.spawn = function patchedSpawn(file, args, options) {
    return originalSpawn.call(this, rewriteManagedTool(file, options), args, options);
  };

  childProcess.spawnSync = function patchedSpawnSync(file, args, options) {
    return originalSpawnSync.call(this, rewriteManagedTool(file, options), args, options);
  };

  childProcess.execFile = function patchedExecFile(file, ...rest) {
    return originalExecFile.call(this, rewriteManagedTool(file, extractOptions(rest)), ...rest);
  };

  childProcess.execFileSync = function patchedExecFileSync(file, ...rest) {
    return originalExecFileSync.call(this, rewriteManagedTool(file, extractOptions(rest)), ...rest);
  };

  function rewriteManagedTool(file, options) {
    if (typeof file !== "string" || file.length === 0) {
      return file;
    }

    if (process.env.NPM_PROTECT_BYPASS_HOOK === "1" || options?.env?.NPM_PROTECT_BYPASS_HOOK === "1") {
      return file;
    }

    const toolName = path.basename(file);
    if (!managedTools.has(toolName)) {
      return file;
    }

    const wrapperPath = wrapperPaths.get(toolName);
    if (!wrapperPath || !fs.existsSync(wrapperPath)) {
      return file;
    }

    const resolvedFile = path.isAbsolute(file) ? path.resolve(file) : null;
    if (resolvedFile === wrapperPath) {
      return file;
    }

    return wrapperPath;
  }

  function extractOptions(rest) {
    if (rest.length === 0) {
      return undefined;
    }

    if (Array.isArray(rest[0])) {
      return isOptionsObject(rest[1]) ? rest[1] : undefined;
    }

    return isOptionsObject(rest[0]) ? rest[0] : undefined;
  }

  function isOptionsObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }
}
`;
}

async function runProtectedManagedInstall(
  toolName,
  args,
  {
    cwd,
    realToolPath,
    fetchImpl,
    now,
    reviewFlags,
    runner,
    env,
    executableDeps,
    wrapperBinDir,
  },
) {
  const command = args[0];
  const projectDir = await resolveProjectDirFromPackageManagerArgs(toolName, cwd, args);

  if (!command) {
    return passThroughCommand(realToolPath, args, { cwd, env }, runner);
  }

  if (hasGlobalInstallFlag(args)) {
    console.error(
      `npm-protect blocked this command: global ${toolName} installs are not supported by the protection shim yet.`,
    );
    return { exitCode: 2, blocked: true };
  }

  let optionsYarnFlavor = null;
  if (toolName === "yarn" || toolName === "yarnpkg") {
    const yarnSupport = await detectYarnManagedInstallSupport(projectDir);
    optionsYarnFlavor = yarnSupport.flavor;
  }

  const snapshots = await snapshotProjectFiles(projectDir);

  if (!shouldSkipPreview(toolName, command)) {
    const previewState = await buildManagedPreview(toolName, args, optionsYarnFlavor);
    let previewResult;
    try {
      previewResult = await runner(realToolPath, previewState.args, {
        cwd,
        env,
        stdio: "inherit",
      });
    } finally {
      await previewState.cleanup();
    }
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
  let rebuildExecution = null;

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
      securityWarnings: configState.securityWarnings,
      intelligence,
    });

    if (report.riskVerdict === "block") {
      await restoreProjectFiles(projectDir, snapshots);
      printBlockingFindings(report, `${toolName} install`, projectDir);
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
      packageManagerFlavor: optionsYarnFlavor,
      rebuildPackageManager: optionsYarnFlavor === "classic" ? "npm" : undefined,
      fetchImpl,
      now,
    });

    if (plan.rebuildStrategy.status === "blocked") {
      await restoreProjectFiles(projectDir, snapshots);
      printRebuildSafetyBlock(plan.rebuildStrategy, toolName);
      return {
        exitCode: 2,
        blocked: true,
        reason: "unsafe_rebuild_targeting",
        report,
        plan,
      };
    }

    const rebuildArgs = Array.isArray(plan.rebuildStrategy?.args) ? plan.rebuildStrategy.args : [];
    if (rebuildArgs.length > 0) {
      const rebuildToolPath =
        optionsYarnFlavor === "classic"
          ? await resolveRealExecutable("npm", executableDeps, { wrapperBinDir })
          : realToolPath;
      rebuildExecution = await resolveLifecycleRebuildExecution({
        config: configState.config,
        realToolPath: path.resolve(rebuildToolPath),
        rebuildArgs,
        cwd,
        projectDir,
        env,
        executableDeps,
        wrapperBinDir,
      });

      if (rebuildExecution.blocked) {
        await restoreProjectFiles(projectDir, snapshots);
        console.error(rebuildExecution.message);
        return {
          exitCode: 2,
          blocked: true,
          reason: rebuildExecution.reason,
          report,
          plan,
        };
      }
    }
  } catch (error) {
    await restoreProjectFiles(projectDir, snapshots);
    throw error;
  }

  const installResult = await runner(
    realToolPath,
    buildInstallArgs(toolName, args, optionsYarnFlavor),
    {
      cwd,
      env,
      stdio: "inherit",
    },
  );
  if (installResult.exitCode !== 0) {
    return {
      ...installResult,
      report,
      plan,
    };
  }

  if (rebuildExecution) {
    if (rebuildExecution.warning) {
      console.error(rebuildExecution.warning);
    }

    const rebuildResult = await runner(rebuildExecution.file, rebuildExecution.args, {
      cwd,
      env: rebuildExecution.env,
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
      securityWarnings: configState.securityWarnings,
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

  if (toolName === "corepack") {
    return classifyCorepackInvocation(args);
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
    return { kind: "pnpm-install" };
  }

  return { kind: "pass-through" };
}

function classifyYarnInvocation(toolName, args) {
  const command = args[0];

  if (!command) {
    return { kind: "yarn-install" };
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

  if (YARN_MUTATING_COMMANDS.has(command)) {
    return { kind: "yarn-install" };
  }

  return { kind: "pass-through" };
}

function classifyCorepackInvocation(args) {
  const delegate = extractCorepackDelegate(args);
  if (!delegate) {
    return {
      kind: "pass-through",
    };
  }

  return {
    kind: "corepack-delegate",
    toolName: delegate.toolName,
    args: delegate.args,
  };
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
    message: `npm-protect blocked this command: ${toolName} ${command} changes dependencies, but always-on lockfile-accurate mediation is only implemented for npm, pnpm, and modern Yarn right now.`,
  };
}

function ensureIgnoreScripts(args) {
  const normalizedArgs = [];

  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];
    if (current === "--") {
      normalizedArgs.push(...args.slice(index));
      break;
    }
    if (current === "--ignore-scripts") {
      if (args[index + 1] === "true" || args[index + 1] === "false") {
        index += 1;
      }
      continue;
    }
    if (current.startsWith("--ignore-scripts=")) {
      continue;
    }
    normalizedArgs.push(current);
  }

  return insertFlagBeforeDoubleDash(normalizedArgs, "--ignore-scripts");
}

function buildPreviewArgs(toolName, args, options = {}) {
  if (toolName === "yarn" || toolName === "yarnpkg") {
    if (options.yarnFlavor === "classic") {
      const withoutUnsafeOverrides = removeOptionWithValue(
        removeYarnModeFlags(args),
        "--modules-folder",
      );
      return insertFlagsBeforeDoubleDash(ensureIgnoreScripts(withoutUnsafeOverrides), [
        "--modules-folder",
        options.modulesFolder,
      ]);
    }
    return ensureYarnMode(args, "update-lockfile");
  }

  const previewArgs = ensureIgnoreScripts(args);
  const previewFlag = toolName === "pnpm" ? "--lockfile-only" : "--package-lock-only";

  if (!previewArgs.includes(previewFlag)) {
    return insertFlagBeforeDoubleDash(previewArgs, previewFlag);
  }

  return previewArgs;
}

function buildInstallArgs(toolName, args, yarnFlavor = null) {
  if (toolName === "yarn" || toolName === "yarnpkg") {
    if (yarnFlavor === "classic") {
      return ensureIgnoreScripts(
        removeOptionWithValue(removeYarnModeFlags(args), "--modules-folder"),
      );
    }
    return ensureYarnMode(args, "skip-build");
  }

  return ensureIgnoreScripts(args);
}

async function buildManagedPreview(toolName, args, yarnFlavor) {
  if ((toolName === "yarn" || toolName === "yarnpkg") && yarnFlavor === "classic") {
    const previewRoot = await mkdtemp(path.join(os.tmpdir(), "npm-protect-yarn-preview-"));
    return {
      args: buildPreviewArgs(toolName, args, {
        yarnFlavor,
        modulesFolder: path.join(previewRoot, "node_modules"),
      }),
      cleanup: () => rm(previewRoot, { recursive: true, force: true }),
    };
  }

  return {
    args: buildPreviewArgs(toolName, args, { yarnFlavor }),
    cleanup: async () => {},
  };
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

function insertFlagsBeforeDoubleDash(args, flags) {
  const separatorIndex = args.indexOf("--");
  if (separatorIndex === -1) {
    return [...args, ...flags];
  }

  return [...args.slice(0, separatorIndex), ...flags, ...args.slice(separatorIndex)];
}

function removeOptionWithValue(args, optionName) {
  const normalizedArgs = [];

  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];
    if (current === "--") {
      normalizedArgs.push(...args.slice(index));
      break;
    }
    if (current === optionName) {
      index += 1;
      continue;
    }
    if (current.startsWith(`${optionName}=`)) {
      continue;
    }
    normalizedArgs.push(current);
  }

  return normalizedArgs;
}

function hasGlobalInstallFlag(args) {
  return args.includes("-g") || args.includes("--global");
}

async function resolveProjectDirFromPackageManagerArgs(toolName, fallbackDir, args) {
  const prefixIndex = args.findIndex((arg) => arg === "--prefix");
  if (prefixIndex !== -1 && typeof args[prefixIndex + 1] === "string") {
    return resolveManagedProjectRoot(path.resolve(args[prefixIndex + 1]));
  }

  const inlinePrefix = args.find((arg) => arg.startsWith("--prefix="));
  if (inlinePrefix) {
    return resolveManagedProjectRoot(path.resolve(inlinePrefix.split("=", 2)[1]));
  }

  if (toolName === "pnpm") {
    const dirIndex = args.findIndex((arg) => arg === "--dir" || arg === "-C");
    if (dirIndex !== -1 && typeof args[dirIndex + 1] === "string") {
      return resolveManagedProjectRoot(path.resolve(args[dirIndex + 1]));
    }

    const inlineDir = args.find((arg) => arg.startsWith("--dir="));
    if (inlineDir) {
      return resolveManagedProjectRoot(path.resolve(inlineDir.split("=", 2)[1]));
    }
  }

  if (toolName === "yarn" || toolName === "yarnpkg") {
    const cwdIndex = args.findIndex((arg) => arg === "--cwd");
    if (cwdIndex !== -1 && typeof args[cwdIndex + 1] === "string") {
      return resolveManagedProjectRoot(path.resolve(args[cwdIndex + 1]));
    }

    const inlineCwd = args.find((arg) => arg.startsWith("--cwd="));
    if (inlineCwd) {
      return resolveManagedProjectRoot(path.resolve(inlineCwd.split("=", 2)[1]));
    }
  }

  return resolveManagedProjectRoot(fallbackDir);
}

function shouldSkipPreview(toolName, command) {
  return toolName === "npm" && command === "ci";
}

function ensureYarnMode(args, mode) {
  const normalizedArgs = removeYarnModeFlags(args);
  return insertFlagBeforeDoubleDash(normalizedArgs, `--mode=${mode}`);
}

function removeYarnModeFlags(args) {
  const normalizedArgs = [];

  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];
    if (current === "--") {
      normalizedArgs.push(...args.slice(index));
      break;
    }
    if (current === "--mode") {
      index += 1;
      continue;
    }

    if (current.startsWith("--mode=")) {
      continue;
    }

    normalizedArgs.push(current);
  }

  return normalizedArgs;
}

async function resolveRealExecutable(name, deps = {}, options = {}) {
  if (typeof deps.realExecutablePaths?.[name] === "string" && deps.realExecutablePaths[name].length > 0) {
    return deps.realExecutablePaths[name];
  }

  const envKey = realExecutableEnvKey(name);
  if (typeof process.env[envKey] === "string" && process.env[envKey].length > 0) {
    return process.env[envKey];
  }

  const candidates = await resolveExecutableCandidates(name, deps);
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

async function resolveExecutableCandidates(name, deps = {}) {
  if (typeof deps.resolveExecutableCandidates === "function") {
    const resolved = await deps.resolveExecutableCandidates(name);
    if (Array.isArray(resolved)) {
      return resolved.map((candidate) => String(candidate)).filter(Boolean);
    }
  }

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
  env.NPM_PROTECT_BYPASS_HOOK = "1";

  if (toolName === "npm") {
    env.NPM_PROTECT_REAL_NPM = realToolPath;
  }

  return env;
}

function buildLifecycleExecutionEnv(env, realToolPath, wrapperBinDir) {
  const lifecycleEnv = {
    ...env,
  };

  for (const key of Object.keys(lifecycleEnv)) {
    if (key.startsWith("NPM_PROTECT_")) {
      delete lifecycleEnv[key];
    }
  }

  lifecycleEnv.PATH = buildLifecycleExecutionPath(
    lifecycleEnv.PATH ?? process.env.PATH ?? "",
    path.dirname(realToolPath),
    wrapperBinDir,
  );

  return lifecycleEnv;
}

function buildLifecycleExecutionPath(pathValue, preferredDir, wrapperBinDir) {
  const entries = String(pathValue ?? "")
    .split(path.delimiter)
    .map((entry) => entry.trim())
    .filter(Boolean);
  const filtered = [];
  const seen = new Set();
  const blocked = new Set(
    [preferredDir, wrapperBinDir]
      .filter((entry) => typeof entry === "string" && entry.length > 0)
      .map((entry) => path.resolve(entry)),
  );

  for (const entry of entries) {
    const resolvedEntry = path.resolve(entry);
    if (blocked.has(resolvedEntry)) {
      continue;
    }

    if (seen.has(resolvedEntry)) {
      continue;
    }

    seen.add(resolvedEntry);
    filtered.push(entry);
  }

  return [preferredDir, ...filtered].join(path.delimiter);
}

function realExecutableEnvKey(name) {
  return `NPM_PROTECT_REAL_${String(name).replace(/[^a-z0-9]+/giu, "_").toUpperCase()}`;
}

async function assertSafeWrapperTarget(wrapperPath, toolName) {
  const wrapperState = await inspectWrapperState(wrapperPath, toolName);
  if (!wrapperState.fileExists) {
    return;
  }

  if (wrapperState.managed) {
    return;
  }

  throw new Error(
    `refusing to overwrite ${wrapperPath} because it is not an npm-protect managed wrapper`,
  );
}

function isManagedWrapperContent(content, toolName) {
  return content.includes("service run --tool") && content.includes(`NPM_PROTECT_TOOL='${toolName}'`);
}

async function inspectWrapperState(wrapperPath, toolName) {
  if (!(await fileExists(wrapperPath))) {
    return {
      fileExists: false,
      managed: false,
    };
  }

  const content = await readFile(wrapperPath, "utf8").catch(() => null);
  return {
    fileExists: true,
    managed: typeof content === "string" && isManagedWrapperContent(content, toolName),
  };
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

async function resolveLifecycleRebuildExecution({
  config,
  realToolPath,
  rebuildArgs,
  cwd,
  projectDir,
  env,
  executableDeps,
  wrapperBinDir,
}) {
  const lifecycleEnv = buildLifecycleExecutionEnv(env, realToolPath, wrapperBinDir);
  const sandboxPolicy = normalizeRebuildSandboxPolicy(config.service?.rebuildSandbox);

  if (sandboxPolicy === "off") {
    return {
      blocked: false,
      file: realToolPath,
      args: rebuildArgs,
      env: lifecycleEnv,
      warning: null,
    };
  }

  if (process.platform !== "linux") {
    return buildLifecycleSandboxFallback(sandboxPolicy, lifecycleEnv, realToolPath, rebuildArgs, {
      reason: "unsupported_platform",
      message:
        `npm-protect ${sandboxPolicy === "require" ? "blocked this install" : "warning"}: approved install-script rebuild sandboxing currently requires Linux bubblewrap, but the current platform is ${process.platform}.`,
    });
  }

  const bwrapPath = await safeResolveRealExecutable("bwrap", executableDeps, {
    wrapperBinDir,
  });
  if (!bwrapPath) {
    return buildLifecycleSandboxFallback(sandboxPolicy, lifecycleEnv, realToolPath, rebuildArgs, {
      reason: "bwrap_unavailable",
      message:
        `npm-protect ${sandboxPolicy === "require" ? "blocked this install" : "warning"}: approved install-script rebuild sandboxing requires bubblewrap (\`bwrap\`), but it was not found in PATH.`,
    });
  }

  return {
    blocked: false,
    file: bwrapPath,
    args: buildBubblewrapArgs({
      commandPath: realToolPath,
      commandArgs: rebuildArgs,
      cwd,
      projectDir,
      env: lifecycleEnv,
    }),
    env: lifecycleEnv,
    warning: null,
  };
}

function buildLifecycleSandboxFallback(sandboxPolicy, env, realToolPath, rebuildArgs, status) {
  if (sandboxPolicy === "require") {
    return {
      blocked: true,
      reason: "rebuild_sandbox_unavailable",
      message: status.message,
    };
  }

  return {
    blocked: false,
    file: realToolPath,
    args: rebuildArgs,
    env,
    warning: status.message,
  };
}

function normalizeRebuildSandboxPolicy(value) {
  return value === "off" || value === "require" ? value : "auto";
}

async function getLifecycleSandboxSupport(deps = {}, options = {}) {
  if (process.platform !== "linux") {
    return {
      provider: "bubblewrap",
      available: false,
      executable: null,
      reason: "unsupported_platform",
      message: `bubblewrap sandboxing is only available on Linux; current platform is ${process.platform}`,
    };
  }

  const bwrapPath = await safeResolveRealExecutable("bwrap", deps, {
    wrapperBinDir: options.wrapperBinDir,
  });
  if (bwrapPath) {
    return {
      provider: "bubblewrap",
      available: true,
      executable: bwrapPath,
      reason: null,
      message: `bubblewrap sandboxing is available at ${bwrapPath}`,
    };
  }

  return {
    provider: "bubblewrap",
    available: false,
    executable: null,
    reason: "not_found",
    message:
      'bubblewrap (`bwrap`) was not found, so approved install-script rebuilds will fall back to unsandboxed execution unless `service.rebuildSandbox` is set to "require"',
  };
}

async function getAbsolutePathProtectionStatus({
  binDir,
  nodeHookPath,
  envScriptPath,
  processEnv,
}) {
  const hookExists = await fileExists(nodeHookPath);
  const envScriptExists = await fileExists(envScriptPath);
  const nodeOptions = typeof processEnv.NODE_OPTIONS === "string" ? processEnv.NODE_OPTIONS : "";
  const forceWrappers = processEnv.NPM_PROTECT_FORCE_WRAPPERS === "1";
  const configuredBinDir =
    typeof processEnv.NPM_PROTECT_SERVICE_BIN_DIR === "string"
      ? path.resolve(processEnv.NPM_PROTECT_SERVICE_BIN_DIR)
      : null;
  const nodeOptionsHasHook = nodeOptionsIncludesHook(nodeOptions, nodeHookPath);
  const active = hookExists && envScriptExists && forceWrappers && configuredBinDir === binDir && nodeOptionsHasHook;

  return {
    provider: "node-child-process-hook",
    hookPath: nodeHookPath,
    hookExists,
    envScriptPath,
    envScriptExists,
    forceWrappers,
    nodeOptionsHasHook,
    active,
    message: active
      ? `Node child-process interception is active through ${envScriptPath}`
      : `Node child-process interception is inactive; source ${envScriptPath} to catch absolute npm, npx, pnpm, yarn, and corepack invocations from Node-based tools`,
  };
}

function nodeOptionsIncludesHook(nodeOptions, nodeHookPath) {
  if (typeof nodeOptions !== "string" || nodeOptions.length === 0) {
    return false;
  }

  const normalizedHook = path.resolve(nodeHookPath);
  return nodeOptions.includes(normalizedHook);
}

function buildBubblewrapArgs({
  commandPath,
  commandArgs,
  cwd,
  projectDir,
  env,
}) {
  const homeDir = "/tmp/npm-protect-home";
  const cacheDir = "/tmp/npm-protect-cache";
  const tempDir = "/tmp/npm-protect-tmp";
  const args = [
    "--die-with-parent",
    "--new-session",
    "--unshare-net",
    "--ro-bind",
    "/",
    "/",
    "--bind",
    "/tmp",
    "/tmp",
    "--dev",
    "/dev",
    "--proc",
    "/proc",
  ];

  for (const bindPath of collectSandboxWritablePaths(projectDir, cwd)) {
    args.push("--bind", bindPath, bindPath);
  }

  args.push(
    "--dir",
    homeDir,
    "--dir",
    cacheDir,
    "--dir",
    tempDir,
    "--chdir",
    cwd,
  );

  const innerEnv = {
    ...env,
    HOME: homeDir,
    TMPDIR: tempDir,
    npm_config_cache: cacheDir,
    npm_config_tmp: tempDir,
    XDG_CACHE_HOME: cacheDir,
    YARN_CACHE_FOLDER: cacheDir,
    COREPACK_HOME: cacheDir,
  };

  for (const [key, value] of Object.entries(innerEnv)) {
    if (typeof value !== "string") {
      continue;
    }

    args.push("--setenv", key, value);
  }

  args.push("--", commandPath, ...commandArgs);
  return args;
}

function collectSandboxWritablePaths(projectDir, cwd) {
  const paths = new Set();

  for (const candidate of [projectDir, cwd]) {
    if (typeof candidate !== "string" || candidate.length === 0) {
      continue;
    }

    paths.add(path.resolve(candidate));
  }

  return [...paths];
}

async function snapshotProjectFiles(projectDir) {
  const snapshots = new Map();
  const snapshotPaths = await collectSnapshotPaths(projectDir);

  for (const relativePath of snapshotPaths) {
    const filePath = path.join(projectDir, relativePath);
    if (await fileExists(filePath)) {
      snapshots.set(relativePath, {
        exists: true,
        content: await readFile(filePath, "utf8"),
      });
      continue;
    }

    snapshots.set(relativePath, {
      exists: false,
      content: null,
    });
  }

  return snapshots;
}

async function restoreProjectFiles(projectDir, snapshots) {
  for (const [relativePath, snapshot] of snapshots.entries()) {
    const filePath = path.join(projectDir, relativePath);

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

function printRebuildSafetyBlock(rebuildStrategy, toolName) {
  console.error(
    `npm-protect blocked this ${toolName} install because approved install-script packages cannot be rebuilt safely with ${rebuildStrategy.packageManager}:`,
  );
  console.error(`- ${rebuildStrategy.message}`);
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

function extractCorepackDelegate(args) {
  const corepackArgs = beforeDoubleDash(args);

  for (let index = 0; index < corepackArgs.length; index += 1) {
    const current = corepackArgs[index];
    if (current.startsWith("-")) {
      continue;
    }

    if (!COREPACK_MANAGED_TOOLS.has(current)) {
      return null;
    }

    return {
      toolName: current,
      args: args.slice(index + 1),
    };
  }

  return null;
}

async function resolveManagedProjectRoot(startDir) {
  let currentDir = path.resolve(startDir);

  while (true) {
    if (await hasSupportedLockfile(currentDir)) {
      return currentDir;
    }

    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) {
      return path.resolve(startDir);
    }
    currentDir = parentDir;
  }
}

async function detectYarnManagedInstallSupport(projectDir) {
  const manifestPath = path.join(projectDir, "package.json");
  const yarnLockPath = path.join(projectDir, "yarn.lock");
  const yarnrcYmlPath = path.join(projectDir, ".yarnrc.yml");

  let manifest = null;
  if (await fileExists(manifestPath)) {
    manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  }

  const packageManager = typeof manifest?.packageManager === "string" ? manifest.packageManager : "";
  const versionMatch = packageManager.match(/^yarn@(\d+)/u);
  const packageManagerMajor = versionMatch ? Number(versionMatch[1]) : null;
  const hasYarnrcYml = await fileExists(yarnrcYmlPath);
  const lockfileContent = (await fileExists(yarnLockPath))
    ? await readFile(yarnLockPath, "utf8")
    : "";
  const hasModernLockMetadata = /^__metadata:/mu.test(lockfileContent);

  if (
    (packageManagerMajor !== null && packageManagerMajor >= 2) ||
    hasYarnrcYml ||
    hasModernLockMetadata
  ) {
    return {
      supported: true,
      flavor: "modern",
      reason: null,
      message: null,
    };
  }

  return {
    supported: true,
    flavor: "classic",
    reason: null,
    message: null,
  };
}

async function hasSupportedLockfile(projectDir) {
  for (const filename of SUPPORTED_LOCKFILE_FILENAMES) {
    if (await fileExists(path.join(projectDir, filename))) {
      return true;
    }
  }

  return false;
}

async function collectSnapshotPaths(projectDir) {
  const paths = new Set(SNAPSHOT_ROOT_FILENAMES);
  await collectPackageManifestPaths(projectDir, projectDir, paths);
  return [...paths].sort();
}

async function collectPackageManifestPaths(projectDir, currentDir, paths) {
  const entries = await readdir(currentDir, {
    withFileTypes: true,
  }).catch(() => []);

  for (const entry of entries) {
    const fullPath = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      if (shouldSkipSnapshotDirectory(entry.name)) {
        continue;
      }
      await collectPackageManifestPaths(projectDir, fullPath, paths);
      continue;
    }

    if (!entry.isFile() || entry.name !== "package.json") {
      continue;
    }

    const relativePath = path.relative(projectDir, fullPath);
    if (relativePath.length > 0) {
      paths.add(relativePath);
    }
  }
}

function shouldSkipSnapshotDirectory(name) {
  return name === ".git" || name === "node_modules";
}
