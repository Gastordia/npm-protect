import { execFile, spawn } from "node:child_process";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { loadConfig } from "./config.js";
import { collectExternalIntelligence } from "./intelligence.js";
import { buildInstallPlan } from "./install-plan.js";
import { evaluateProjectWithIntelligence } from "./policy.js";
import { fileExists, loadProjectSnapshot } from "./project.js";

const execFileAsync = promisify(execFile);
const SERVICE_COMMANDS = new Set(["install", "i", "ci", "add", "update", "up"]);
const SNAPSHOT_FILENAMES = ["package.json", "package-lock.json", "npm-shrinkwrap.json"];
const DEFAULT_SERVICE_FLAGS = {
  online: true,
  "inspect-tarballs": true,
};
const DEFAULT_BIN_DIR = path.join(os.homedir(), ".local", "bin");

export async function installProtectionService(options = {}, deps = {}) {
  const binDir = path.resolve(options.binDir ?? deps.binDir ?? DEFAULT_BIN_DIR);
  const wrapperPath = path.join(binDir, "npm");
  const manifestPath = path.join(binDir, "npm-protect-service.json");
  const cliPath = path.resolve(
    options.cliPath ?? deps.cliPath ?? fileURLToPath(new URL("../../bin/npm-protect.js", import.meta.url)),
  );
  const nodePath = path.resolve(options.nodePath ?? deps.nodePath ?? process.execPath);
  const realNpmPath = path.resolve(
    options.realNpmPath ?? (await resolveRealNpmPath(deps)),
  );
  const pathValue = options.pathValue ?? deps.pathValue ?? process.env.PATH ?? "";

  await mkdir(binDir, { recursive: true });
  await writeFile(
    wrapperPath,
    createNpmWrapperScript({
      nodePath,
      cliPath,
      realNpmPath,
    }),
    "utf8",
  );
  await chmod(wrapperPath, 0o755);
  await writeFile(
    manifestPath,
    JSON.stringify(
      {
        wrapperPath,
        manifestPath,
        binDir,
        cliPath,
        nodePath,
        realNpmPath,
        installedAt: new Date().toISOString(),
      },
      null,
      2,
    ),
    "utf8",
  );

  return {
    wrapperPath,
    manifestPath,
    binDir,
    cliPath,
    nodePath,
    realNpmPath,
    pathActive: isBinDirAheadInPath(binDir, pathValue),
    shellSnippet: `export PATH="${binDir}:$PATH"`,
  };
}

export async function uninstallProtectionService(options = {}) {
  const binDir = path.resolve(options.binDir ?? DEFAULT_BIN_DIR);
  const wrapperPath = path.join(binDir, "npm");
  const manifestPath = path.join(binDir, "npm-protect-service.json");

  await rm(wrapperPath, { force: true });
  await rm(manifestPath, { force: true });

  return {
    wrapperPath,
    manifestPath,
    removed: true,
  };
}

export async function getProtectionServiceStatus(options = {}, deps = {}) {
  const binDir = path.resolve(options.binDir ?? deps.binDir ?? DEFAULT_BIN_DIR);
  const wrapperPath = path.join(binDir, "npm");
  const manifestPath = path.join(binDir, "npm-protect-service.json");
  const pathValue = options.pathValue ?? deps.pathValue ?? process.env.PATH ?? "";
  const wrapperExists = await fileExists(wrapperPath);
  const manifestExists = await fileExists(manifestPath);
  const manifest = manifestExists ? JSON.parse(await readFile(manifestPath, "utf8")) : null;
  const currentNpmPath =
    typeof deps.currentNpmPath === "string"
      ? deps.currentNpmPath
      : await safeResolveExecutable("npm", deps);

  return {
    binDir,
    wrapperPath,
    wrapperExists,
    manifestPath,
    manifestExists,
    pathActive: isBinDirAheadInPath(binDir, pathValue),
    currentNpmPath,
    active: wrapperExists && currentNpmPath === wrapperPath,
    manifest,
  };
}

export async function runProtectedNpmCommand(argv, options = {}, deps = {}) {
  const args = argv.filter((arg) => arg !== "--");
  const command = args[0];
  const cwd = path.resolve(options.cwd ?? process.cwd());
  const projectDir = resolveProjectDirFromNpmArgs(cwd, args);
  const runner = deps.runProcess ?? runProcess;
  const realNpmPath = path.resolve(
    options.realNpmPath ??
      process.env.NPM_PROTECT_REAL_NPM ??
      (await resolveRealNpmPath(deps)),
  );
  const npmEnv = {
    ...process.env,
    NPM_PROTECT_REAL_NPM: realNpmPath,
  };

  if (!command) {
    return passThroughNpmCommand(realNpmPath, args, { cwd, env: npmEnv }, runner);
  }

  if (hasGlobalInstallFlag(args)) {
    console.error(
      "npm-protect blocked this command: global npm installs are not supported by the protection shim yet.",
    );
    return { exitCode: 2, blocked: true };
  }

  if (!SERVICE_COMMANDS.has(command)) {
    return passThroughNpmCommand(realNpmPath, args, { cwd, env: npmEnv }, runner);
  }

  const snapshots = await snapshotProjectFiles(projectDir);

  if (command !== "ci") {
    const previewResult = await runner(realNpmPath, buildPreviewArgs(args), {
      cwd: projectDir,
      env: npmEnv,
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
        ...(options.reviewFlags ?? {}),
      },
      fetchImpl: options.fetchImpl,
      now: options.now,
    });
    report = evaluateProjectWithIntelligence(project, configState.config, {
      validationErrors: configState.validationErrors,
      intelligence,
    });

    if (report.riskVerdict === "block") {
      await restoreProjectFiles(projectDir, snapshots);
      printBlockingFindings(report);
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
      fetchImpl: options.fetchImpl,
      now: options.now,
    });
  } catch (error) {
    await restoreProjectFiles(projectDir, snapshots);
    throw error;
  }

  const installResult = await runner(realNpmPath, ensureIgnoreScripts(args), {
    cwd: projectDir,
    env: npmEnv,
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
    const rebuildResult = await runner(realNpmPath, ["rebuild", ...approvedPackageNames], {
      cwd: projectDir,
      env: npmEnv,
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

export function createNpmWrapperScript({ nodePath, cliPath, realNpmPath }) {
  return `#!/usr/bin/env sh
export NPM_PROTECT_REAL_NPM=${quoteForShell(realNpmPath)}
exec ${quoteForShell(nodePath)} ${quoteForShell(cliPath)} service run "$@"
`;
}

function ensureIgnoreScripts(args) {
  if (args.includes("--ignore-scripts")) {
    return [...args];
  }

  return [...args, "--ignore-scripts"];
}

function buildPreviewArgs(args) {
  const previewArgs = ensureIgnoreScripts(args);

  if (!previewArgs.includes("--package-lock-only")) {
    previewArgs.push("--package-lock-only");
  }

  return previewArgs;
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

async function resolveRealNpmPath(deps = {}) {
  if (typeof deps.realNpmPath === "string" && deps.realNpmPath.length > 0) {
    return deps.realNpmPath;
  }

  if (typeof process.env.NPM_PROTECT_REAL_NPM === "string" && process.env.NPM_PROTECT_REAL_NPM.length > 0) {
    return process.env.NPM_PROTECT_REAL_NPM;
  }

  const result = await execFileAsync("which", ["npm"]);
  return result.stdout.trim();
}

async function safeResolveExecutable(name, deps = {}) {
  try {
    if (typeof deps.currentNpmPath === "string") {
      return deps.currentNpmPath;
    }

    const result = await execFileAsync("which", [name]);
    return result.stdout.trim();
  } catch (error) {
    return null;
  }
}

async function passThroughNpmCommand(realNpmPath, args, options, runner) {
  return runner(realNpmPath, args, {
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

function printBlockingFindings(report) {
  console.error("npm-protect blocked this install because the requested dependency state is unsafe:");

  for (const finding of report.findings.filter((finding) => finding.severity === "error")) {
    console.error(`- ${finding.code}: ${finding.message}`);
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
