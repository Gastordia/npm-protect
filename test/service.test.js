import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { runCli } from "../src/cli.js";
import {
  getProtectionServiceStatus,
  installProtectionService,
  runProtectedPackageManagerCommand,
  runProtectedNpmCommand,
} from "../src/lib/service.js";

const fixturesDir = path.join(process.cwd(), "test", "fixtures");
const require = createRequire(import.meta.url);

test("installProtectionService writes managed wrappers and reports active status", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-service-"));
  const binDir = path.join(tempDir, "bin");

  try {
    const installResult = await installProtectionService({
      binDir,
      cliPath: "/opt/npm-protect/bin/npm-protect.js",
      nodePath: "/usr/bin/node",
      pathValue: `${binDir}${path.delimiter}/usr/bin`,
      toolNames: ["npm", "npx", "pnpm"],
    });

    const wrapper = await readFile(installResult.wrapperPath, "utf8");
    assert.match(wrapper, /NPM_PROTECT_TOOL='npm'/);
    assert.match(wrapper, /service run/);
    assert.match(wrapper, /\/opt\/npm-protect\/bin\/npm-protect\.js/);
    assert.equal(installResult.nodeHookPath, path.join(binDir, "npm-protect-node-hook.cjs"));
    assert.equal(installResult.envScriptPath, path.join(binDir, "npm-protect-service-env.sh"));
    assert.match(await readFile(installResult.envScriptPath, "utf8"), /NPM_PROTECT_FORCE_WRAPPERS=1/u);
    assert.deepEqual(
      installResult.wrappers.map((wrapperEntry) => wrapperEntry.name),
      ["npm", "npx", "pnpm"],
    );

    const status = await getProtectionServiceStatus(
      {
        binDir,
        pathValue: `${binDir}${path.delimiter}/usr/bin`,
      },
      {
        currentNpmPath: installResult.wrapperPath,
        currentExecutablePaths: {
          npm: installResult.wrapperPath,
          npx: path.join(binDir, "npx"),
          pnpm: "/usr/bin/pnpm",
        },
        processEnv: {},
      },
    );

    assert.equal(status.wrapperExists, true);
    assert.equal(status.active, true);
    assert.equal(status.pathActive, true);
    assert.equal(status.absolutePathProtection.hookExists, true);
    assert.equal(status.absolutePathProtection.envScriptExists, true);
    assert.equal(status.absolutePathProtection.active, false);
    assert.equal(status.wrappers.find((wrapperEntry) => wrapperEntry.name === "npx")?.active, true);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("getProtectionServiceStatus reports active Node absolute-path protection when activation env is loaded", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-service-hook-status-"));
  const binDir = path.join(tempDir, "bin");

  try {
    const installResult = await installProtectionService({
      binDir,
      cliPath: "/opt/npm-protect/bin/npm-protect.js",
      nodePath: "/usr/bin/node",
      toolNames: ["npm"],
    });

    const status = await getProtectionServiceStatus(
      {
        binDir,
        pathValue: `${binDir}${path.delimiter}/usr/bin`,
        processEnv: {
          ...process.env,
          NPM_PROTECT_FORCE_WRAPPERS: "1",
          NPM_PROTECT_SERVICE_BIN_DIR: binDir,
          NODE_OPTIONS: `--require ${installResult.nodeHookPath}`,
        },
      },
      {
        currentExecutablePaths: {
          npm: installResult.wrapperPath,
        },
      },
    );

    assert.equal(status.pathActive, true);
    assert.equal(status.active, true);
    assert.equal(status.absolutePathProtection.active, true);
    assert.equal(status.absolutePathProtection.nodeOptionsHasHook, true);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("installProtectionService activation hook rewrites absolute npm invocations from Node child processes", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-service-hook-exec-"));
  const binDir = path.join(tempDir, "bin");
  const fakeCliPath = path.join(tempDir, "fake-cli.mjs");

  try {
    await writeFile(
      fakeCliPath,
      "process.stdout.write('ok');\n",
      "utf8",
    );

    const installResult = await installProtectionService({
      binDir,
      cliPath: fakeCliPath,
      nodePath: process.execPath,
      toolNames: ["npm"],
    });

    const childProcess = require("node:child_process");
    const originalEnv = {
      NPM_PROTECT_FORCE_WRAPPERS: process.env.NPM_PROTECT_FORCE_WRAPPERS,
      NPM_PROTECT_SERVICE_BIN_DIR: process.env.NPM_PROTECT_SERVICE_BIN_DIR,
      NPM_PROTECT_BYPASS_HOOK: process.env.NPM_PROTECT_BYPASS_HOOK,
    };
    const originals = {
      spawn: childProcess.spawn,
      spawnSync: childProcess.spawnSync,
      execFile: childProcess.execFile,
      execFileSync: childProcess.execFileSync,
    };
    const payload = {};

    process.env.NPM_PROTECT_FORCE_WRAPPERS = "1";
    process.env.NPM_PROTECT_SERVICE_BIN_DIR = binDir;
    delete process.env.NPM_PROTECT_BYPASS_HOOK;
    childProcess.execFileSync = (file, args) => {
      payload.file = file;
      payload.args = args;
      return Buffer.from(JSON.stringify(payload));
    };

    delete require.cache[installResult.nodeHookPath];
    require(installResult.nodeHookPath);
    childProcess.execFileSync("/usr/bin/npm", ["--version"], { encoding: "utf8" });

    assert.equal(payload.file, installResult.wrapperPath);
    assert.deepEqual(payload.args, ["--version"]);

    Object.assign(childProcess, originals);
    restoreProcessEnv(originalEnv);
    delete require.cache[installResult.nodeHookPath];
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("getProtectionServiceStatus does not treat unmanaged files as npm-protect wrappers", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-service-unmanaged-"));
  const binDir = path.join(tempDir, "bin");
  const wrapperPath = path.join(binDir, "npm");

  try {
    await mkdir(binDir, { recursive: true });
    await writeFile(wrapperPath, "#!/usr/bin/env sh\nexec /usr/bin/npm \"$@\"\n", "utf8");

    const status = await getProtectionServiceStatus(
      {
        binDir,
        toolNames: ["npm"],
        pathValue: `${binDir}${path.delimiter}/usr/bin`,
      },
      {
        currentExecutablePaths: {
          npm: wrapperPath,
        },
      },
    );

    assert.equal(status.wrapperExists, false);
    assert.equal(status.active, false);
    assert.equal(status.wrappers[0].fileExists, true);
    assert.equal(status.wrappers[0].managed, false);
    assert.equal(status.wrappers[0].wrapperExists, false);
    assert.equal(status.wrappers[0].active, false);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("runProtectedNpmCommand blocks risky installs and restores the original files", async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-guard-block-"));
  const originalManifestPath = path.join(projectDir, "package.json");
  const originalLockfilePath = path.join(projectDir, "package-lock.json");

  try {
    await cp(path.join(fixturesDir, "online-project"), projectDir, { recursive: true });

    const originalManifest = await readFile(originalManifestPath, "utf8");
    const originalLockfile = await readFile(originalLockfilePath, "utf8");
    const blockedManifest = await readFile(
      path.join(fixturesDir, "block-project", "package.json"),
      "utf8",
    );
    const blockedLockfile = await readFile(
      path.join(fixturesDir, "block-project", "package-lock.json"),
      "utf8",
    );
    const calls = [];

    const result = await runProtectedNpmCommand(
      ["install", "esbuild@0.25.0"],
      {
        cwd: projectDir,
        realNpmPath: "/usr/bin/npm",
        fetchImpl: async () => {
          throw new Error("offline");
        },
      },
      {
        runProcess: async (_file, args) => {
          calls.push(args);

          if (args.includes("--package-lock-only")) {
            await writeFile(originalManifestPath, blockedManifest, "utf8");
            await writeFile(originalLockfilePath, blockedLockfile, "utf8");
            return { exitCode: 0 };
          }

          throw new Error("actual install should not run after a blocked review");
        },
      },
    );

    assert.equal(result.exitCode, 2);
    assert.equal(result.blocked, true);
    assert.equal(calls.length, 1);
    assert.match(calls[0].join(" "), /--package-lock-only/);
    assert.equal(await readFile(originalManifestPath, "utf8"), originalManifest);
    assert.equal(await readFile(originalLockfilePath, "utf8"), originalLockfile);
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }
});

test("runProtectedNpmCommand uses ignore-scripts and only rebuilds approved packages", async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-guard-allow-"));
  const configPath = path.join(projectDir, "npm-protect.json");

  try {
    await cp(path.join(fixturesDir, "block-project"), projectDir, { recursive: true });
    await writeFile(
      configPath,
      JSON.stringify(
        {
          allowedInstallScripts: ["esbuild@0.25.0"],
          service: {
            rebuildSandbox: "off",
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const calls = [];
    const result = await runProtectedNpmCommand(
      ["ci"],
      {
        cwd: projectDir,
        realNpmPath: "/usr/bin/npm",
        fetchImpl: async () => {
          throw new Error("offline");
        },
      },
      {
        runProcess: async (_file, args) => {
          calls.push(args);
          return { exitCode: 0 };
        },
      },
    );

    assert.equal(result.exitCode, 0);
    assert.deepEqual(calls, [
      ["ci", "--ignore-scripts"],
      ["rebuild", "esbuild@0.25.0"],
    ]);
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }
});

test("runProtectedNpmCommand blocks unmanaged global installs", async () => {
  const result = await runProtectedNpmCommand(
    ["install", "-g", "left-pad@1.3.0"],
    {
      cwd: process.cwd(),
      realNpmPath: "/usr/bin/npm",
    },
    {
      runProcess: async () => {
        throw new Error("global installs should not be passed through");
      },
    },
  );

  assert.equal(result.exitCode, 2);
  assert.equal(result.blocked, true);
});

test("runProtectedNpmCommand sandboxes approved rebuilds with bubblewrap when available", async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-guard-sandbox-"));
  const configPath = path.join(projectDir, "npm-protect.json");

  try {
    await cp(path.join(fixturesDir, "block-project"), projectDir, { recursive: true });
    await writeFile(
      configPath,
      JSON.stringify(
        {
          allowedInstallScripts: ["esbuild@0.25.0"],
          service: {
            rebuildSandbox: "auto",
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const calls = [];
    const files = [];
    const envs = [];
    const result = await runProtectedNpmCommand(
      ["ci"],
      {
        cwd: projectDir,
        realToolPath: "/usr/bin/npm",
        fetchImpl: async () => {
          throw new Error("offline");
        },
      },
      {
        resolveExecutableCandidates: async (name) => {
          if (name === "bwrap") {
            return ["/usr/bin/bwrap"];
          }

          return [];
        },
        runProcess: async (file, args, options) => {
          files.push(file);
          calls.push(args);
          envs.push(options.env);
          return { exitCode: 0 };
        },
      },
    );

    assert.equal(result.exitCode, 0);
    assert.deepEqual(files, ["/usr/bin/npm", "/usr/bin/bwrap"]);
    assert.deepEqual(calls[0], ["ci", "--ignore-scripts"]);
    assert.ok(calls[1].includes("--unshare-net"));
    assert.ok(calls[1].includes("/usr/bin/npm"));
    assert.ok(calls[1].includes("rebuild"));
    assert.ok(calls[1].includes("esbuild@0.25.0"));
    assert.equal("NPM_PROTECT_TOOL" in envs[1], false);
    assert.equal("NPM_PROTECT_SERVICE_BIN_DIR" in envs[1], false);
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }
});

test("runProtectedNpmCommand blocks when approved rebuild sandboxing is required but unavailable", async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-guard-sandbox-required-"));
  const configPath = path.join(projectDir, "npm-protect.json");

  try {
    await cp(path.join(fixturesDir, "block-project"), projectDir, { recursive: true });
    await writeFile(
      configPath,
      JSON.stringify(
        {
          allowedInstallScripts: ["esbuild@0.25.0"],
          service: {
            rebuildSandbox: "require",
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const calls = [];
    const result = await runProtectedNpmCommand(
      ["ci"],
      {
        cwd: projectDir,
        realToolPath: "/usr/bin/npm",
        fetchImpl: async () => {
          throw new Error("offline");
        },
      },
      {
        resolveExecutableCandidates: async () => [],
        runProcess: async (_file, args) => {
          calls.push(args);
          return { exitCode: 0 };
        },
      },
    );

    assert.equal(result.exitCode, 2);
    assert.equal(result.blocked, true);
    assert.equal(result.reason, "rebuild_sandbox_unavailable");
    assert.deepEqual(calls, []);
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }
});

test("runProtectedPackageManagerCommand blocks unsafe npx package execution before it runs", async () => {
  const blockedManifest = await readFile(
    path.join(fixturesDir, "block-project", "package.json"),
    "utf8",
  );
  const blockedLockfile = await readFile(
    path.join(fixturesDir, "block-project", "package-lock.json"),
    "utf8",
  );
  const calls = [];

  const result = await runProtectedPackageManagerCommand(
    "npx",
    ["esbuild@0.25.0"],
    {
      cwd: process.cwd(),
      realToolPath: "/usr/bin/npx",
      realNpmPath: "/usr/bin/npm",
      fetchImpl: async () => {
        throw new Error("offline");
      },
    },
    {
      runProcess: async (_file, args, runOptions) => {
        calls.push(args);
        if (args[0] === "install" && args.includes("--package-lock-only")) {
          await writeFile(path.join(runOptions.cwd, "package.json"), blockedManifest, "utf8");
          await writeFile(path.join(runOptions.cwd, "package-lock.json"), blockedLockfile, "utf8");
          return { exitCode: 0 };
        }

        throw new Error("npx should not execute after a blocked preflight review");
      },
    },
  );

  assert.equal(result.exitCode, 2);
  assert.equal(result.blocked, true);
  assert.deepEqual(calls, [["install", "--package-lock-only", "--ignore-scripts", "esbuild@0.25.0"]]);
});

test("runProtectedPackageManagerCommand passes through local-only npx execution", async () => {
  const calls = [];
  const result = await runProtectedPackageManagerCommand(
    "npx",
    ["--no-install", "eslint", "--version"],
    {
      cwd: process.cwd(),
      realToolPath: "/usr/bin/npx",
    },
    {
      runProcess: async (_file, args) => {
        calls.push(args);
        return { exitCode: 0 };
      },
    },
  );

  assert.equal(result.exitCode, 0);
  assert.deepEqual(calls, [["--no-install", "eslint", "--version"]]);
});

test("runProtectedPackageManagerCommand reviews pnpm add with a lockfile-only preview", async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-pnpm-block-"));
  const calls = [];

  try {
    await cp(path.join(fixturesDir, "pnpm-project"), projectDir, { recursive: true });

    const result = await runProtectedPackageManagerCommand(
      "pnpm",
      ["add", "left-pad@1.3.0"],
      {
        cwd: projectDir,
        realToolPath: "/usr/bin/pnpm",
        fetchImpl: async () => {
          throw new Error("offline");
        },
      },
      {
        runProcess: async (_file, args) => {
          calls.push(args);
          if (args.includes("--lockfile-only")) {
            return { exitCode: 0 };
          }

          throw new Error("pnpm add should not proceed after a blocked review");
        },
      },
    );

    assert.equal(result.exitCode, 2);
    assert.equal(result.blocked, true);
    assert.deepEqual(calls, [["add", "left-pad@1.3.0", "--ignore-scripts", "--lockfile-only"]]);
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }
});

test("runProtectedPackageManagerCommand mediates pnpm installs with lockfile-only preview", async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-pnpm-allow-"));
  const configPath = path.join(projectDir, "npm-protect.json");

  try {
    await cp(path.join(fixturesDir, "pnpm-project"), projectDir, { recursive: true });
    await writeFile(
      configPath,
      JSON.stringify(
        {
          allowedInstallScripts: ["esbuild@0.25.0"],
          service: {
            rebuildSandbox: "off",
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const calls = [];
    const result = await runProtectedPackageManagerCommand(
      "pnpm",
      ["install"],
      {
        cwd: projectDir,
        realToolPath: "/usr/bin/pnpm",
        fetchImpl: async () => {
          throw new Error("offline");
        },
      },
      {
        runProcess: async (_file, args) => {
          calls.push(args);
          return { exitCode: 0 };
        },
      },
    );

    assert.equal(result.exitCode, 0);
    assert.deepEqual(calls, [
      ["install", "--ignore-scripts", "--lockfile-only"],
      ["install", "--ignore-scripts"],
      ["rebuild", "esbuild"],
    ]);
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }
});

test("runProtectedPackageManagerCommand mediates modern yarn installs with update-lockfile preview", async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-yarn-modern-"));
  const configPath = path.join(projectDir, "npm-protect.json");

  try {
    await cp(path.join(fixturesDir, "yarn-project"), projectDir, { recursive: true });
    await writeFile(
      path.join(projectDir, "package.json"),
      JSON.stringify(
        {
          name: "yarn-project",
          version: "1.0.0",
          packageManager: "yarn@4.4.1",
          dependencies: {
            esbuild: "0.25.0",
            react: "19.0.0",
          },
        },
        null,
        2,
      ),
      "utf8",
    );
    await writeFile(path.join(projectDir, ".yarnrc.yml"), "nodeLinker: node-modules\n", "utf8");
    await writeFile(
      configPath,
      JSON.stringify(
        {
          allowedInstallScripts: ["esbuild@0.25.0"],
          service: {
            rebuildSandbox: "off",
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const calls = [];
    const result = await runProtectedPackageManagerCommand(
      "yarn",
      ["install"],
      {
        cwd: projectDir,
        realToolPath: "/usr/bin/yarn",
        fetchImpl: async (url) => {
          if (String(url) === "https://registry.npmjs.org/esbuild/-/esbuild-0.25.0.tgz") {
            return bufferResponse(
              createTarball({
                "package/package.json": JSON.stringify({
                  name: "esbuild",
                  version: "0.25.0",
                  scripts: {
                    install: "node install.js",
                  },
                }),
                "package/install.js": "console.log('hello');",
              }),
            );
          }

          if (String(url) === "https://registry.npmjs.org/react/-/react-19.0.0.tgz") {
            return bufferResponse(
              createTarball({
                "package/package.json": JSON.stringify({
                  name: "react",
                  version: "19.0.0",
                }),
              }),
            );
          }

          throw new Error(`unexpected fetch ${url}`);
        },
      },
      {
        runProcess: async (_file, args) => {
          calls.push(args);
          return { exitCode: 0 };
        },
      },
    );

    assert.equal(result.exitCode, 0);
    assert.deepEqual(calls, [
      ["install", "--mode=update-lockfile"],
      ["install", "--mode=skip-build"],
      ["rebuild", "esbuild"],
    ]);
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }
});

test("runProtectedPackageManagerCommand mediates classic yarn with a temporary script-free preview", async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-yarn-classic-"));
  const configPath = path.join(projectDir, "npm-protect.json");

  try {
    await cp(path.join(fixturesDir, "yarn-project"), projectDir, { recursive: true });
    await writeFile(
      configPath,
      JSON.stringify({
        allowedInstallScripts: ["esbuild@0.25.0"],
        service: { rebuildSandbox: "off" },
      }),
      "utf8",
    );

    const calls = [];

    const result = await runProtectedPackageManagerCommand(
      "yarn",
      ["install", "--ignore-scripts=false", "--modules-folder=/tmp/untrusted-target"],
      {
        cwd: projectDir,
        realToolPath: "/usr/bin/yarn",
        fetchImpl: async (url) => {
          if (String(url).endsWith("/esbuild-0.25.0.tgz")) {
            return bufferResponse(
              createTarball({
                "package/package.json": JSON.stringify({
                  name: "esbuild",
                  version: "0.25.0",
                  scripts: { install: "node install.js" },
                }),
                "package/install.js": "console.log('hello');",
              }),
            );
          }
          return bufferResponse(
            createTarball({
              "package/package.json": JSON.stringify({ name: "react", version: "19.0.0" }),
            }),
          );
        },
      },
      {
        realExecutablePaths: { npm: "/usr/bin/npm" },
        runProcess: async (file, args) => {
          calls.push({ file, args });
          return { exitCode: 0 };
        },
      },
    );

    assert.equal(result.exitCode, 0);
    assert.equal(calls.length, 3);
    assert.equal(calls[0].file, "/usr/bin/yarn");
    assert.equal(calls[0].args[0], "install");
    assert.equal(calls[0].args.includes("--ignore-scripts"), true);
    assert.equal(calls[0].args.some((arg) => arg.startsWith("--ignore-scripts=")), false);
    assert.equal(calls[0].args.includes("--modules-folder=/tmp/untrusted-target"), false);
    const modulesIndex = calls[0].args.indexOf("--modules-folder");
    assert.notEqual(modulesIndex, -1);
    assert.match(calls[0].args[modulesIndex + 1], /npm-protect-yarn-preview-/u);
    assert.deepEqual(calls[1], {
      file: "/usr/bin/yarn",
      args: ["install", "--ignore-scripts"],
    });
    assert.deepEqual(calls[2], {
      file: "/usr/bin/npm",
      args: ["rebuild", "esbuild@0.25.0"],
    });
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }
});

test("runProtectedPackageManagerCommand delegates managed corepack invocations to the underlying tool", async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-corepack-yarn-"));
  const configPath = path.join(projectDir, "npm-protect.json");

  try {
    await cp(path.join(fixturesDir, "yarn-project"), projectDir, { recursive: true });
    await writeFile(
      path.join(projectDir, "package.json"),
      JSON.stringify(
        {
          name: "yarn-project",
          version: "1.0.0",
          packageManager: "yarn@4.4.1",
          dependencies: {
            react: "19.0.0",
          },
        },
        null,
        2,
      ),
      "utf8",
    );
    await writeFile(path.join(projectDir, ".yarnrc.yml"), "nodeLinker: node-modules\n", "utf8");
    await writeFile(configPath, JSON.stringify({}, null, 2), "utf8");

    const calls = [];
    const files = [];
    const result = await runProtectedPackageManagerCommand(
      "corepack",
      ["yarn", "install"],
      {
        cwd: projectDir,
      },
      {
        realExecutablePaths: {
          corepack: "/usr/bin/corepack",
          yarn: "/usr/bin/yarn",
        },
        runProcess: async (file, args) => {
          files.push(file);
          calls.push(args);
          return { exitCode: 0 };
        },
      },
    );

    assert.equal(result.exitCode, 0);
    assert.deepEqual(files, ["/usr/bin/yarn", "/usr/bin/yarn"]);
    assert.deepEqual(calls, [
      ["install", "--mode=update-lockfile"],
      ["install", "--mode=skip-build"],
    ]);
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }
});

test("runProtectedNpmCommand restores root and workspace manifests when previewed from a workspace", async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-workspace-root-"));
  const workspaceDir = path.join(projectDir, "packages", "app");
  const rootManifestPath = path.join(projectDir, "package.json");
  const rootLockfilePath = path.join(projectDir, "package-lock.json");
  const workspaceManifestPath = path.join(workspaceDir, "package.json");

  try {
    await cp(path.join(fixturesDir, "block-project"), projectDir, { recursive: true });
    await mkdir(workspaceDir, { recursive: true });

    const originalRootManifest = JSON.parse(await readFile(rootManifestPath, "utf8"));
    originalRootManifest.workspaces = ["packages/*"];
    await writeFile(rootManifestPath, JSON.stringify(originalRootManifest, null, 2), "utf8");
    await writeFile(
      workspaceManifestPath,
      JSON.stringify(
        {
          name: "workspace-app",
          version: "1.0.0",
        },
        null,
        2,
      ),
      "utf8",
    );

    const expectedRootManifest = await readFile(rootManifestPath, "utf8");
    const expectedRootLockfile = await readFile(rootLockfilePath, "utf8");
    const expectedWorkspaceManifest = await readFile(workspaceManifestPath, "utf8");
    const tamperedRootLockfile = expectedRootLockfile.replace(
      '"name": "block-project"',
      '"name": "tampered-block-project"',
    );

    const result = await runProtectedNpmCommand(
      ["install", "left-pad@1.3.0"],
      {
        cwd: workspaceDir,
        realNpmPath: "/usr/bin/npm",
        fetchImpl: async () => {
          throw new Error("offline");
        },
      },
      {
        runProcess: async (_file, args, runOptions) => {
          assert.equal(runOptions.cwd, workspaceDir);
          if (args.includes("--package-lock-only")) {
            await writeFile(
              rootManifestPath,
              JSON.stringify(
                {
                  ...originalRootManifest,
                  dependencies: {
                    ...originalRootManifest.dependencies,
                    "left-pad": "1.3.0",
                  },
                },
                null,
                2,
              ),
              "utf8",
            );
            await writeFile(rootLockfilePath, tamperedRootLockfile, "utf8");
            await writeFile(
              workspaceManifestPath,
              JSON.stringify(
                {
                  name: "workspace-app",
                  version: "2.0.0",
                },
                null,
                2,
              ),
              "utf8",
            );
          }

          return { exitCode: 0 };
        },
      },
    );

    assert.equal(result.exitCode, 2);
    assert.equal(result.blocked, true);
    assert.equal(await readFile(rootManifestPath, "utf8"), expectedRootManifest);
    assert.equal(await readFile(rootLockfilePath, "utf8"), expectedRootLockfile);
    assert.equal(await readFile(workspaceManifestPath, "utf8"), expectedWorkspaceManifest);
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }
});

test("runProtectedPackageManagerCommand blocks pnpm installs when rebuild targeting would widen approvals", async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-pnpm-ambiguous-"));
  const configPath = path.join(projectDir, "npm-protect.json");
  const lockfilePath = path.join(projectDir, "pnpm-lock.yaml");

  try {
    await writeFile(
      path.join(projectDir, "package.json"),
      JSON.stringify(
        {
          name: "pnpm-ambiguous-project",
          version: "1.0.0",
          dependencies: {
            esbuild: "0.25.0",
          },
        },
        null,
        2,
      ),
      "utf8",
    );
    await writeFile(
      configPath,
      JSON.stringify(
        {
          allowedInstallScripts: ["esbuild@0.25.0"],
          blockRules: {
            unreviewedInstallScripts: false,
          },
        },
        null,
        2,
      ),
      "utf8",
    );
    await writeFile(
      lockfilePath,
      `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      esbuild:
        version: 0.25.0

packages:
  /esbuild@0.25.0:
    resolution:
      integrity: sha512-esbuild-new
    requiresBuild: true

  /esbuild@0.24.0:
    resolution:
      integrity: sha512-esbuild-old
    requiresBuild: true
`,
      "utf8",
    );

    const calls = [];
    const result = await runProtectedPackageManagerCommand(
      "pnpm",
      ["install"],
      {
        cwd: projectDir,
        realToolPath: "/usr/bin/pnpm",
        fetchImpl: async () => {
          throw new Error("offline");
        },
      },
      {
        runProcess: async (_file, args) => {
          calls.push(args);
          return { exitCode: 0 };
        },
      },
    );

    assert.equal(result.exitCode, 2);
    assert.equal(result.blocked, true);
    assert.equal(result.reason, "unsafe_rebuild_targeting");
    assert.deepEqual(calls, [["install", "--ignore-scripts", "--lockfile-only"]]);
    assert.equal(result.plan.rebuildStrategy.status, "blocked");
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }
});

test("installProtectionService refuses to overwrite an unmanaged wrapper", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-service-overwrite-"));
  const binDir = path.join(tempDir, "bin");

  try {
    await mkdir(binDir, { recursive: true });
    await writeFile(path.join(binDir, "npm"), "#!/usr/bin/env sh\nexec /usr/bin/npm \"$@\"\n", "utf8");

    await assert.rejects(
      () =>
        installProtectionService({
          binDir,
          cliPath: "/opt/npm-protect/bin/npm-protect.js",
          nodePath: "/usr/bin/node",
          toolNames: ["npm"],
        }),
      /refusing to overwrite/u,
    );
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("runCli service install emits JSON metadata for wrapper installation", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-service-cli-"));
  const binDir = path.join(tempDir, "bin");

  try {
    const { output, exitCode } = await captureRun(async () => {
      await runCli([
        "service",
        "install",
        "--bin-dir",
        binDir,
        "--cli-path",
        "/opt/npm-protect/bin/npm-protect.js",
        "--node-path",
        "/usr/bin/node",
        "--json",
      ], {
        pathValue: "",
      });
    });

    const result = JSON.parse(output);
    assert.equal(result.wrapperPath, path.join(binDir, "npm"));
    assert.ok(Array.isArray(result.wrappers));
    assert.ok(result.wrappers.some((wrapperEntry) => wrapperEntry.name === "npx"));
    assert.equal(result.nodeHookPath, path.join(binDir, "npm-protect-node-hook.cjs"));
    assert.equal(result.envScriptPath, path.join(binDir, "npm-protect-service-env.sh"));
    assert.equal(exitCode, undefined);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("runCli service doctor reports PATH and wrapper issues", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-service-doctor-"));
  const binDir = path.join(tempDir, "bin");

  try {
    const { output, exitCode } = await captureRun(async () => {
      await runCli([
        "service",
        "doctor",
        "--bin-dir",
        binDir,
        "--json",
      ], {
        pathValue: "/usr/bin",
        currentExecutablePaths: {
          npm: "/usr/bin/npm",
          npx: "/usr/bin/npx",
          pnpm: "/usr/bin/pnpm",
          pnpx: "/usr/bin/pnpx",
          yarn: "/usr/bin/yarn",
          yarnpkg: "/usr/bin/yarnpkg",
          corepack: "/usr/bin/corepack",
        },
        resolveExecutableCandidates: async () => [],
      });
    });

    const result = JSON.parse(output);
    assert.equal(result.status.pathActive, false);
    assert.ok(result.issues.some((issue) => issue.code === "missing_primary_wrapper"));
    assert.ok(result.issues.some((issue) => issue.code === "path_not_active"));
    assert.ok(result.issues.some((issue) => issue.code === "absolute_path_hook_missing"));
    assert.ok(result.issues.some((issue) => issue.code === "rebuild_sandbox_unavailable"));
    assert.ok(result.recommendations.some((entry) => /service install/u.test(entry)));
    assert.equal(exitCode, undefined);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("runCli service doctor reports unmanaged wrapper conflicts", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-service-doctor-unmanaged-"));
  const binDir = path.join(tempDir, "bin");
  const wrapperPath = path.join(binDir, "npm");

  try {
    await mkdir(binDir, { recursive: true });
    await writeFile(wrapperPath, "#!/usr/bin/env sh\nexec /usr/bin/npm \"$@\"\n", "utf8");

    const { output, exitCode } = await captureRun(async () => {
      await runCli([
        "service",
        "doctor",
        "--bin-dir",
        binDir,
        "--json",
      ], {
        pathValue: `${binDir}${path.delimiter}/usr/bin`,
        currentExecutablePaths: {
          npm: wrapperPath,
        },
      });
    });

    const result = JSON.parse(output);
    assert.equal(result.status.wrapperExists, false);
    assert.ok(result.issues.some((issue) => issue.code === "wrapper_unmanaged"));
    assert.ok(result.issues.some((issue) => issue.code === "missing_primary_wrapper"));
    assert.equal(exitCode, undefined);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("runCli service doctor reports inactive absolute-path protection after installation", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-service-doctor-hook-inactive-"));
  const binDir = path.join(tempDir, "bin");

  try {
    const installResult = await installProtectionService({
      binDir,
      cliPath: "/opt/npm-protect/bin/npm-protect.js",
      nodePath: "/usr/bin/node",
      toolNames: ["npm"],
    });

    const { output, exitCode } = await captureRun(async () => {
      await runCli([
        "service",
        "doctor",
        "--bin-dir",
        binDir,
        "--json",
      ], {
        pathValue: `${binDir}${path.delimiter}/usr/bin`,
        currentExecutablePaths: {
          npm: installResult.wrapperPath,
        },
        processEnv: {},
        resolveExecutableCandidates: async () => [],
      });
    });

    const result = JSON.parse(output);
    assert.ok(result.issues.some((issue) => issue.code === "absolute_path_protection_inactive"));
    assert.ok(result.recommendations.some((entry) => entry.includes(installResult.envScriptPath)));
    assert.equal(exitCode, undefined);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

async function captureRun(fn) {
  const originalLog = console.log;
  const originalError = console.error;
  const originalExitCode = process.exitCode;
  const chunks = [];

  console.log = (...args) => {
    chunks.push(args.join(" "));
  };

  console.error = (...args) => {
    chunks.push(args.join(" "));
  };

  try {
    process.exitCode = undefined;
    await fn();
    return {
      output: chunks.join("\n"),
      exitCode: process.exitCode,
    };
  } finally {
    console.log = originalLog;
    console.error = originalError;
    process.exitCode = originalExitCode;
  }
}

function restoreProcessEnv(previousValues) {
  for (const [key, value] of Object.entries(previousValues)) {
    if (value === undefined) {
      delete process.env[key];
      continue;
    }

    process.env[key] = value;
  }
}

function bufferResponse(buffer, options = {}) {
  const headerMap = new Map(
    Object.entries(options.headers ?? {}).map(([key, value]) => [String(key).toLowerCase(), String(value)]),
  );

  return {
    ok: (options.status ?? 200) >= 200 && (options.status ?? 200) < 300,
    status: options.status ?? 200,
    headers: {
      get(name) {
        return headerMap.get(String(name).toLowerCase()) ?? null;
      },
    },
    async arrayBuffer() {
      return buffer;
    },
  };
}

function createTarball(files) {
  const records = [];

  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content, "utf8");
    const header = Buffer.alloc(512, 0);
    writeTarString(header, 0, 100, name);
    writeTarString(header, 100, 8, "0000777");
    writeTarString(header, 108, 8, "0000000");
    writeTarString(header, 116, 8, "0000000");
    writeTarString(header, 124, 12, data.length.toString(8));
    writeTarString(header, 136, 12, Math.floor(Date.now() / 1000).toString(8));
    header[156] = "0".charCodeAt(0);
    writeTarString(header, 257, 6, "ustar");
    writeTarString(header, 263, 2, "00");

    for (let index = 148; index < 156; index += 1) {
      header[index] = 32;
    }
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    writeTarString(header, 148, 8, checksum.toString(8));

    records.push(header, data, Buffer.alloc((512 - (data.length % 512)) % 512, 0));
  }

  records.push(Buffer.alloc(1024, 0));
  return gzipSync(Buffer.concat(records));
}

function writeTarString(buffer, offset, length, value) {
  buffer.write(String(value).slice(0, length - 1), offset, length - 1, "utf8");
}
