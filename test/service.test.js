import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { runCli } from "../src/cli.js";
import {
  getProtectionServiceStatus,
  installProtectionService,
  runProtectedNpmCommand,
} from "../src/lib/service.js";

const fixturesDir = path.join(process.cwd(), "test", "fixtures");

test("installProtectionService writes an npm wrapper and reports active status", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-service-"));
  const binDir = path.join(tempDir, "bin");

  try {
    const installResult = await installProtectionService({
      binDir,
      realNpmPath: "/usr/bin/npm",
      cliPath: "/opt/npm-protect/bin/npm-protect.js",
      nodePath: "/usr/bin/node",
      pathValue: `${binDir}${path.delimiter}/usr/bin`,
    });

    const wrapper = await readFile(installResult.wrapperPath, "utf8");
    assert.match(wrapper, /NPM_PROTECT_REAL_NPM/);
    assert.match(wrapper, /service run/);
    assert.match(wrapper, /\/opt\/npm-protect\/bin\/npm-protect\.js/);

    const status = await getProtectionServiceStatus(
      {
        binDir,
        pathValue: `${binDir}${path.delimiter}/usr/bin`,
      },
      {
        currentNpmPath: installResult.wrapperPath,
      },
    );

    assert.equal(status.wrapperExists, true);
    assert.equal(status.active, true);
    assert.equal(status.pathActive, true);
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
      ["rebuild", "esbuild"],
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
        "--real-npm",
        "/usr/bin/npm",
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
    assert.equal(result.realNpmPath, "/usr/bin/npm");
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
