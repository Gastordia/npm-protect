import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { runCli } from "../src/cli.js";

test("policy init writes a default config file", async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-policy-init-"));

  try {
    const { output } = await captureRun(async () => {
      await runCli([
        "policy",
        "init",
        "--project",
        projectDir,
      ]);
    });

    const configPath = path.join(projectDir, "npm-protect.yml");
    const content = await readFile(configPath, "utf8");

    assert.match(output, /Wrote .*npm-protect\.yml/);
    assert.match(content, /mode: enforce/);
    assert.match(content, /allowedInstallScripts:/);
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }
});

test("policy init can also scaffold a GitHub Actions workflow", async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-policy-gha-"));

  try {
    const { output } = await captureRun(async () => {
      await runCli([
        "policy",
        "init",
        "--project",
        projectDir,
        "--github-actions",
      ]);
    });

    const workflowPath = path.join(projectDir, ".github", "workflows", "npm-protect.yml");
    const workflow = await readFile(workflowPath, "utf8");

    assert.match(output, /Wrote .*npm-protect\.yml/);
    assert.match(workflow, /name: npm-protect/);
    assert.match(workflow, /uses: \.\//);
    assert.match(workflow, /before-ref:/);
    assert.match(workflow, /write-summary: "true"/);
  } finally {
    await rm(projectDir, { recursive: true, force: true });
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
