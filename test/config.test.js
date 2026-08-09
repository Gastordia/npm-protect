import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { loadConfig } from "../src/lib/config.js";

test("loadConfig accepts partial YAML config and merges defaults", async () => {
  const projectDir = await mkdtemp(path.join(tmpdir(), "npm-protect-config-"));
  await writeFile(
    path.join(projectDir, "npm-protect.yml"),
    "allowedInstallScripts:\n  - esbuild@0.25.0\n",
    "utf8",
  );

  const state = await loadConfig(projectDir);

  assert.equal(state.validationErrors.length, 0);
  assert.equal(state.config.mode, "warn");
  assert.deepEqual(state.config.allowedInstallScripts, ["esbuild@0.25.0"]);
  assert.equal(state.config.blockRules.requireLockfile, true);
});

test("loadConfig surfaces parse errors and falls back to defaults", async () => {
  const projectDir = await mkdtemp(path.join(tmpdir(), "npm-protect-config-invalid-"));
  await writeFile(path.join(projectDir, "npm-protect.yml"), "blockRules:\n - nope: true\n", "utf8");

  const state = await loadConfig(projectDir);

  assert.equal(state.config.mode, "warn");
  assert.equal(state.validationErrors.length, 1);
  assert.match(state.validationErrors[0], /unable to parse config file/);
});

test("loadConfig merges nested service settings", async () => {
  const projectDir = await mkdtemp(path.join(tmpdir(), "npm-protect-config-services-"));
  await writeFile(
    path.join(projectDir, "npm-protect.yml"),
    [
      "services:",
      "  osv:",
      "    enabled: true",
      "    timeoutMs: 1000",
      "blockRules:",
      "  vulnerabilitySeverityThreshold: critical",
    ].join("\n"),
    "utf8",
  );

  const state = await loadConfig(projectDir);

  assert.equal(state.validationErrors.length, 0);
  assert.equal(state.config.services.osv.enabled, true);
  assert.equal(state.config.services.osv.timeoutMs, 1000);
  assert.equal(state.config.services.registry.enabled, false);
  assert.equal(state.config.services.registry.warnPackageAgeDays, 14);
  assert.equal(state.config.services.tarballs.enabled, false);
  assert.equal(state.config.services.auditSignatures.enabled, false);
  assert.equal(state.config.blockRules.vulnerabilitySeverityThreshold, "critical");
});

test("loadConfig merges install-script approvals from the approval store", async () => {
  const projectDir = await mkdtemp(path.join(tmpdir(), "npm-protect-config-approvals-"));
  await mkdir(path.join(projectDir, ".npm-protect"), { recursive: true });
  await writeFile(
    path.join(projectDir, ".npm-protect", "approvals.json"),
    JSON.stringify(
      {
        version: 1,
        installScripts: [
          {
            package: "sharp",
            version: "0.34.0",
            approvedAt: "2026-08-01T00:00:00.000Z",
            expiresAt: "2026-08-20T00:00:00.000Z",
            reason: "reviewed native image build",
          },
        ],
      },
      null,
      2,
    ),
    "utf8",
  );
  await writeFile(
    path.join(projectDir, "npm-protect.json"),
    JSON.stringify(
      {
        allowedInstallScripts: ["esbuild@0.25.0"],
      },
      null,
      2,
    ),
    "utf8",
  );

  const state = await loadConfig(projectDir);

  assert.equal(state.validationErrors.length, 0);
  assert.equal(state.config.installScriptApprovals.length, 2);
  assert.ok(
    state.config.installScriptApprovals.some(
      (entry) => entry.name === "esbuild" && entry.version === "0.25.0" && entry.source === "config",
    ),
  );
  assert.ok(
    state.config.installScriptApprovals.some(
      (entry) => entry.name === "sharp" && entry.version === "0.34.0" && entry.source === "store",
    ),
  );
});
