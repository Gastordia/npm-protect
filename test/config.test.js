import assert from "node:assert/strict";
import { chmod, mkdtemp, mkdir, writeFile } from "node:fs/promises";
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

test("loadConfig validates trustedScopes entries", async () => {
  const projectDir = await mkdtemp(path.join(tmpdir(), "npm-protect-config-trusted-scopes-"));
  await writeFile(
    path.join(projectDir, "npm-protect.yml"),
    [
      "trustedScopes:",
      "  - mycompany",
    ].join("\n"),
    "utf8",
  );

  const state = await loadConfig(projectDir);

  assert.ok(
    state.validationErrors.some((error) => /trustedScopes entries must be scope strings/u.test(error)),
  );
});

test("loadConfig validates service rebuildSandbox values", async () => {
  const projectDir = await mkdtemp(path.join(tmpdir(), "npm-protect-config-service-"));
  await writeFile(
    path.join(projectDir, "npm-protect.yml"),
    [
      "service:",
      "  rebuildSandbox: strict",
    ].join("\n"),
    "utf8",
  );

  const state = await loadConfig(projectDir);

  assert.ok(
    state.validationErrors.some((error) => /service\.rebuildSandbox must be one of/u.test(error)),
  );
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

test("loadConfig reports insecure local policy file permissions as warnings", async () => {
  const projectDir = await mkdtemp(path.join(tmpdir(), "npm-protect-config-security-"));
  const configPath = path.join(projectDir, "npm-protect.yml");
  const approvalDir = path.join(projectDir, ".npm-protect");
  const approvalPath = path.join(approvalDir, "approvals.json");

  await mkdir(approvalDir, { recursive: true });
  await writeFile(configPath, "mode: enforce\n", "utf8");
  await writeFile(
    approvalPath,
    JSON.stringify(
      {
        version: 1,
        installScripts: [],
      },
      null,
      2,
    ),
    "utf8",
  );
  await chmod(configPath, 0o666);
  await chmod(approvalPath, 0o666);

  const state = await loadConfig(projectDir);

  assert.equal(state.validationErrors.length, 0);
  assert.equal(state.securityWarnings.length, 2);
  assert.ok(state.securityWarnings.some((warning) => warning.includes(configPath)));
  assert.ok(state.securityWarnings.some((warning) => warning.includes(approvalPath)));
});
