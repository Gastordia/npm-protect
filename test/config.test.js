import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
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
