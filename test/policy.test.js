import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import { DEFAULT_CONFIG } from "../src/lib/config.js";
import { evaluateProject } from "../src/lib/policy.js";
import { loadProjectSnapshot } from "../src/lib/project.js";

const fixturesDir = path.join(process.cwd(), "test", "fixtures");

test("evaluateProject reports warn-level dependency issues without blocking in warn mode", async () => {
  const project = await loadProjectSnapshot(path.join(fixturesDir, "warn-project"));
  const report = evaluateProject(project, DEFAULT_CONFIG, []);

  assert.equal(report.riskVerdict, "warn");
  assert.equal(report.verdict, "warn");
  assert.equal(report.stats.directNonRegistryDependencyCount, 1);
  assert.ok(report.findings.some((finding) => finding.code === "suspicious_typosquat"));
  assert.ok(
    report.findings.some((finding) => finding.code === "non_registry_direct_dependency"),
  );
});

test("evaluateProject blocks unapproved install scripts in enforce mode", async () => {
  const project = await loadProjectSnapshot(path.join(fixturesDir, "block-project"));
  const report = evaluateProject(project, {
    ...DEFAULT_CONFIG,
    mode: "enforce",
  });

  assert.equal(report.riskVerdict, "block");
  assert.equal(report.verdict, "block");
  assert.ok(
    report.findings.some((finding) => finding.code === "unreviewed_install_script"),
  );
});

test("loadProjectSnapshot annotates top-level direct dependencies", async () => {
  const project = await loadProjectSnapshot(path.join(fixturesDir, "block-project"));
  const esbuild = project.lockfile.packages.find((pkg) => pkg.name === "esbuild");

  assert.equal(esbuild.isTopLevel, true);
  assert.equal(esbuild.isDirectDependency, true);
});
