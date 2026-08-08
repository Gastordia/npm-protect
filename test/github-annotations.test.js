import assert from "node:assert/strict";
import test from "node:test";

import { buildGitHubAnnotations, supportsGitHubAnnotations } from "../src/lib/github-annotations.js";

test("buildGitHubAnnotations renders review findings as workflow commands", () => {
  const lines = buildGitHubAnnotations("review", {
    project: {
      manifestPath: "/repo/package.json",
      lockfilePath: "/repo/package-lock.json",
    },
    findings: [
      {
        severity: "warn",
        code: "suspicious_typosquat",
        message: "expres@1.0.0 is close to express",
        packagePath: "node_modules/expres",
      },
      {
        severity: "error",
        code: "missing_repository",
        message: "package.json does not declare a repository field",
      },
    ],
  });

  assert.equal(lines.length, 2);
  assert.match(lines[0], /^::warning /);
  assert.match(lines[0], /file=\/repo\/package-lock\.json/);
  assert.match(lines[1], /^::error /);
  assert.match(lines[1], /file=\/repo\/package\.json/);
});

test("buildGitHubAnnotations renders diff risky adds", () => {
  const lines = buildGitHubAnnotations("diff", {
    riskyAdds: [
      {
        name: "esbuild",
        version: "0.25.0",
      },
    ],
    changedNames: [],
  });

  assert.equal(lines.length, 1);
  assert.match(lines[0], /^::error /);
  assert.match(lines[0], /risky_added_package/);
});

test("buildGitHubAnnotations renders diff artifact drift", () => {
  const lines = buildGitHubAnnotations("diff", {
    riskyAdds: [],
    changedNames: [],
    changedArtifacts: [
      {
        name: "left-pad",
        version: "1.3.0",
        beforeResolved: ["https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"],
        afterResolved: ["https://mirror.example/left-pad-1.3.0.tgz"],
        beforeIntegrity: ["sha512-before"],
        afterIntegrity: ["sha512-after"],
        resolvedChanged: true,
        integrityChanged: true,
      },
    ],
  });

  assert.equal(lines.length, 2);
  assert.match(lines[0], /^::warning /);
  assert.match(lines[0], /dependency_source_changed/);
  assert.match(lines[1], /^::error /);
  assert.match(lines[1], /dependency_integrity_changed/);
});

test("supportsGitHubAnnotations limits supported commands", () => {
  assert.equal(supportsGitHubAnnotations("review"), true);
  assert.equal(supportsGitHubAnnotations("publish-check"), true);
  assert.equal(supportsGitHubAnnotations("sbom"), false);
});
