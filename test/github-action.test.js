import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import {
  buildGitHubActionPlan,
  supportsGitHubAnnotations,
  supportsMarkdownSummary,
} from "../src/lib/github-action.js";

test("buildGitHubActionPlan builds default review arguments", () => {
  const plan = buildGitHubActionPlan({
    GITHUB_WORKSPACE: "/workspace/repo",
    RUNNER_TEMP: "/tmp/runner",
    INPUT_ONLINE: "true",
    INPUT_CACHE_DIR: ".npm-protect-cache",
  });

  assert.equal(plan.command, "review");
  assert.equal(plan.format, "json");
  assert.equal(plan.outputPath, path.join("/tmp/runner", "npm-protect-result.json"));
  assert.deepEqual(plan.args, [
    "review",
    "--project",
    "/workspace/repo",
    "--cache-dir",
    ".npm-protect-cache",
    "--online",
    "--format",
    "json",
    "--output",
    path.join("/tmp/runner", "npm-protect-result.json"),
  ]);
  assert.ok(plan.summaryArgs);
  assert.equal(plan.annotationArgs, null);
  assert.deepEqual(plan.summaryArgs, [
    "review",
    "--project",
    "/workspace/repo",
    "--cache-dir",
    ".npm-protect-cache",
    "--online",
    "--format",
    "markdown",
    "--output",
    path.join("/tmp/runner", "npm-protect-summary.md"),
  ]);
});

test("buildGitHubActionPlan supports git diff inputs", () => {
  const plan = buildGitHubActionPlan({
    GITHUB_WORKSPACE: "/workspace/repo",
    RUNNER_TEMP: "/tmp/runner",
    INPUT_COMMAND: "diff",
    INPUT_BEFORE_REF: "origin/main",
    INPUT_AFTER_REF: "HEAD",
    INPUT_LOCKFILE_PATH: "frontend/package-lock.json",
    INPUT_FORMAT: "sarif",
    INPUT_WRITE_SUMMARY: "false",
  });

  assert.equal(plan.command, "diff");
  assert.equal(plan.summaryArgs, null);
  assert.ok(plan.annotationArgs);
  assert.deepEqual(plan.args, [
    "diff",
    "--project",
    "/workspace/repo",
    "--before-ref",
    "origin/main",
    "--after-ref",
    "HEAD",
    "--lockfile-path",
    "frontend/package-lock.json",
    "--format",
    "sarif",
    "--output",
    path.join("/tmp/runner", "npm-protect-result.sarif"),
  ]);
  assert.deepEqual(plan.annotationArgs, [
    "diff",
    "--project",
    "/workspace/repo",
    "--before-ref",
    "origin/main",
    "--after-ref",
    "HEAD",
    "--lockfile-path",
    "frontend/package-lock.json",
    "--format",
    "json",
    "--output",
    path.join("/tmp/runner", "npm-protect-annotations.json"),
  ]);
});

test("supportsMarkdownSummary only enables supported commands", () => {
  assert.equal(supportsMarkdownSummary("review"), true);
  assert.equal(supportsMarkdownSummary("publish-check"), true);
  assert.equal(supportsMarkdownSummary("sbom"), false);
});

test("supportsGitHubAnnotations only enables supported commands", () => {
  assert.equal(supportsGitHubAnnotations("review"), true);
  assert.equal(supportsGitHubAnnotations("publish-check"), true);
  assert.equal(supportsGitHubAnnotations("sbom"), false);
});
