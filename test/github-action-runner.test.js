import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import { executeGitHubAction } from "../src/lib/github-action-runner.js";

test("executeGitHubAction writes outputs, summary, and annotations", async () => {
  const files = new Map();
  const logs = [];

  const result = await executeGitHubAction(
    {
      GITHUB_WORKSPACE: "/workspace/repo",
      RUNNER_TEMP: "/tmp/runner",
      GITHUB_OUTPUT: "/tmp/github-output.txt",
      GITHUB_STEP_SUMMARY: "/tmp/github-summary.txt",
      INPUT_COMMAND: "review",
      INPUT_PROJECT: "/workspace/repo",
      INPUT_FORMAT: "json",
      INPUT_WRITE_SUMMARY: "true",
      INPUT_ANNOTATE_FINDINGS: "true",
    },
    {
      async ensureDir() {},
      async runCliCommand(args) {
        const outputPath = args[args.indexOf("--output") + 1];
        const format = args[args.indexOf("--format") + 1];

        if (format === "json") {
          files.set(
            outputPath,
            JSON.stringify({
              project: {
                manifestPath: "/workspace/repo/package.json",
                lockfilePath: "/workspace/repo/package-lock.json",
              },
              findings: [
                {
                  severity: "warn",
                  code: "missing_integrity",
                  message: "demo is missing integrity",
                },
              ],
            }),
          );
        } else if (format === "markdown") {
          files.set(outputPath, "# npm-protect review");
        }

        return 2;
      },
      async readText(filePath) {
        return files.get(filePath) ?? "";
      },
      async appendText(filePath, content) {
        files.set(filePath, (files.get(filePath) ?? "") + content);
      },
      log(line) {
        logs.push(line);
      },
    },
  );

  assert.equal(result.exitCode, 2);
  assert.equal(result.annotationCount, 1);
  assert.match(logs[0], /^::warning /);
  assert.match(files.get("/tmp/github-summary.txt"), /# npm-protect review/);
  assert.match(files.get("/tmp/github-output.txt"), /annotation_count=1/);
  assert.equal(result.outputs.result_path, path.join("/tmp/runner", "npm-protect-result.json"));
});
