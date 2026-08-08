import { access, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  DEFAULT_CONFIG_TEMPLATE,
  loadConfig,
  validateConfig,
} from "../lib/config.js";

export async function runPolicyCommand(subcommand, args) {
  if (!subcommand || subcommand === "--help" || subcommand === "-h") {
    printPolicyHelp();
    return;
  }

  if (subcommand === "init") {
    await runPolicyInit(args);
    return;
  }

  if (subcommand === "validate") {
    await runPolicyValidate(args);
    return;
  }

  throw new Error(`unknown policy subcommand "${subcommand}"`);
}

async function runPolicyInit(args) {
  const projectDir = String(args.flags.project ?? process.cwd());
  const targetPath = path.join(projectDir, "npm-protect.yml");
  const workflowPath = path.join(projectDir, ".github", "workflows", "npm-protect.yml");
  const overwrite = Boolean(args.flags.force);
  const withGitHubActions = Boolean(args.flags["github-actions"]);

  await assertWritableTarget(targetPath, overwrite);
  if (withGitHubActions) {
    await assertWritableTarget(workflowPath, overwrite);
  }

  await writeFile(targetPath, DEFAULT_CONFIG_TEMPLATE, "utf8");
  console.log(`Wrote ${targetPath}`);

  if (withGitHubActions) {
    await mkdir(path.dirname(workflowPath), { recursive: true });
    await writeFile(workflowPath, DEFAULT_GITHUB_ACTION_WORKFLOW_TEMPLATE, "utf8");
    console.log(`Wrote ${workflowPath}`);
  }
}

async function runPolicyValidate(args) {
  const projectDir = String(args.flags.project ?? process.cwd());
  const outputJson = Boolean(args.flags.json);
  const configPath = typeof args.flags.config === "string" ? args.flags.config : null;
  const state = await loadConfig(projectDir, configPath);
  const extraErrors = validateConfig(state.rawConfig);
  const validationErrors = [...state.validationErrors, ...extraErrors];

  if (outputJson) {
    console.log(
      JSON.stringify(
        {
          source: state.source,
          config: state.config,
          valid: validationErrors.length === 0,
          errors: validationErrors,
        },
        null,
        2,
      ),
    );
  } else {
    console.log(`Config source: ${state.source ?? "defaults"}`);
    console.log(`Valid: ${validationErrors.length === 0 ? "yes" : "no"}`);
    if (validationErrors.length > 0) {
      console.log("");
      for (const error of validationErrors) {
        console.log(`- ${error}`);
      }
    }
  }

  if (validationErrors.length > 0) {
    process.exitCode = 2;
  }
}

function printPolicyHelp() {
  console.log(`npm-protect policy

Usage:
  npm-protect policy init [--project <dir>] [--force] [--github-actions]
  npm-protect policy validate [--project <dir>] [--config <path>] [--json]
`);
}

async function assertWritableTarget(targetPath, overwrite) {
  if (overwrite) {
    return;
  }

  try {
    await access(targetPath);
    throw new Error(`refusing to overwrite existing file at ${targetPath}; use --force`);
  } catch (error) {
    if (error && error.code !== "ENOENT") {
      throw error;
    }
  }
}

const DEFAULT_GITHUB_ACTION_WORKFLOW_TEMPLATE = `name: npm-protect

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-node@v4
        with:
          node-version: "22"
      - uses: ./
        with:
          command: diff
          before-ref: \${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || 'HEAD~1' }}
          after-ref: \${{ github.sha }}
          format: json
          write-summary: "true"
`;
