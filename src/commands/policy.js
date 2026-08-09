import { access, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  loadInstallScriptApprovalStore,
  parseInstallScriptApprovalSpec,
  writeInstallScriptApprovalStore,
} from "../lib/approvals.js";
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

  if (subcommand === "approve-install-script") {
    await runPolicyApproveInstallScript(args);
    return;
  }

  if (subcommand === "list-approvals") {
    await runPolicyListApprovals(args);
    return;
  }

  if (subcommand === "revoke-install-script") {
    await runPolicyRevokeInstallScript(args);
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
  npm-protect policy approve-install-script <package[@version]> [--project <dir>] [--config <path>] [--expires-days <n>] [--reason <text>] [--json]
  npm-protect policy list-approvals [--project <dir>] [--config <path>] [--json]
  npm-protect policy revoke-install-script <package[@version]> [--project <dir>] [--config <path>] [--json]
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

async function runPolicyApproveInstallScript(args) {
  const projectDir = String(args.flags.project ?? process.cwd());
  const configPath = typeof args.flags.config === "string" ? args.flags.config : null;
  const outputJson = Boolean(args.flags.json);
  const spec = String(args.positionals[0] ?? "");
  const parsedSpec = parseInstallScriptApprovalSpec(spec);
  if (!parsedSpec) {
    throw new Error("approve-install-script requires a package[@version] spec");
  }

  const expiresDays = parseOptionalDays(args.flags["expires-days"], "--expires-days");
  const reason = typeof args.flags.reason === "string" ? args.flags.reason.trim() || null : null;
  const state = await loadConfig(projectDir, configPath);
  const store = await loadInstallScriptApprovalStore(projectDir, state.config.approvals);
  const now = new Date();
  const entry = {
    name: parsedSpec.name,
    version: parsedSpec.version,
    approvedAt: now,
    expiresAt:
      expiresDays === null ? null : new Date(now.getTime() + expiresDays * 24 * 60 * 60 * 1000),
    reason,
    source: "store",
  };
  const approvals = [
    ...store.approvals.filter(
      (approval) => !(approval.name === entry.name && String(approval.version ?? "") === String(entry.version ?? "")),
    ),
    entry,
  ].sort(compareApprovalEntries);
  const storePath = await writeInstallScriptApprovalStore(projectDir, state.config.approvals, approvals);

  if (outputJson) {
    console.log(
      JSON.stringify(
        {
          storePath,
          approval: serializeApproval(entry),
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`Updated ${storePath}`);
  console.log(`Approved ${formatApprovalLabel(entry)}`);
  if (entry.expiresAt) {
    console.log(`Expires: ${entry.expiresAt.toISOString()}`);
  }
  if (entry.reason) {
    console.log(`Reason: ${entry.reason}`);
  }
}

async function runPolicyListApprovals(args) {
  const projectDir = String(args.flags.project ?? process.cwd());
  const configPath = typeof args.flags.config === "string" ? args.flags.config : null;
  const outputJson = Boolean(args.flags.json);
  const state = await loadConfig(projectDir, configPath);
  const approvals = state.config.installScriptApprovals ?? [];
  const expiredApprovals = state.config.approvalState?.expiredApprovals ?? [];

  if (outputJson) {
    console.log(
      JSON.stringify(
        {
          storePath: state.config.approvalState?.source ?? null,
          approvals: approvals.map(serializeApproval),
          expiredApprovals: expiredApprovals.map(serializeApproval),
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`Approval store: ${state.config.approvalState?.source ?? "(not configured)"}`);
  console.log(`Active approvals: ${approvals.length}`);
  if (approvals.length === 0) {
    console.log("");
    console.log("No active install-script approvals.");
  } else {
    for (const approval of approvals) {
      console.log(`- ${formatApprovalLabel(approval)} (${approval.source})${formatApprovalSuffix(approval)}`);
    }
  }

  if (expiredApprovals.length > 0) {
    console.log("");
    console.log("Expired approvals:");
    for (const approval of expiredApprovals) {
      console.log(`- ${formatApprovalLabel(approval)}${formatApprovalSuffix(approval)}`);
    }
  }
}

async function runPolicyRevokeInstallScript(args) {
  const projectDir = String(args.flags.project ?? process.cwd());
  const configPath = typeof args.flags.config === "string" ? args.flags.config : null;
  const outputJson = Boolean(args.flags.json);
  const spec = String(args.positionals[0] ?? "");
  const parsedSpec = parseInstallScriptApprovalSpec(spec);
  if (!parsedSpec) {
    throw new Error("revoke-install-script requires a package[@version] spec");
  }

  const state = await loadConfig(projectDir, configPath);
  const store = await loadInstallScriptApprovalStore(projectDir, state.config.approvals);
  const remaining = store.approvals.filter(
    (approval) => !(approval.name === parsedSpec.name && String(approval.version ?? "") === String(parsedSpec.version ?? "")),
  );

  if (remaining.length === store.approvals.length) {
    throw new Error(`no stored approval matched ${spec}`);
  }

  const storePath = await writeInstallScriptApprovalStore(projectDir, state.config.approvals, remaining);

  if (outputJson) {
    console.log(
      JSON.stringify(
        {
          storePath,
          revoked: {
            package: parsedSpec.name,
            version: parsedSpec.version,
          },
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`Updated ${storePath}`);
  console.log(`Revoked ${parsedSpec.name}${parsedSpec.version ? `@${parsedSpec.version}` : ""}`);
}

function parseOptionalDays(value, flagName) {
  if (value === undefined) {
    return null;
  }

  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${flagName} must be a positive number`);
  }

  return parsed;
}

function serializeApproval(approval) {
  return {
    package: approval.name,
    version: approval.version ?? null,
    source: approval.source,
    approvedAt: approval.approvedAt ? new Date(approval.approvedAt).toISOString() : null,
    expiresAt: approval.expiresAt ? new Date(approval.expiresAt).toISOString() : null,
    reason: approval.reason ?? null,
  };
}

function formatApprovalLabel(approval) {
  return `${approval.name}${approval.version ? `@${approval.version}` : ""}`;
}

function formatApprovalSuffix(approval) {
  const parts = [];
  if (approval.expiresAt) {
    parts.push(`expires ${approval.expiresAt.toISOString()}`);
  }
  if (approval.reason) {
    parts.push(`reason: ${approval.reason}`);
  }

  return parts.length > 0 ? `, ${parts.join(", ")}` : "";
}

function compareApprovalEntries(left, right) {
  const byName = left.name.localeCompare(right.name);
  if (byName !== 0) {
    return byName;
  }

  return String(left.version ?? "").localeCompare(String(right.version ?? ""));
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
