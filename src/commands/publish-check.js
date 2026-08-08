import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

import {
  assertSupportedFormat,
  emitOutput,
  resolveOutputFormat,
  resolveOutputPath,
} from "../lib/output.js";
import { loadProjectSnapshot } from "../lib/project.js";
import { serializePublishCheckReport } from "../lib/reporters.js";

export async function runPublishCheckCommand(args) {
  const projectDir = String(args.flags.project ?? process.cwd());
  const format = resolveOutputFormat(args.flags);
  const outputPath = resolveOutputPath(args.flags);
  assertSupportedFormat("publish-check", format, ["text", "json", "sarif", "markdown"]);
  const project = await loadProjectSnapshot(projectDir);
  const workflows = await loadWorkflowFiles(projectDir);
  const sbomFiles = await findSbomFiles(projectDir);
  const npmrcState = await loadOptionalNpmrc(projectDir);

  const findings = [];

  if (!project.repository) {
    findings.push({
      severity: "warn",
      code: "missing_repository",
      message: "package.json does not declare a repository field",
    });
  }

  if (project.manifest.publishConfig?.provenance === false) {
    findings.push({
      severity: "warn",
      code: "provenance_disabled",
      message: "publishConfig.provenance is set to false",
    });
  }

  findings.push(...analyzeNpmrc(npmrcState));

  const publishWorkflows = workflows.filter((workflow) =>
    /npm\s+(publish|stage\s+publish)/.test(workflow.content),
  );

  if (publishWorkflows.length === 0) {
    findings.push({
      severity: "warn",
      code: "missing_publish_workflow",
      message: "no npm publish workflow was detected under .github/workflows",
    });
  }

  if (sbomFiles.length === 0) {
    findings.push({
      severity: "warn",
      code: "missing_sbom_file",
      message: "no SBOM file was detected in the project root or common artifact locations",
    });
  }

  for (const workflow of publishWorkflows) {
    const provider = detectWorkflowProvider(workflow);
    const usesOidc = workflowUsesOidc(provider, workflow.content);
    const usesLongLivedToken = /NPM_TOKEN|NODE_AUTH_TOKEN/.test(workflow.content);
    const provenanceEnabled = workflowPublishesWithProvenance(
      workflow.content,
      project.manifest,
      provider,
      usesOidc,
    );

    if (!/id-token:\s*write/.test(workflow.content)) {
      findings.push({
        severity: "error",
        code: "missing_id_token_permission",
        message: `${workflow.name} publishes packages without an obvious id-token: write permission`,
        details: {
          workflowPath: workflow.path,
        },
      });
    }

    if (usesLongLivedToken) {
      findings.push({
        severity: "warn",
        code: "long_lived_token_reference",
        message: `${workflow.name} references NPM_TOKEN or NODE_AUTH_TOKEN`,
        details: {
          workflowPath: workflow.path,
        },
      });
    }

    if (/provenance:\s*false|NPM_CONFIG_PROVENANCE\s*=\s*false/.test(workflow.content)) {
      findings.push({
        severity: "warn",
        code: "workflow_disables_provenance",
        message: `${workflow.name} appears to disable provenance`,
        details: {
          workflowPath: workflow.path,
        },
      });
    }

    if (provider === "github" && !/uses:\s*actions\/setup-node@/i.test(workflow.content)) {
      findings.push({
        severity: "warn",
        code: "missing_setup_node_for_publish",
        message: `${workflow.name} publishes from GitHub Actions without actions/setup-node`,
        details: {
          workflowPath: workflow.path,
          provider,
        },
      });
    }

    if (provider === "github" && !/contents:\s*read/.test(workflow.content)) {
      findings.push({
        severity: "warn",
        code: "missing_contents_read_permission",
        message: `${workflow.name} does not declare contents: read in workflow permissions`,
        details: {
          workflowPath: workflow.path,
          provider,
        },
      });
    }

    if (provider === "github" && /runs-on:\s*.*self-hosted/i.test(workflow.content)) {
      findings.push({
        severity: "warn",
        code: "self_hosted_runner_publish",
        message: `${workflow.name} appears to publish from a self-hosted GitHub runner`,
        details: {
          workflowPath: workflow.path,
          provider,
        },
      });
    }

    if (
      provider === "github" &&
      project.repository &&
      !isGitHubRepository(project.repository)
    ) {
      findings.push({
        severity: "warn",
        code: "repository_provider_mismatch",
        message: `package.json repository does not appear to point at GitHub even though ${workflow.name} publishes from GitHub Actions`,
        details: {
          workflowPath: workflow.path,
          provider,
          repository: project.repository,
        },
      });
    }

    if (!provenanceEnabled) {
      findings.push({
        severity: "warn",
        code: "publish_without_provenance_signal",
        message: `${workflow.name} does not show an obvious provenance-enabling publish path`,
        details: {
          workflowPath: workflow.path,
          provider,
          usesOidc,
        },
      });
    }

    if (!workflowMentionsSbom(workflow.content) && sbomFiles.length === 0) {
      findings.push({
        severity: "warn",
        code: "missing_sbom_generation",
        message: `${workflow.name} does not appear to generate or publish an SBOM`,
        details: {
          workflowPath: workflow.path,
        },
      });
    }

    const unpinnedActions = findUnpinnedActions(workflow.content);
    for (const action of unpinnedActions) {
      findings.push({
        severity: "warn",
        code: "unpinned_workflow_action",
        message: `${workflow.name} uses ${action} without pinning to a full commit SHA`,
        details: {
          action,
          workflowPath: workflow.path,
        },
      });
    }
  }

  const report = {
    project: project.packageName ?? "(unnamed project)",
    workflowCount: workflows.length,
    publishWorkflowCount: publishWorkflows.length,
    sbomFileCount: sbomFiles.length,
    npmrcPresent: npmrcState.exists,
    findings,
    verdict: findings.some((finding) => finding.severity === "error") ? "block" : findings.length > 0 ? "warn" : "allow",
  };

  await emitOutput(serializePublishCheckReport(report, format), outputPath);

  if (report.verdict === "block") {
    process.exitCode = 2;
  }
}

function detectWorkflowProvider(workflow) {
  if (workflow.path.includes(`${path.sep}.github${path.sep}workflows${path.sep}`)) {
    return "github";
  }

  return "generic";
}

function workflowUsesOidc(provider, content) {
  if (provider === "github") {
    return /id-token:\s*write/.test(content);
  }

  return /\bNPM_ID_TOKEN\b|\bid_tokens:\b/i.test(content);
}

function workflowPublishesWithProvenance(content, manifest, provider, usesOidc) {
  if (/npm\s+(publish|stage\s+publish)[^\n]*--provenance/.test(content)) {
    return true;
  }

  if (/NPM_CONFIG_PROVENANCE\s*[:=]\s*true/.test(content)) {
    return true;
  }

  if (manifest.publishConfig?.provenance === true) {
    return true;
  }

  if ((provider === "github" || provider === "gitlab") && usesOidc) {
    return true;
  }

  return false;
}

function workflowMentionsSbom(content) {
  return /\bnpm\s+sbom\b|\bnpm-protect\s+sbom\b|\bnpm-scan\s+sbom\b|\bcyclonedx\b|\bsyft\b|\bspdx\b|\bsbom\b/i.test(
    content,
  );
}

function isGitHubRepository(repository) {
  return /github\.com[:/]/i.test(repository);
}

function findUnpinnedActions(content) {
  const matches = [...content.matchAll(/uses:\s*([^\s#]+)/g)];
  const actions = [];

  for (const match of matches) {
    const reference = match[1];
    if (reference.startsWith("./")) {
      continue;
    }

    const [, version = ""] = reference.split("@", 2);
    if (!/^[a-f0-9]{40}$/i.test(version)) {
      actions.push(reference);
    }
  }

  return actions;
}

async function loadWorkflowFiles(projectDir) {
  const workflowsDir = path.join(projectDir, ".github", "workflows");

  try {
    const entries = await readdir(workflowsDir, { withFileTypes: true });
    const files = entries.filter(
      (entry) => entry.isFile() && /\.(ya?ml)$/i.test(entry.name),
    );

    const workflows = [];
    for (const file of files) {
      const filePath = path.join(workflowsDir, file.name);
      workflows.push({
        name: file.name,
        path: filePath,
        content: await readFile(filePath, "utf8"),
      });
    }

    return workflows;
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return [];
    }

    throw error;
  }
}

async function findSbomFiles(projectDir) {
  const candidates = [
    "sbom.json",
    "bom.json",
    "cyclonedx.json",
    "sbom.cdx.json",
    "sbom.spdx.json",
    "dist/sbom.json",
    "artifacts/sbom.json",
  ];

  const found = [];

  for (const relativePath of candidates) {
    const absolutePath = path.join(projectDir, relativePath);
    try {
      await readFile(absolutePath, "utf8");
      found.push(relativePath);
    } catch (error) {
      if (!error || error.code !== "ENOENT") {
        throw error;
      }
    }
  }

  return found;
}

async function loadOptionalNpmrc(projectDir) {
  const npmrcPath = path.join(projectDir, ".npmrc");

  try {
    return {
      exists: true,
      path: npmrcPath,
      content: await readFile(npmrcPath, "utf8"),
    };
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return {
        exists: false,
        path: npmrcPath,
        content: "",
      };
    }

    throw error;
  }
}

function analyzeNpmrc(npmrcState) {
  if (!npmrcState.exists) {
    return [];
  }

  const findings = [];
  const lines = npmrcState.content
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#") && !line.startsWith(";"));

  for (const line of lines) {
    if (/\bprovenance\s*=\s*false\b/i.test(line)) {
      findings.push({
        severity: "warn",
        code: "npmrc_disables_provenance",
        message: `.npmrc disables provenance with "${line}"`,
        details: {
          npmrcPath: npmrcState.path,
          line,
        },
      });
    }

    if (/\balways-auth\s*=\s*true\b/i.test(line)) {
      findings.push({
        severity: "warn",
        code: "npmrc_always_auth",
        message: `.npmrc enables always-auth with "${line}"`,
        details: {
          npmrcPath: npmrcState.path,
          line,
        },
      });
    }

    if (hasHardcodedAuthSecret(line)) {
      findings.push({
        severity: "error",
        code: "hardcoded_npm_credentials",
        message: `.npmrc appears to contain hardcoded npm credentials`,
        details: {
          npmrcPath: npmrcState.path,
          line,
        },
      });
      continue;
    }

    if (hasEnvTokenReference(line)) {
      findings.push({
        severity: "warn",
        code: "long_lived_token_reference_in_npmrc",
        message: `.npmrc references an npm auth token with "${line}"`,
        details: {
          npmrcPath: npmrcState.path,
          line,
        },
      });
    }
  }

  return findings;
}

function hasHardcodedAuthSecret(line) {
  if (!/(_authToken|_auth|_password)\s*=/i.test(line)) {
    return false;
  }

  return !/\$\{[^}]+\}/.test(line);
}

function hasEnvTokenReference(line) {
  if (!/(_authToken|_auth|_password)\s*=/i.test(line)) {
    return false;
  }

  return /\$\{[^}]+\}/.test(line);
}
