import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { inspectLocalPolicyFile } from "./file-security.js";
import { fileExists } from "./project.js";

export const DEFAULT_APPROVAL_STORE_PATH = ".npm-protect/approvals.json";
export const APPROVAL_STORE_VERSION = 1;

export async function loadInstallScriptApprovalStore(projectDir, approvalSettings = {}) {
  const storePath = resolveApprovalStorePath(projectDir, approvalSettings.path);

  if (!(await fileExists(storePath))) {
    return {
      source: storePath,
      exists: false,
      approvals: [],
      expiredApprovals: [],
      raw: {
        version: APPROVAL_STORE_VERSION,
        installScripts: [],
      },
      validationErrors: [],
      securityWarnings: [],
    };
  }

  let raw;
  const securityWarnings = await inspectLocalPolicyFile(storePath, "approval store");

  try {
    raw = JSON.parse(await readFile(storePath, "utf8"));
  } catch (error) {
    return {
      source: storePath,
      exists: true,
      approvals: [],
      expiredApprovals: [],
      raw: null,
      validationErrors: [
        `unable to parse approval store ${storePath}: ${error instanceof Error ? error.message : String(error)}`,
      ],
      securityWarnings,
    };
  }

  const parsed = normalizeApprovalStore(raw, {
    sourceLabel: storePath,
  });

  return {
    source: storePath,
    exists: true,
    approvals: parsed.approvals,
    expiredApprovals: parsed.expiredApprovals,
    raw,
    validationErrors: parsed.validationErrors,
    securityWarnings,
  };
}

export async function writeInstallScriptApprovalStore(
  projectDir,
  approvalSettings = {},
  approvals = [],
) {
  const storePath = resolveApprovalStorePath(projectDir, approvalSettings.path);
  await mkdir(path.dirname(storePath), { recursive: true });
  await writeFile(
    storePath,
    JSON.stringify(
      {
        version: APPROVAL_STORE_VERSION,
        installScripts: approvals.map(serializeApprovalEntry),
      },
      null,
      2,
    ),
    "utf8",
  );
  await chmod(storePath, 0o600);

  return storePath;
}

export function normalizeConfiguredInstallScriptApprovals(entries = []) {
  const approvals = [];
  const validationErrors = [];

  for (const entry of entries) {
    if (typeof entry !== "string") {
      validationErrors.push("allowedInstallScripts entries must be strings");
      continue;
    }

    const parsed = parseInstallScriptApprovalSpec(entry);
    if (!parsed) {
      validationErrors.push(`allowedInstallScripts entry "${entry}" is not a valid package spec`);
      continue;
    }

    approvals.push({
      name: parsed.name,
      version: parsed.version,
      approvedAt: null,
      expiresAt: null,
      reason: null,
      source: "config",
    });
  }

  return {
    approvals,
    validationErrors,
  };
}

export function normalizeApprovalStore(raw, options = {}) {
  const sourceLabel = options.sourceLabel ?? "approval store";
  const validationErrors = [];
  const approvals = [];
  const expiredApprovals = [];

  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return {
      approvals,
      expiredApprovals,
      validationErrors: [`${sourceLabel} must be a JSON object`],
    };
  }

  if (raw.version !== undefined && raw.version !== APPROVAL_STORE_VERSION) {
    validationErrors.push(
      `${sourceLabel} uses unsupported version ${raw.version}; expected ${APPROVAL_STORE_VERSION}`,
    );
  }

  const installScripts = raw.installScripts ?? [];
  if (!Array.isArray(installScripts)) {
    validationErrors.push(`${sourceLabel} installScripts must be an array`);
    return {
      approvals,
      expiredApprovals,
      validationErrors,
    };
  }

  for (const entry of installScripts) {
    const normalized = normalizeApprovalEntry(entry, sourceLabel);
    if ("error" in normalized) {
      validationErrors.push(normalized.error);
      continue;
    }

    if (normalized.expiresAt && normalized.expiresAt.getTime() <= Date.now()) {
      expiredApprovals.push(normalized);
      continue;
    }

    approvals.push(normalized);
  }

  return {
    approvals,
    expiredApprovals,
    validationErrors,
  };
}

export function mergeInstallScriptApprovals(...approvalLists) {
  const merged = [];
  const seen = new Set();

  for (const list of approvalLists) {
    for (const approval of list ?? []) {
      const key = `${approval.name}@${approval.version ?? "*"}`;
      if (seen.has(key)) {
        continue;
      }

      seen.add(key);
      merged.push(approval);
    }
  }

  return merged.sort(compareApprovals);
}

export function isInstallScriptPackageApproved(config, packageName, version, now = new Date()) {
  return Boolean(findInstallScriptApproval(config, packageName, version, now));
}

export function findInstallScriptApproval(config, packageName, version, now = new Date()) {
  const approvals = Array.isArray(config?.installScriptApprovals)
    ? config.installScriptApprovals
    : normalizeConfiguredInstallScriptApprovals(config?.allowedInstallScripts ?? []).approvals;

  for (const approval of approvals) {
    if (approval.name !== packageName) {
      continue;
    }

    if (approval.version && approval.version !== version) {
      continue;
    }

    if (approval.expiresAt && approval.expiresAt.getTime() <= now.getTime()) {
      continue;
    }

    return approval;
  }

  return null;
}

export function buildApprovalCommand(packageName, version, options = {}) {
  const spec = version ? `${packageName}@${version}` : packageName;
  const parts = ["npm-protect", "policy", "approve-install-script", spec];

  if (options.projectDir) {
    parts.push("--project", shellQuote(options.projectDir));
  }

  if (options.expiresDays) {
    parts.push("--expires-days", String(options.expiresDays));
  }

  return parts.join(" ");
}

export function parseInstallScriptApprovalSpec(spec) {
  if (typeof spec !== "string") {
    return null;
  }

  const trimmed = spec.trim();
  if (trimmed.length === 0) {
    return null;
  }

  if (trimmed.startsWith("@")) {
    const secondAt = trimmed.lastIndexOf("@");
    if (secondAt > 0) {
      const name = trimmed.slice(0, secondAt);
      const version = trimmed.slice(secondAt + 1);
      if (name.includes("/") && version.length > 0) {
        return {
          name,
          version,
        };
      }
    }

    return trimmed.includes("/")
      ? {
          name: trimmed,
          version: null,
        }
      : null;
  }

  const atIndex = trimmed.lastIndexOf("@");
  if (atIndex > 0) {
    return {
      name: trimmed.slice(0, atIndex),
      version: trimmed.slice(atIndex + 1) || null,
    };
  }

  return {
    name: trimmed,
    version: null,
  };
}

function normalizeApprovalEntry(entry, sourceLabel) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    return {
      error: `${sourceLabel} installScripts entries must be objects`,
    };
  }

  const packageName = typeof entry.package === "string" ? entry.package.trim() : "";
  if (packageName.length === 0) {
    return {
      error: `${sourceLabel} approval entries must include a non-empty "package"`,
    };
  }

  const packageVersion =
    typeof entry.version === "string" && entry.version.trim().length > 0
      ? entry.version.trim()
      : null;
  const approvedAt = parseOptionalDate(entry.approvedAt, sourceLabel, "approvedAt");
  if ("error" in approvedAt) {
    return approvedAt;
  }

  const expiresAt = parseOptionalDate(entry.expiresAt, sourceLabel, "expiresAt");
  if ("error" in expiresAt) {
    return expiresAt;
  }

  return {
    name: packageName,
    version: packageVersion,
    approvedAt: approvedAt.value,
    expiresAt: expiresAt.value,
    reason:
      typeof entry.reason === "string" && entry.reason.trim().length > 0
        ? entry.reason.trim()
        : null,
    source: "store",
  };
}

function parseOptionalDate(value, sourceLabel, fieldName) {
  if (value === undefined || value === null || value === "") {
    return {
      value: null,
    };
  }

  if (typeof value !== "string") {
    return {
      error: `${sourceLabel} ${fieldName} must be an ISO 8601 string when provided`,
    };
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return {
      error: `${sourceLabel} ${fieldName} "${value}" is not a valid date`,
    };
  }

  return {
    value: parsed,
  };
}

function serializeApprovalEntry(entry) {
  return {
    package: entry.name,
    version: entry.version ?? undefined,
    approvedAt: entry.approvedAt ? new Date(entry.approvedAt).toISOString() : undefined,
    expiresAt: entry.expiresAt ? new Date(entry.expiresAt).toISOString() : undefined,
    reason: entry.reason ?? undefined,
  };
}

function compareApprovals(left, right) {
  const nameComparison = left.name.localeCompare(right.name);
  if (nameComparison !== 0) {
    return nameComparison;
  }

  return String(left.version ?? "").localeCompare(String(right.version ?? ""));
}

function resolveApprovalStorePath(projectDir, configuredPath = DEFAULT_APPROVAL_STORE_PATH) {
  if (path.isAbsolute(configuredPath)) {
    return configuredPath;
  }

  return path.resolve(projectDir, configuredPath);
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'\"'\"'`)}'`;
}
