import { readFile } from "node:fs/promises";
import path from "node:path";

import {
  DEFAULT_APPROVAL_STORE_PATH,
  loadInstallScriptApprovalStore,
  mergeInstallScriptApprovals,
  normalizeConfiguredInstallScriptApprovals,
} from "./approvals.js";
import { fileExists } from "./project.js";

export const DEFAULT_CONFIG = {
  mode: "warn",
  trustedScopes: [],
  allowedInstallScripts: [],
  approvals: {
    path: DEFAULT_APPROVAL_STORE_PATH,
  },
  services: {
    osv: {
      enabled: false,
      url: "https://api.osv.dev/v1/querybatch",
      timeoutMs: 5000,
    },
    registry: {
      enabled: false,
      url: "https://registry.npmjs.org",
      timeoutMs: 5000,
      warnPackageAgeDays: 14,
    },
    tarballs: {
      enabled: false,
      timeoutMs: 10000,
      maxFilesPerPackage: 6,
      maxFileBytes: 65536,
      selection: "focused",
      maxPackages: 0,
    },
    auditSignatures: {
      enabled: false,
      includeAttestations: true,
      timeoutMs: 15000,
    },
  },
  blockRules: {
    requireLockfile: true,
    unreviewedInstallScripts: true,
    missingIntegrity: false,
    typosquatScoreThreshold: 0.85,
    vulnerabilitySeverityThreshold: "high",
    requireRegistrySignatures: false,
    requireVerifiedAttestations: false,
    minPackageAgeDays: 0,
    suspiciousTarballIndicators: false,
    integrityMismatch: true,
  },
  warnRules: {
    suspiciousTyposquats: true,
    missingRepository: true,
    knownVulnerabilities: true,
    missingRegistrySignatures: true,
    missingVerifiedAttestations: true,
    freshPackages: true,
    suspiciousTarballIndicators: true,
    auditSignaturesUnavailable: true,
    externalServiceFailures: true,
    expiredInstallScriptApprovals: true,
  },
};

export const DEFAULT_CONFIG_TEMPLATE = `mode: enforce

trustedScopes:
  - "@mycompany"

allowedInstallScripts:
  - esbuild@0.25.0
  - sharp@0.34.0

approvals:
  path: ".npm-protect/approvals.json"

services:
  osv:
    enabled: false
    url: "https://api.osv.dev/v1/querybatch"
  registry:
    enabled: false
    url: "https://registry.npmjs.org"
    warnPackageAgeDays: 14
  tarballs:
    enabled: false
    timeoutMs: 10000
    maxFilesPerPackage: 6
    maxFileBytes: 65536
    selection: focused
    maxPackages: 0
  auditSignatures:
    enabled: false
    includeAttestations: true

blockRules:
  requireLockfile: true
  unreviewedInstallScripts: true
  missingIntegrity: false
  typosquatScoreThreshold: 0.85
  vulnerabilitySeverityThreshold: high
  requireRegistrySignatures: false
  requireVerifiedAttestations: false
  minPackageAgeDays: 0
  suspiciousTarballIndicators: false
  integrityMismatch: true

warnRules:
  suspiciousTyposquats: true
  missingRepository: true
  knownVulnerabilities: true
  missingRegistrySignatures: true
  missingVerifiedAttestations: true
  freshPackages: true
  suspiciousTarballIndicators: true
  auditSignaturesUnavailable: true
  externalServiceFailures: true
  expiredInstallScriptApprovals: true
`;

const CONFIG_FILENAMES = [
  "npm-protect.yml",
  "npm-protect.yaml",
  "npm-protect.json",
  "npm-scan.yml",
  "npm-scan.yaml",
  "npm-scan.json",
];

export async function loadConfig(projectDir, explicitPath = null) {
  const source = explicitPath ? path.resolve(explicitPath) : await findConfigPath(projectDir);

  if (!source) {
    const configuredApprovals = normalizeConfiguredInstallScriptApprovals(
      DEFAULT_CONFIG.allowedInstallScripts,
    );
    const approvalState = await loadInstallScriptApprovalStore(
      projectDir,
      DEFAULT_CONFIG.approvals,
    );
    return {
      source: null,
      rawConfig: structuredClone(DEFAULT_CONFIG),
      config: {
        ...structuredClone(DEFAULT_CONFIG),
        installScriptApprovals: mergeInstallScriptApprovals(
          configuredApprovals.approvals,
          approvalState.approvals,
        ),
        approvalState,
      },
      validationErrors: [
        ...configuredApprovals.validationErrors,
        ...approvalState.validationErrors,
      ],
    };
  }

  let rawConfig;
  const validationErrors = [];

  try {
    const content = await readFile(source, "utf8");
    rawConfig = parseConfig(source, content);
  } catch (error) {
    rawConfig = {};
    validationErrors.push(
      `unable to parse config file ${source}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  validationErrors.push(...validateConfig(rawConfig));
  const config = mergeConfig(DEFAULT_CONFIG, rawConfig);
  const configuredApprovals = normalizeConfiguredInstallScriptApprovals(config.allowedInstallScripts);
  validationErrors.push(...configuredApprovals.validationErrors);
  const approvalState = await loadInstallScriptApprovalStore(
    projectDir,
    config.approvals,
  );
  validationErrors.push(...approvalState.validationErrors);
  const mergedApprovals = mergeInstallScriptApprovals(
    configuredApprovals.approvals,
    approvalState.approvals,
  );

  return {
    source,
    rawConfig,
    config: {
      ...config,
      installScriptApprovals: mergedApprovals,
      approvalState,
    },
    validationErrors,
  };
}

export function validateConfig(config) {
  const errors = [];

  if (!config || typeof config !== "object" || Array.isArray(config)) {
    return ["config must be an object"];
  }

  if (config.mode !== undefined && !["warn", "enforce"].includes(config.mode)) {
    errors.push('mode must be "warn" or "enforce"');
  }

  if (config.trustedScopes !== undefined && !Array.isArray(config.trustedScopes)) {
    errors.push("trustedScopes must be an array");
  }

  if (
    config.allowedInstallScripts !== undefined &&
    !Array.isArray(config.allowedInstallScripts)
  ) {
    errors.push("allowedInstallScripts must be an array");
  }

  if (config.approvals !== undefined && !isPlainObject(config.approvals)) {
    errors.push("approvals must be an object");
  }

  if (config.blockRules !== undefined && !isPlainObject(config.blockRules)) {
    errors.push("blockRules must be an object");
  }

  if (config.warnRules !== undefined && !isPlainObject(config.warnRules)) {
    errors.push("warnRules must be an object");
  }

  if (config.services !== undefined && !isPlainObject(config.services)) {
    errors.push("services must be an object");
  }

  if (
    config.approvals?.path !== undefined &&
    (typeof config.approvals.path !== "string" || config.approvals.path.trim().length === 0)
  ) {
    errors.push("approvals.path must be a non-empty string");
  }

  const threshold = config.blockRules?.typosquatScoreThreshold;
  if (threshold !== undefined && (typeof threshold !== "number" || threshold <= 0 || threshold > 1)) {
    errors.push("blockRules.typosquatScoreThreshold must be a number between 0 and 1");
  }

  const vulnerabilitySeverityThreshold = config.blockRules?.vulnerabilitySeverityThreshold;
  if (
    vulnerabilitySeverityThreshold !== undefined &&
    !["none", "low", "moderate", "high", "critical"].includes(
      vulnerabilitySeverityThreshold,
    )
  ) {
    errors.push(
      'blockRules.vulnerabilitySeverityThreshold must be one of "none", "low", "moderate", "high", or "critical"',
    );
  }

  const minimumPackageAge = config.blockRules?.minPackageAgeDays;
  if (
    minimumPackageAge !== undefined &&
    (typeof minimumPackageAge !== "number" || minimumPackageAge < 0)
  ) {
    errors.push("blockRules.minPackageAgeDays must be a non-negative number");
  }

  if (
    config.blockRules?.suspiciousTarballIndicators !== undefined &&
    typeof config.blockRules.suspiciousTarballIndicators !== "boolean"
  ) {
    errors.push("blockRules.suspiciousTarballIndicators must be a boolean");
  }

  if (config.services?.osv !== undefined && !isPlainObject(config.services.osv)) {
    errors.push("services.osv must be an object");
  }

  if (
    config.services?.registry !== undefined &&
    !isPlainObject(config.services.registry)
  ) {
    errors.push("services.registry must be an object");
  }

  const warnPackageAgeDays = config.services?.registry?.warnPackageAgeDays;
  if (
    warnPackageAgeDays !== undefined &&
    (typeof warnPackageAgeDays !== "number" || warnPackageAgeDays < 0)
  ) {
    errors.push("services.registry.warnPackageAgeDays must be a non-negative number");
  }

  if (
    config.services?.auditSignatures !== undefined &&
    !isPlainObject(config.services.auditSignatures)
  ) {
    errors.push("services.auditSignatures must be an object");
  }

  if (
    config.services?.tarballs !== undefined &&
    !isPlainObject(config.services.tarballs)
  ) {
    errors.push("services.tarballs must be an object");
  }

  const maxFilesPerPackage = config.services?.tarballs?.maxFilesPerPackage;
  if (
    maxFilesPerPackage !== undefined &&
    (!Number.isInteger(maxFilesPerPackage) || maxFilesPerPackage < 0)
  ) {
    errors.push("services.tarballs.maxFilesPerPackage must be a non-negative integer");
  }

  const maxFileBytes = config.services?.tarballs?.maxFileBytes;
  if (
    maxFileBytes !== undefined &&
    (!Number.isInteger(maxFileBytes) || maxFileBytes <= 0)
  ) {
    errors.push("services.tarballs.maxFileBytes must be a positive integer");
  }

  const tarballSelection = config.services?.tarballs?.selection;
  if (
    tarballSelection !== undefined &&
    !["focused", "all"].includes(tarballSelection)
  ) {
    errors.push('services.tarballs.selection must be either "focused" or "all"');
  }

  const tarballMaxPackages = config.services?.tarballs?.maxPackages;
  if (
    tarballMaxPackages !== undefined &&
    (!Number.isInteger(tarballMaxPackages) || tarballMaxPackages < 0)
  ) {
    errors.push("services.tarballs.maxPackages must be a non-negative integer");
  }

  return errors;
}

async function findConfigPath(projectDir) {
  for (const filename of CONFIG_FILENAMES) {
    const candidate = path.join(projectDir, filename);
    if (await fileExists(candidate)) {
      return candidate;
    }
  }

  return null;
}

function parseConfig(filePath, content) {
  if (filePath.endsWith(".json")) {
    return JSON.parse(content);
  }

  return parseSimpleYaml(content);
}

function parseSimpleYaml(content) {
  const lines = content
    .split(/\r?\n/u)
    .map((line) => stripInlineComment(line))
    .map((line) => ({
      raw: line,
      indent: countIndent(line),
      content: line.trim(),
    }))
    .filter((line) => line.content.length > 0);

  if (lines.length === 0) {
    return {};
  }

  const [result] = parseObjectBlock(lines, 0, 0);
  return result;
}

function parseObjectBlock(lines, startIndex, indent) {
  const object = {};
  let index = startIndex;

  while (index < lines.length) {
    const line = lines[index];

    if (line.indent < indent) {
      break;
    }

    if (line.indent !== indent) {
      throw new Error(`invalid YAML indentation near "${line.raw}"`);
    }

    if (line.content.startsWith("- ")) {
      throw new Error(`unexpected array item near "${line.raw}"`);
    }

    const separator = line.content.indexOf(":");
    if (separator === -1) {
      throw new Error(`expected key/value pair near "${line.raw}"`);
    }

    const key = line.content.slice(0, separator).trim();
    const valueText = line.content.slice(separator + 1).trim();

    if (valueText.length > 0) {
      object[key] = parseScalar(valueText);
      index += 1;
      continue;
    }

    const next = lines[index + 1];
    if (!next || next.indent <= indent) {
      object[key] = {};
      index += 1;
      continue;
    }

    if (next.content.startsWith("- ")) {
      const [value, nextIndex] = parseArrayBlock(lines, index + 1, indent + 2);
      object[key] = value;
      index = nextIndex;
      continue;
    }

    const [value, nextIndex] = parseObjectBlock(lines, index + 1, indent + 2);
    object[key] = value;
    index = nextIndex;
  }

  return [object, index];
}

function parseArrayBlock(lines, startIndex, indent) {
  const values = [];
  let index = startIndex;

  while (index < lines.length) {
    const line = lines[index];
    if (line.indent < indent) {
      break;
    }

    if (line.indent !== indent || !line.content.startsWith("- ")) {
      throw new Error(`invalid array item near "${line.raw}"`);
    }

    values.push(parseScalar(line.content.slice(2).trim()));
    index += 1;
  }

  return [values, index];
}

function parseScalar(value) {
  if (value === "true") {
    return true;
  }

  if (value === "false") {
    return false;
  }

  if (/^-?\d+(\.\d+)?$/u.test(value)) {
    return Number(value);
  }

  if (value === "[]") {
    return [];
  }

  if (value === "{}") {
    return {};
  }

  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }

  return value;
}

function stripInlineComment(line) {
  const hashIndex = line.indexOf("#");
  if (hashIndex === -1) {
    return line;
  }

  return line.slice(0, hashIndex);
}

function countIndent(value) {
  const match = value.match(/^ */u);
  return match ? match[0].length : 0;
}

function mergeConfig(defaults, config) {
  return {
    mode: config.mode ?? defaults.mode,
    trustedScopes: Array.isArray(config.trustedScopes)
      ? [...config.trustedScopes]
      : [...defaults.trustedScopes],
    allowedInstallScripts: Array.isArray(config.allowedInstallScripts)
      ? [...config.allowedInstallScripts]
      : [...defaults.allowedInstallScripts],
    approvals: {
      ...defaults.approvals,
      ...(isPlainObject(config.approvals) ? config.approvals : {}),
    },
    services: {
      osv: {
        ...defaults.services.osv,
        ...(isPlainObject(config.services?.osv) ? config.services.osv : {}),
      },
      registry: {
        ...defaults.services.registry,
        ...(isPlainObject(config.services?.registry) ? config.services.registry : {}),
      },
      tarballs: {
        ...defaults.services.tarballs,
        ...(isPlainObject(config.services?.tarballs) ? config.services.tarballs : {}),
      },
      auditSignatures: {
        ...defaults.services.auditSignatures,
        ...(isPlainObject(config.services?.auditSignatures)
          ? config.services.auditSignatures
          : {}),
      },
    },
    blockRules: {
      ...defaults.blockRules,
      ...(isPlainObject(config.blockRules) ? config.blockRules : {}),
    },
    warnRules: {
      ...defaults.warnRules,
      ...(isPlainObject(config.warnRules) ? config.warnRules : {}),
    },
  };
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
