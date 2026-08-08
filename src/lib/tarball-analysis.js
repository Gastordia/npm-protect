import { gunzipSync } from "node:zlib";

const LIFECYCLE_SCRIPTS = ["preinstall", "install", "postinstall", "prepare"];

const COMMAND_PATTERNS = [
  {
    category: "network_downloader",
    description: "downloads a remote payload in a lifecycle script",
    regex: /\b(?:curl|wget)\b|Invoke-WebRequest|certutil\b/iu,
  },
  {
    category: "shell_eval",
    description: "executes inline shell code in a lifecycle script",
    regex: /\b(?:bash|sh)\s+-c\b/iu,
  },
  {
    category: "node_eval",
    description: "executes inline Node.js code in a lifecycle script",
    regex: /\bnode(?:js)?\s+-e\b/iu,
  },
  {
    category: "powershell",
    description: "executes PowerShell in a lifecycle script",
    regex: /\bpowershell(?:\.exe)?\b/iu,
  },
];

const NETWORK_PATTERN = /\bhttps?\.(?:request|get)\b|\bfetch\s*\(|\bXMLHttpRequest\b|\bnet\.connect\b/iu;
const ENV_PATTERN = /\bprocess\.env\b|\bos\.homedir\b|\bos\.userInfo\b|\.npmrc|id_rsa|known_hosts/iu;
const EXEC_PATTERN = /\bchild_process\b|\bexecSync\b|\bspawnSync\b|\bspawn\b|\bexec\b/iu;
const URL_PATTERN = /https?:\/\//iu;
const SHELL_DOWNLOAD_PATTERN = /\b(?:curl|wget)\b|Invoke-WebRequest|certutil\b/iu;

export function inspectPackageTarball(tarballBuffer, pkg, config, settings = {}) {
  const severity = config.blockRules.suspiciousTarballIndicators ? "error" : "warn";
  const findings = [];
  const entries = extractTextEntries(tarballBuffer, settings.maxFileBytes ?? 65536);
  const manifestText = entries.get("package.json");

  if (!manifestText) {
    return { findings, stats: { inspectedFiles: 0 }, metadata: { lifecycleScripts: [] } };
  }

  let manifest;
  try {
    manifest = JSON.parse(manifestText);
  } catch (error) {
    findings.push({
      severity,
      code: "tarball_manifest_parse_error",
      message: `${pkg.name}@${pkg.version} has an unreadable package.json inside its published tarball`,
      packageName: pkg.name,
      packageVersion: pkg.version,
      packagePath: pkg.packagePath,
      details: {
        reason: error instanceof Error ? error.message : String(error),
      },
    });
    return { findings, stats: { inspectedFiles: 0 }, metadata: { lifecycleScripts: [] } };
  }

  const lifecycleScripts = collectLifecycleScripts(manifest.scripts);
  const inspectedFiles = new Set();
  const maxFilesPerPackage = Number(settings.maxFilesPerPackage ?? 6);

  for (const { name: scriptName, command } of lifecycleScripts) {
    for (const pattern of COMMAND_PATTERNS) {
      if (!pattern.regex.test(command)) {
        continue;
      }

      findings.push({
        severity,
        code: "suspicious_lifecycle_script_command",
        message: `${pkg.name}@${pkg.version} ${pattern.description}`,
        packageName: pkg.name,
        packageVersion: pkg.version,
        packagePath: pkg.packagePath,
        details: {
          scriptName,
          indicator: pattern.category,
          command,
        },
      });
    }

    for (const filePath of extractScriptFileReferences(command)) {
      if (inspectedFiles.size >= maxFilesPerPackage || inspectedFiles.has(filePath)) {
        continue;
      }

      inspectedFiles.add(filePath);
      const content = entries.get(normalizeScriptPath(filePath));
      if (!content) {
        continue;
      }

      const indicators = detectFileIndicators(content);
      for (const indicator of indicators) {
        findings.push({
          severity,
          code: "suspicious_lifecycle_script_file",
          message: `${pkg.name}@${pkg.version} ${indicator.description}`,
          packageName: pkg.name,
          packageVersion: pkg.version,
          packagePath: pkg.packagePath,
          details: {
            scriptName,
            filePath,
            indicator: indicator.category,
          },
        });
      }
    }
  }

  return {
    findings,
    stats: {
      inspectedFiles: inspectedFiles.size,
    },
    metadata: {
      lifecycleScripts: lifecycleScripts.map((script) => script.name),
    },
  };
}

function collectLifecycleScripts(scripts) {
  const lifecycleScripts = [];

  for (const scriptName of LIFECYCLE_SCRIPTS) {
    const command = scripts?.[scriptName];
    if (typeof command !== "string" || command.trim().length === 0) {
      continue;
    }

    lifecycleScripts.push({
      name: scriptName,
      command,
    });
  }

  return lifecycleScripts;
}

function extractTextEntries(tarballBuffer, maxFileBytes) {
  const decompressed = gunzipSync(Buffer.from(tarballBuffer));
  const entries = new Map();
  let offset = 0;

  while (offset + 512 <= decompressed.length) {
    const header = decompressed.subarray(offset, offset + 512);
    if (isZeroBlock(header)) {
      break;
    }

    const name = readString(header, 0, 100);
    const prefix = readString(header, 345, 155);
    const typeFlag = header[156];
    const size = parseTarSize(readString(header, 124, 12));
    const fullName = normalizeEntryName(prefix ? `${prefix}/${name}` : name);
    const contentStart = offset + 512;
    const contentEnd = contentStart + size;

    if (isTextEntry(fullName, typeFlag)) {
      entries.set(
        fullName,
        decompressed
          .subarray(contentStart, Math.min(contentEnd, contentStart + maxFileBytes))
          .toString("utf8"),
      );
    }

    offset = contentStart + Math.ceil(size / 512) * 512;
  }

  return entries;
}

function extractScriptFileReferences(command) {
  const references = new Set();
  const regex =
    /\b(?:node(?:js)?|bash|sh|zsh)\b(?:\s+--[^\s]+)*\s+(['"]?)([^'"\s|;&]+?\.(?:[cm]?js|sh))\1/giu;

  for (const match of command.matchAll(regex)) {
    references.add(match[2]);
  }

  return [...references];
}

function detectFileIndicators(content) {
  const indicators = [];

  if (ENV_PATTERN.test(content) && NETWORK_PATTERN.test(content)) {
    indicators.push({
      category: "env_network",
      description: "reads local environment data and uses network APIs during install",
    });
  }

  if (EXEC_PATTERN.test(content) && NETWORK_PATTERN.test(content)) {
    indicators.push({
      category: "exec_network",
      description: "spawns child processes and uses network APIs during install",
    });
  }

  if (SHELL_DOWNLOAD_PATTERN.test(content) && (EXEC_PATTERN.test(content) || URL_PATTERN.test(content))) {
    indicators.push({
      category: "download_exec",
      description: "contains downloader-like logic in an install lifecycle file",
    });
  }

  return dedupeIndicators(indicators);
}

function dedupeIndicators(indicators) {
  const seen = new Set();
  const deduped = [];

  for (const indicator of indicators) {
    if (seen.has(indicator.category)) {
      continue;
    }

    seen.add(indicator.category);
    deduped.push(indicator);
  }

  return deduped;
}

function isTextEntry(name, typeFlag) {
  if (!(typeFlag === 0 || typeFlag === 48)) {
    return false;
  }

  return (
    name === "package.json" ||
    /\.(?:json|[cm]?js|sh)$/iu.test(name)
  );
}

function normalizeEntryName(name) {
  return String(name).replace(/^package\//u, "");
}

function normalizeScriptPath(filePath) {
  return String(filePath).replace(/^\.\/+/u, "");
}

function parseTarSize(rawSize) {
  const normalized = rawSize.replace(/\0.*$/u, "").trim();
  return normalized ? Number.parseInt(normalized, 8) : 0;
}

function readString(buffer, start, length) {
  return buffer
    .subarray(start, start + length)
    .toString("utf8")
    .replace(/\0.*$/u, "")
    .trim();
}

function isZeroBlock(buffer) {
  for (const byte of buffer) {
    if (byte !== 0) {
      return false;
    }
  }

  return true;
}
