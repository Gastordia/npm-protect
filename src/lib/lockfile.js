export function parseLockfileContent(lockfilePath, content) {
  if (isPnpmLockfilePath(lockfilePath)) {
    return parsePnpmLockfile(String(content));
  }

  return parseLockfile(JSON.parse(String(content)));
}

export function parseLockfile(lockfile) {
  if (lockfile?.packages && typeof lockfile.packages === "object") {
    const packages = [];

    for (const [packagePath, info] of Object.entries(lockfile.packages)) {
      if (packagePath === "") {
        continue;
      }

      packages.push({
        name: info.name ?? inferNameFromPackagePath(packagePath),
        version: info.version ?? "unknown",
        path: packagePath,
        resolved: info.resolved ?? null,
        integrity: info.integrity ?? null,
        dev: Boolean(info.dev),
        optional: Boolean(info.optional),
        hasInstallScript: Boolean(info.hasInstallScript),
        dependencyCount: Object.keys(info.dependencies ?? {}).length,
      });
    }

    return {
      packageManager: "npm",
      lockfileVersion: lockfile.lockfileVersion ?? null,
      packageCount: packages.length,
      packages,
      directDependencyKeys: [],
    };
  }

  if (lockfile?.dependencies && typeof lockfile.dependencies === "object") {
    const packages = [];
    flattenLegacyDependencies(lockfile.dependencies, "node_modules", packages);

    return {
      packageManager: "npm",
      lockfileVersion: lockfile.lockfileVersion ?? 1,
      packageCount: packages.length,
      packages,
      directDependencyKeys: [],
    };
  }

  return {
    packageManager: "npm",
    lockfileVersion: lockfile?.lockfileVersion ?? null,
    packageCount: 0,
    packages: [],
    directDependencyKeys: [],
  };
}

export function parsePnpmLockfile(content) {
  const lines = String(content)
    .split(/\r?\n/u)
    .map((rawLine) => ({
      raw: rawLine,
      indent: countIndent(rawLine),
      content: rawLine.trim(),
    }))
    .filter((line) => line.content.length > 0 && !line.content.startsWith("#"));

  let rootSection = null;
  let lockfileVersion = null;
  let currentImporter = null;
  let currentImporterSection = null;
  let pendingImporterDependency = null;
  let currentPackage = null;
  let currentPackageSection = null;
  const directDependencyKeys = new Set();
  const packageEntries = [];

  for (const line of lines) {
    if (line.indent === 0) {
      currentImporter = null;
      currentImporterSection = null;
      pendingImporterDependency = null;
      currentPackage = null;
      currentPackageSection = null;

      if (line.content.startsWith("lockfileVersion:")) {
        lockfileVersion = parseScalar(line.content.split(/:(.+)/u, 2)[1]?.trim() ?? null);
        continue;
      }

      if (line.content === "importers:") {
        rootSection = "importers";
        continue;
      }

      if (line.content === "packages:") {
        rootSection = "packages";
        continue;
      }

      rootSection = null;
      continue;
    }

    if (rootSection === "importers") {
      consumePnpmImporterLine(line, {
        setCurrentImporter(value) {
          currentImporter = value;
          currentImporterSection = null;
          pendingImporterDependency = null;
        },
        getCurrentImporter() {
          return currentImporter;
        },
        setCurrentImporterSection(value) {
          currentImporterSection = value;
          pendingImporterDependency = null;
        },
        getCurrentImporterSection() {
          return currentImporterSection;
        },
        setPendingImporterDependency(value) {
          pendingImporterDependency = value;
        },
        getPendingImporterDependency() {
          return pendingImporterDependency;
        },
        directDependencyKeys,
      });
      continue;
    }

    if (rootSection === "packages") {
      const nextPackage = consumePnpmPackageLine(line, currentPackage, currentPackageSection);
      currentPackage = nextPackage.currentPackage;
      currentPackageSection = nextPackage.currentPackageSection;

      if (nextPackage.createdPackage) {
        packageEntries.push(nextPackage.createdPackage);
      }
    }
  }

  const packages = packageEntries.map((entry) => finalizePnpmPackageEntry(entry, directDependencyKeys));

  return {
    packageManager: "pnpm",
    lockfileVersion,
    packageCount: packages.length,
    packages,
    directDependencyKeys: [...directDependencyKeys].sort(),
  };
}

function flattenLegacyDependencies(dependencies, basePath, packages) {
  for (const [name, info] of Object.entries(dependencies)) {
    const packagePath = `${basePath}/${name}`;
    packages.push({
      name,
      version: info.version ?? "unknown",
      path: packagePath,
      resolved: info.resolved ?? null,
      integrity: info.integrity ?? null,
      dev: Boolean(info.dev),
      optional: Boolean(info.optional),
      hasInstallScript: null,
      dependencyCount: Object.keys(info.dependencies ?? {}).length,
    });

    if (info.dependencies) {
      flattenLegacyDependencies(info.dependencies, `${packagePath}/node_modules`, packages);
    }
  }
}

function consumePnpmImporterLine(line, state) {
  if (line.indent === 2 && line.content.endsWith(":")) {
    state.setCurrentImporter(unquoteKey(stripTrailingColon(line.content)));
    return;
  }

  if (state.getCurrentImporter() !== ".") {
    return;
  }

  if (line.indent === 4 && line.content.endsWith(":")) {
    const sectionName = unquoteKey(stripTrailingColon(line.content));
    if (isDependencySection(sectionName)) {
      state.setCurrentImporterSection(sectionName);
      return;
    }

    state.setCurrentImporterSection(null);
    return;
  }

  if (!isDependencySection(state.getCurrentImporterSection())) {
    return;
  }

  if (line.indent === 6) {
    const entry = splitKeyValueLine(line.content);
    if (!entry) {
      state.setPendingImporterDependency(null);
      return;
    }

    if (entry.valueText.length > 0) {
      state.directDependencyKeys.add(
        normalizeDirectDependencyKey(entry.key, normalizePnpmDependencyVersion(entry.valueText, true)),
      );
      state.setPendingImporterDependency(null);
      return;
    }

    state.setPendingImporterDependency({
      name: entry.key,
    });
    return;
  }

  if (line.indent === 8) {
    const pending = state.getPendingImporterDependency();
    if (!pending) {
      return;
    }

    const entry = splitKeyValueLine(line.content);
    if (!entry || entry.key !== "version") {
      return;
    }

    state.directDependencyKeys.add(
      normalizeDirectDependencyKey(pending.name, normalizePnpmDependencyVersion(entry.valueText, true)),
    );
    state.setPendingImporterDependency(null);
  }
}

function consumePnpmPackageLine(line, currentPackage, currentPackageSection) {
  if (line.indent === 2 && line.content.endsWith(":")) {
    const createdPackage = {
      key: unquoteKey(stripTrailingColon(line.content)),
      resolved: null,
      integrity: null,
      dev: false,
      optional: false,
      hasInstallScript: false,
      dependencyCount: 0,
    };

    return {
      createdPackage,
      currentPackage: createdPackage,
      currentPackageSection: null,
    };
  }

  if (!currentPackage) {
    return {
      createdPackage: null,
      currentPackage: null,
      currentPackageSection: null,
    };
  }

  if (line.indent === 4) {
    const entry = splitKeyValueLine(line.content);
    if (!entry) {
      return {
        createdPackage: null,
        currentPackage,
        currentPackageSection: null,
      };
    }

    if (entry.key === "resolution") {
      if (entry.valueText.startsWith("{")) {
        const inlineResolution = parseInlineResolution(entry.valueText);
        currentPackage.integrity = inlineResolution.integrity ?? currentPackage.integrity;
        currentPackage.resolved = inlineResolution.tarball ?? currentPackage.resolved;
        return {
          createdPackage: null,
          currentPackage,
          currentPackageSection: null,
        };
      }

      return {
        createdPackage: null,
        currentPackage,
        currentPackageSection: "resolution",
      };
    }

    if (isDependencySection(entry.key)) {
      return {
        createdPackage: null,
        currentPackage,
        currentPackageSection: entry.key,
      };
    }

    applyPnpmPackageField(currentPackage, entry.key, entry.valueText);
    return {
      createdPackage: null,
      currentPackage,
      currentPackageSection: null,
    };
  }

  if (line.indent === 6 && currentPackageSection === "resolution") {
    const entry = splitKeyValueLine(line.content);
    if (entry) {
      if (entry.key === "integrity") {
        currentPackage.integrity = stripQuotes(entry.valueText);
      }
      if (entry.key === "tarball") {
        currentPackage.resolved = stripQuotes(entry.valueText);
      }
    }

    return {
      createdPackage: null,
      currentPackage,
      currentPackageSection,
    };
  }

  if (line.indent === 6 && isDependencySection(currentPackageSection)) {
    if (splitKeyValueLine(line.content)) {
      currentPackage.dependencyCount += 1;
    }

    return {
      createdPackage: null,
      currentPackage,
      currentPackageSection,
    };
  }

  return {
    createdPackage: null,
    currentPackage,
    currentPackageSection,
  };
}

function finalizePnpmPackageEntry(entry, directDependencyKeys) {
  const parsedKey = parsePnpmPackageKey(entry.key);
  const isDirectDependency = directDependencyKeys.has(parsedKey.directKey);

  return {
    name: parsedKey.name,
    version: parsedKey.version,
    path: isDirectDependency
      ? `node_modules/${parsedKey.name}`
      : `node_modules/.pnpm/${normalizePnpmStoreKey(entry.key)}/node_modules/${parsedKey.name}`,
    resolved: entry.resolved ?? inferDefaultRegistryTarballUrl(parsedKey.name, parsedKey.version),
    integrity: entry.integrity ?? null,
    dev: Boolean(entry.dev),
    optional: Boolean(entry.optional),
    hasInstallScript: Boolean(entry.hasInstallScript),
    dependencyCount: entry.dependencyCount ?? 0,
    rawKey: parsedKey.directKey,
  };
}

function applyPnpmPackageField(currentPackage, key, valueText) {
  const parsedValue = parseScalar(valueText);

  if (key === "dev") {
    currentPackage.dev = Boolean(parsedValue);
  }

  if (key === "optional") {
    currentPackage.optional = Boolean(parsedValue);
  }

  if (key === "requiresBuild") {
    currentPackage.hasInstallScript = Boolean(parsedValue);
  }
}

function parsePnpmPackageKey(rawKey) {
  const normalized = String(rawKey).replace(/^\/+/u, "");
  const withoutPeerSuffix = normalized.replace(/\(.+$/u, "");
  const separatorIndex = withoutPeerSuffix.lastIndexOf("@");

  if (separatorIndex <= 0) {
    return {
      name: normalized,
      version: "unknown",
      directKey: normalized,
    };
  }

  return {
    name: withoutPeerSuffix.slice(0, separatorIndex),
    version: withoutPeerSuffix.slice(separatorIndex + 1) || "unknown",
    directKey: normalized,
  };
}

function normalizeDirectDependencyKey(name, version) {
  return version ? `${name}@${version}` : name;
}

function normalizePnpmDependencyVersion(valueText, preservePeerSuffix = false) {
  const normalized = stripQuotes(valueText);

  if (
    normalized.startsWith("link:") ||
    normalized.startsWith("file:") ||
    normalized.startsWith("workspace:")
  ) {
    return normalized;
  }

  if (preservePeerSuffix) {
    return normalized;
  }

  const peerIndex = normalized.indexOf("(");
  return peerIndex === -1 ? normalized : normalized.slice(0, peerIndex);
}

function parseInlineResolution(valueText) {
  return {
    integrity: matchInlineResolutionValue(valueText, "integrity"),
    tarball: matchInlineResolutionValue(valueText, "tarball"),
  };
}

function matchInlineResolutionValue(valueText, key) {
  const match = String(valueText).match(
    new RegExp(`(?:^|[,{]\\s*)${escapeRegExp(key)}\\s*:\\s*([^,}]+)`, "u"),
  );
  return match ? stripQuotes(match[1].trim()) : null;
}

function inferDefaultRegistryTarballUrl(name, version) {
  if (!isDefaultRegistryCandidate(name, version)) {
    return null;
  }

  if (name.startsWith("@")) {
    const [, packageName] = name.split("/");
    if (!packageName) {
      return null;
    }

    return `https://registry.npmjs.org/${encodeURIComponent(name)}/-/${packageName}-${version}.tgz`;
  }

  return `https://registry.npmjs.org/${encodeURIComponent(name)}/-/${name}-${version}.tgz`;
}

function isDefaultRegistryCandidate(name, version) {
  return (
    typeof name === "string" &&
    name.length > 0 &&
    typeof version === "string" &&
    version.length > 0 &&
    version !== "unknown" &&
    !version.startsWith("file:") &&
    !version.startsWith("link:") &&
    !version.startsWith("workspace:")
  );
}

function normalizePnpmStoreKey(key) {
  return String(key).replace(/^\/+/u, "").replace(/[\\/]/gu, "+");
}

function splitKeyValueLine(content) {
  const separatorIndex = content.indexOf(":");
  if (separatorIndex === -1) {
    return null;
  }

  return {
    key: unquoteKey(content.slice(0, separatorIndex).trim()),
    valueText: content.slice(separatorIndex + 1).trim(),
  };
}

function countIndent(value) {
  const match = String(value).match(/^ */u);
  return match ? match[0].length : 0;
}

function parseScalar(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const normalized = stripQuotes(String(value).trim());
  if (normalized === "true") {
    return true;
  }

  if (normalized === "false") {
    return false;
  }

  if (/^-?\d+(\.\d+)?$/u.test(normalized)) {
    return Number(normalized);
  }

  return normalized;
}

function stripTrailingColon(value) {
  return String(value).replace(/:\s*$/u, "");
}

function unquoteKey(value) {
  return stripQuotes(String(value).trim());
}

function stripQuotes(value) {
  const trimmed = String(value).trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }

  return trimmed;
}

function isDependencySection(name) {
  return [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ].includes(name);
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function inferNameFromPackagePath(packagePath) {
  const parts = packagePath.split("/");
  const markerIndex = parts.lastIndexOf("node_modules");
  if (markerIndex === -1) {
    return packagePath;
  }

  const first = parts[markerIndex + 1];
  const second = parts[markerIndex + 2];

  if (first?.startsWith("@") && second) {
    return `${first}/${second}`;
  }

  return first ?? packagePath;
}

function isPnpmLockfilePath(lockfilePath) {
  return /(?:^|\/)pnpm-lock\.ya?ml$/iu.test(String(lockfilePath));
}
