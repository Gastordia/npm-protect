import { execFile } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { parseLockfileContent } from "./lockfile.js";

const execFileAsync = promisify(execFile);

export async function loadProjectSnapshot(projectDir) {
  const resolvedDir = path.resolve(projectDir);
  const manifestPath = path.join(resolvedDir, "package.json");

  if (!(await fileExists(manifestPath))) {
    throw new Error(`package.json not found in ${resolvedDir}`);
  }

  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const lockfilePath = await findLockfilePath(resolvedDir);
  const directDependencies = collectDirectDependencies(manifest);
  const dependencyNames = directDependencies.map((dependency) => dependency.name).sort();
  const lockfile = lockfilePath
    ? annotateLockfile(
        parseLockfileContent(lockfilePath, await readFile(lockfilePath, "utf8")),
        directDependencies,
      )
    : null;

  return {
    dir: resolvedDir,
    manifestPath,
    lockfilePath,
    manifest,
    packageName: manifest.name ?? null,
    packageVersion: manifest.version ?? null,
    repository: normalizeRepository(manifest.repository),
    dependencyNames,
    directDependencies,
    lockfile,
  };
}

export async function loadSnapshotTarget(targetPath) {
  const resolvedPath = path.resolve(targetPath);

  if (isDirectLockfilePath(resolvedPath)) {
    return {
      label: resolvedPath,
      packages: parseLockfileContent(resolvedPath, await readFile(resolvedPath, "utf8")).packages,
    };
  }

  const project = await loadProjectSnapshot(resolvedPath);
  return {
    label: resolvedPath,
    packages: project.lockfile?.packages ?? [],
  };
}

export async function loadGitRefSnapshot(repoDir, ref, lockfilePath = null, options = {}) {
  const resolvedRepo = path.resolve(repoDir);
  const readGitFileImpl = options.readGitFile ?? readGitFile;
  const relativeLockfilePath =
    lockfilePath ?? (await findGitLockfilePath(resolvedRepo, ref, readGitFileImpl));

  if (!relativeLockfilePath) {
    throw new Error(`no supported package manager lockfile was found in git ref "${ref}" under ${resolvedRepo}`);
  }

  const content = await readGitFileImpl(resolvedRepo, ref, relativeLockfilePath);
  return {
    label: `${resolvedRepo}@${ref}:${relativeLockfilePath}`,
    packages: parseLockfileContent(relativeLockfilePath, content).packages,
  };
}

export function diffSnapshots(beforeSnapshot, afterSnapshot) {
  const beforeKeys = packageKeyCounts(beforeSnapshot.packages);
  const afterKeys = packageKeyCounts(afterSnapshot.packages);
  const beforeArtifacts = groupArtifactsByKey(beforeSnapshot.packages);
  const afterArtifacts = groupArtifactsByKey(afterSnapshot.packages);
  const added = [];
  const removed = [];

  for (const [key, count] of afterKeys.entries()) {
    const beforeCount = beforeKeys.get(key) ?? 0;
    if (count > beforeCount) {
      added.push(key);
    }
  }

  for (const [key, count] of beforeKeys.entries()) {
    const afterCount = afterKeys.get(key) ?? 0;
    if (count > afterCount) {
      removed.push(key);
    }
  }

  const changedNames = [];
  const beforeByName = groupByName(beforeSnapshot.packages);
  const afterByName = groupByName(afterSnapshot.packages);

  for (const [name, beforeVersions] of beforeByName.entries()) {
    const afterVersions = afterByName.get(name);
    if (!afterVersions) {
      continue;
    }

    if (!sameSet(beforeVersions, afterVersions)) {
      changedNames.push({
        name,
        before: [...beforeVersions].sort(),
        after: [...afterVersions].sort(),
      });
    }
  }

  const riskyAdds = afterSnapshot.packages
    .filter((pkg) => added.includes(`${pkg.name}@${pkg.version}`))
    .filter((pkg) => pkg.hasInstallScript);

  const changedArtifacts = [];
  for (const [key, beforeArtifact] of beforeArtifacts.entries()) {
    const afterArtifact = afterArtifacts.get(key);
    if (!afterArtifact) {
      continue;
    }

    const resolvedChanged = !sameSet(beforeArtifact.resolved, afterArtifact.resolved);
    const integrityChanged = !sameSet(beforeArtifact.integrity, afterArtifact.integrity);
    if (!resolvedChanged && !integrityChanged) {
      continue;
    }

    changedArtifacts.push({
      name: beforeArtifact.name,
      version: beforeArtifact.version,
      beforeResolved: [...beforeArtifact.resolved].sort(),
      afterResolved: [...afterArtifact.resolved].sort(),
      beforeIntegrity: [...beforeArtifact.integrity].sort(),
      afterIntegrity: [...afterArtifact.integrity].sort(),
      resolvedChanged,
      integrityChanged,
    });
  }

  const hasBlockingArtifactDrift = changedArtifacts.some((change) => change.integrityChanged);
  const hasWarnings =
    added.length > 0 ||
    removed.length > 0 ||
    changedNames.length > 0 ||
    changedArtifacts.length > 0;

  return {
    before: beforeSnapshot.label,
    after: afterSnapshot.label,
    added,
    removed,
    changedNames,
    changedArtifacts,
    riskyAdds,
    verdict:
      riskyAdds.length > 0 || hasBlockingArtifactDrift
        ? "block"
        : hasWarnings
          ? "warn"
          : "allow",
  };
}

export async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return false;
    }

    throw error;
  }
}

async function findLockfilePath(projectDir) {
  for (const name of ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"]) {
    const candidate = path.join(projectDir, name);
    if (await fileExists(candidate)) {
      return candidate;
    }
  }

  return null;
}

async function findGitLockfilePath(repoDir, ref, readGitFileImpl) {
  for (const name of ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"]) {
    try {
      await readGitFileImpl(repoDir, ref, name);
      return name;
    } catch (error) {
      if (isMissingGitPathError(error)) {
        continue;
      }

      throw error;
    }
  }

  return null;
}

async function readGitFile(repoDir, ref, filePath) {
  const gitObject = `${ref}:${toGitPath(filePath)}`;

  try {
    const result = await execFileAsync("git", ["show", gitObject], {
      cwd: repoDir,
      maxBuffer: 10 * 1024 * 1024,
    });
    return result.stdout;
  } catch (error) {
    if (typeof error?.stderr === "string" && /exists on disk, but not in|does not exist in|path .* exists/u.test(error.stderr)) {
      throw new Error(`git path "${filePath}" was not found in ref "${ref}"`);
    }

    throw new Error(
      `unable to read ${filePath} from git ref "${ref}": ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function toGitPath(filePath) {
  return String(filePath).replace(/\\/gu, "/").replace(/^\.\/+/u, "");
}

function isMissingGitPathError(error) {
  return error instanceof Error && /was not found in ref/u.test(error.message);
}

function collectDependencyNames(manifest) {
  return collectDirectDependencies(manifest).map((dependency) => dependency.name).sort();
}

function collectDirectDependencies(manifest) {
  const fields = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
  const byName = new Map();

  for (const field of fields) {
    for (const [name, spec] of Object.entries(manifest[field] ?? {})) {
      if (!byName.has(name)) {
        byName.set(name, {
          name,
          spec,
          field,
          isScoped: name.startsWith("@"),
          isRegistryDependency: isRegistryDependencySpec(spec),
        });
      }
    }
  }

  return [...byName.values()].sort((left, right) => left.name.localeCompare(right.name));
}

function normalizeRepository(repository) {
  if (!repository) {
    return null;
  }

  if (typeof repository === "string") {
    return repository;
  }

  if (typeof repository === "object" && repository.url) {
    return repository.url;
  }

  return null;
}

function packageKeyCounts(packages) {
  const counts = new Map();

  for (const pkg of packages) {
    const key = `${pkg.name}@${pkg.version}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  return counts;
}

function groupByName(packages) {
  const map = new Map();

  for (const pkg of packages) {
    if (!map.has(pkg.name)) {
      map.set(pkg.name, new Set());
    }
    map.get(pkg.name).add(pkg.version);
  }

  return map;
}

function groupArtifactsByKey(packages) {
  const map = new Map();

  for (const pkg of packages) {
    const key = `${pkg.name}@${pkg.version}`;
    if (!map.has(key)) {
      map.set(key, {
        name: pkg.name,
        version: pkg.version,
        resolved: new Set(),
        integrity: new Set(),
      });
    }

    const artifact = map.get(key);
    artifact.resolved.add(pkg.resolved ?? "(none)");
    artifact.integrity.add(pkg.integrity ?? "(none)");
  }

  return map;
}

function sameSet(left, right) {
  if (left.size !== right.size) {
    return false;
  }

  for (const value of left) {
    if (!right.has(value)) {
      return false;
    }
  }

  return true;
}

function annotateLockfile(lockfile, directDependencies) {
  const dependencySet = new Set((directDependencies ?? []).map((dependency) => dependency.name));
  const directDependencyKeys = new Set(lockfile.directDependencyKeys ?? []);

  return {
    ...lockfile,
    packages: lockfile.packages.map((pkg) => {
      const isTopLevel = isTopLevelPackagePath(pkg.path);
      const isDirectDependency =
        directDependencyKeys.size > 0
          ? matchesDirectDependencyKey(pkg, directDependencyKeys)
          : lockfile.packageManager === "yarn"
            ? matchesYarnDirectDependency(pkg, directDependencies)
            : isTopLevel && dependencySet.has(pkg.name);

      return {
        ...pkg,
        path:
          lockfile.packageManager === "yarn" && isDirectDependency
            ? directDependencyPathForPackage(pkg.name)
            : pkg.path,
        isTopLevel: lockfile.packageManager === "yarn" ? isDirectDependency : isTopLevel,
        isDirectDependency,
      };
    }),
  };
}

function matchesDirectDependencyKey(pkg, directDependencyKeys) {
  const rawKeys = normalizePackageRawKeys(pkg);
  if (rawKeys.length === 0) {
    return directDependencyKeys.has(`${pkg.name}@${pkg.version}`);
  }

  return rawKeys.some((key) => directDependencyKeys.has(key));
}

function matchesYarnDirectDependency(pkg, directDependencies = []) {
  const rawKeys = normalizePackageRawKeys(pkg);
  if (rawKeys.length === 0) {
    return directDependencies.some((dependency) => dependency.name === pkg.name);
  }

  const descriptors = rawKeys.map(parseYarnDescriptor);
  return descriptors.some((descriptor) =>
    directDependencies.some((dependency) => yarnDescriptorMatchesDependency(descriptor, dependency)),
  );
}

function isTopLevelPackagePath(packagePath) {
  const parts = packagePath.split("/");
  if (parts.length < 2 || parts[0] !== "node_modules") {
    return false;
  }

  if (parts[1]?.startsWith("@")) {
    return parts.length === 3;
  }

  return parts.length === 2;
}

function isRegistryDependencySpec(spec) {
  if (typeof spec !== "string" || spec.length === 0) {
    return true;
  }

  const nonRegistryPrefixes = [
    "file:",
    "git:",
    "git+",
    "github:",
    "http:",
    "https:",
    "link:",
    "workspace:",
  ];

  return !nonRegistryPrefixes.some((prefix) => spec.startsWith(prefix));
}

function isDirectLockfilePath(targetPath) {
  return (
    (/\.(?:json|ya?ml)$/iu.test(targetPath) &&
      /(?:package-lock|npm-shrinkwrap|pnpm-lock)\./iu.test(targetPath)) ||
    /(?:^|\/)yarn\.lock$/iu.test(targetPath)
  );
}

function normalizePackageRawKeys(pkg) {
  if (Array.isArray(pkg.rawKeys)) {
    return pkg.rawKeys.map((value) => String(value));
  }

  if (typeof pkg.rawKey === "string" && pkg.rawKey.length > 0) {
    return [pkg.rawKey];
  }

  return [];
}

function parseYarnDescriptor(rawDescriptor) {
  const descriptor = String(rawDescriptor).trim().replace(/^['"]|['"]$/gu, "");
  if (descriptor.length === 0) {
    return {
      name: null,
      reference: null,
    };
  }

  if (descriptor.startsWith("@")) {
    const slashIndex = descriptor.indexOf("/");
    if (slashIndex === -1) {
      return {
        name: descriptor,
        reference: null,
      };
    }

    const separatorIndex = descriptor.indexOf("@", slashIndex + 1);
    if (separatorIndex === -1) {
      return {
        name: descriptor,
        reference: null,
      };
    }

    return {
      name: descriptor.slice(0, separatorIndex),
      reference: descriptor.slice(separatorIndex + 1) || null,
    };
  }

  const separatorIndex = descriptor.indexOf("@");
  if (separatorIndex === -1) {
    return {
      name: descriptor,
      reference: null,
    };
  }

  return {
    name: descriptor.slice(0, separatorIndex),
    reference: descriptor.slice(separatorIndex + 1) || null,
  };
}

function yarnDescriptorMatchesDependency(descriptor, dependency) {
  if (!descriptor.name || descriptor.name !== dependency?.name) {
    return false;
  }

  const spec = typeof dependency.spec === "string" ? dependency.spec : "";
  if (spec.length === 0 || !descriptor.reference) {
    return true;
  }

  if (descriptor.reference === spec || descriptor.reference === `npm:${spec}`) {
    return true;
  }

  if (spec.startsWith("npm:") && descriptor.reference === spec.slice(4)) {
    return true;
  }

  return false;
}

function directDependencyPathForPackage(name) {
  return `node_modules/${name}`;
}
