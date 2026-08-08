import { execFile } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { parseLockfile } from "./lockfile.js";

const execFileAsync = promisify(execFile);

export async function loadProjectSnapshot(projectDir) {
  const resolvedDir = path.resolve(projectDir);
  const manifestPath = path.join(resolvedDir, "package.json");

  if (!(await fileExists(manifestPath))) {
    throw new Error(`package.json not found in ${resolvedDir}`);
  }

  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const lockfilePath = await findLockfilePath(resolvedDir);
  const dependencyNames = collectDependencyNames(manifest);
  const lockfile = lockfilePath
    ? annotateLockfile(
        parseLockfile(JSON.parse(await readFile(lockfilePath, "utf8"))),
        dependencyNames,
      )
    : null;
  const directDependencies = collectDirectDependencies(manifest);

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

  if (resolvedPath.endsWith(".json")) {
    const parsed = JSON.parse(await readFile(resolvedPath, "utf8"));
    return {
      label: resolvedPath,
      packages: parseLockfile(parsed).packages,
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
    throw new Error(`no npm lockfile was found in git ref "${ref}" under ${resolvedRepo}`);
  }

  const content = await readGitFileImpl(resolvedRepo, ref, relativeLockfilePath);
  return {
    label: `${resolvedRepo}@${ref}:${relativeLockfilePath}`,
    packages: parseLockfile(JSON.parse(content)).packages,
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
  for (const name of ["package-lock.json", "npm-shrinkwrap.json"]) {
    const candidate = path.join(projectDir, name);
    if (await fileExists(candidate)) {
      return candidate;
    }
  }

  return null;
}

async function findGitLockfilePath(repoDir, ref, readGitFileImpl) {
  for (const name of ["package-lock.json", "npm-shrinkwrap.json"]) {
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

function annotateLockfile(lockfile, dependencyNames) {
  const dependencySet = new Set(dependencyNames);

  return {
    ...lockfile,
    packages: lockfile.packages.map((pkg) => {
      const isTopLevel = isTopLevelPackagePath(pkg.path);
      return {
        ...pkg,
        isTopLevel,
        isDirectDependency: isTopLevel && dependencySet.has(pkg.name),
      };
    }),
  };
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
