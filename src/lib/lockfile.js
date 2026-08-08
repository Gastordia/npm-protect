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
      lockfileVersion: lockfile.lockfileVersion ?? null,
      packageCount: packages.length,
      packages,
    };
  }

  if (lockfile?.dependencies && typeof lockfile.dependencies === "object") {
    const packages = [];
    flattenLegacyDependencies(lockfile.dependencies, "node_modules", packages);

    return {
      lockfileVersion: lockfile.lockfileVersion ?? 1,
      packageCount: packages.length,
      packages,
    };
  }

  return {
    lockfileVersion: lockfile?.lockfileVersion ?? null,
    packageCount: 0,
    packages: [],
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
