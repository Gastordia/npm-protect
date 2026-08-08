export function buildCycloneDxSbom(project) {
  const components = dedupeComponents(project.lockfile?.packages ?? []);
  const rootRef = buildRootRef(project.packageName, project.packageVersion);

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      component: {
        type: "application",
        "bom-ref": rootRef,
        name: project.packageName ?? "unnamed-project",
        version: project.packageVersion ?? "0.0.0",
        purl:
          project.packageName && project.packageVersion
            ? packageToPurl(project.packageName, project.packageVersion)
            : undefined,
        externalReferences: project.repository
          ? [
              {
                type: "vcs",
                url: project.repository,
              },
            ]
          : undefined,
      },
      properties: [
        {
          name: "npm-protect:projectDir",
          value: project.dir,
        },
        {
          name: "npm-protect:manifestPath",
          value: project.manifestPath,
        },
        ...(project.lockfilePath
          ? [
              {
                name: "npm-protect:lockfilePath",
                value: project.lockfilePath,
              },
            ]
          : []),
      ],
      tools: [
        {
          vendor: "npm-protect",
          name: "npm-protect",
        },
      ],
    },
    components,
    dependencies: [
      {
        ref: rootRef,
        dependsOn: components
          .filter((component) => component.properties.some(
            (property) => property.name === "npm-protect:isDirectDependency" && property.value === "true",
          ))
          .map((component) => component["bom-ref"]),
      },
    ],
  };
}

function dedupeComponents(packages) {
  const byRef = new Map();

  for (const pkg of packages) {
    const ref = packageToPurl(pkg.name, pkg.version);
    if (!byRef.has(ref)) {
      byRef.set(ref, {
        type: "library",
        "bom-ref": ref,
        name: pkg.name,
        version: pkg.version,
        purl: ref,
        scope: pkg.dev ? "excluded" : "required",
        hashes: pkg.integrity ? [{ alg: "SHA-512", content: stripIntegrityPrefix(pkg.integrity) }] : undefined,
        externalReferences: pkg.resolved
          ? [
              {
                type: "distribution",
                url: pkg.resolved,
              },
            ]
          : undefined,
        properties: [
          {
            name: "npm-protect:isDirectDependency",
            value: String(Boolean(pkg.isDirectDependency)),
          },
          {
            name: "npm-protect:isTopLevel",
            value: String(Boolean(pkg.isTopLevel)),
          },
          {
            name: "npm-protect:installScript",
            value: String(Boolean(pkg.hasInstallScript)),
          },
          {
            name: "npm-protect:optional",
            value: String(Boolean(pkg.optional)),
          },
        ],
      });
      continue;
    }

    const existing = byRef.get(ref);
    if (pkg.isDirectDependency) {
      updateProperty(existing.properties, "npm-protect:isDirectDependency", "true");
    }
    if (pkg.isTopLevel) {
      updateProperty(existing.properties, "npm-protect:isTopLevel", "true");
    }
    if (pkg.hasInstallScript) {
      updateProperty(existing.properties, "npm-protect:installScript", "true");
    }
    if (pkg.optional) {
      updateProperty(existing.properties, "npm-protect:optional", "true");
    }
  }

  return [...byRef.values()].sort((left, right) => left.name.localeCompare(right.name));
}

function updateProperty(properties, name, value) {
  const property = properties.find((entry) => entry.name === name);
  if (property) {
    property.value = value;
  }
}

function buildRootRef(name, version) {
  if (name && version) {
    return packageToPurl(name, version);
  }

  return "pkg:generic/npm-protect-root@0.0.0";
}

function stripIntegrityPrefix(integrity) {
  return String(integrity).replace(/^sha\d+-/iu, "");
}

function packageToPurl(name, version) {
  if (name.startsWith("@")) {
    const [scope, packageName] = name.slice(1).split("/", 2);
    return `pkg:npm/%40${encodeURIComponent(scope)}/${encodeURIComponent(packageName)}@${encodeURIComponent(version)}`;
  }

  return `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}
