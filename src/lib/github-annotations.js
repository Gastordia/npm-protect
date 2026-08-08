export function supportsGitHubAnnotations(command) {
  return ["review", "verify", "diff", "publish-check"].includes(command);
}

export function buildGitHubAnnotations(command, report) {
  if (command === "diff") {
    return buildDiffAnnotations(report);
  }

  if (Array.isArray(report?.findings)) {
    return report.findings.map((finding) => {
      const location = resolveFindingLocation(command, report, finding);
      return renderWorkflowCommand(
        toWorkflowLevel(finding.severity),
        finding.message,
        {
          title: `npm-protect ${command}: ${finding.code}`,
          ...(location ? { file: location } : {}),
        },
      );
    });
  }

  return [];
}

function buildDiffAnnotations(report) {
  const lines = [];

  for (const pkg of report.riskyAdds ?? []) {
    lines.push(
      renderWorkflowCommand(
        "error",
        `${pkg.name}@${pkg.version} was added and has install-time scripts`,
        {
          title: "npm-protect diff: risky_added_package",
        },
      ),
    );
  }

  for (const change of report.changedNames ?? []) {
    lines.push(
      renderWorkflowCommand(
        "warning",
        `${change.name} changed from ${change.before.join(", ")} to ${change.after.join(", ")}`,
        {
          title: "npm-protect diff: dependency_version_changed",
        },
      ),
    );
  }

  for (const change of report.changedArtifacts ?? []) {
    if (change.resolvedChanged) {
      lines.push(
        renderWorkflowCommand(
          "warning",
          `${change.name}@${change.version} resolved source changed from ${change.beforeResolved.join(", ")} to ${change.afterResolved.join(", ")}`,
          {
            title: "npm-protect diff: dependency_source_changed",
          },
        ),
      );
    }

    if (change.integrityChanged) {
      lines.push(
        renderWorkflowCommand(
          "error",
          `${change.name}@${change.version} integrity changed from ${change.beforeIntegrity.join(", ")} to ${change.afterIntegrity.join(", ")}`,
          {
            title: "npm-protect diff: dependency_integrity_changed",
          },
        ),
      );
    }
  }

  return lines;
}

function resolveFindingLocation(command, report, finding) {
  if (finding.details?.workflowPath) {
    return finding.details.workflowPath;
  }

  if (command === "publish-check") {
    return null;
  }

  if (
    finding.code === "missing_repository" ||
    finding.code === "non_registry_direct_dependency"
  ) {
    return report?.project?.manifestPath ?? null;
  }

  if (report?.project?.lockfilePath) {
    return report.project.lockfilePath;
  }

  return report?.project?.manifestPath ?? null;
}

function toWorkflowLevel(severity) {
  if (severity === "error") {
    return "error";
  }
  if (severity === "warn") {
    return "warning";
  }

  return "notice";
}

function renderWorkflowCommand(level, message, properties = {}) {
  const serializedProperties = Object.entries(properties)
    .filter(([, value]) => value !== null && value !== undefined && String(value).length > 0)
    .map(([key, value]) => `${key}=${escapeProperty(String(value))}`)
    .join(",");

  return `::${level}${serializedProperties ? ` ${serializedProperties}` : ""}::${escapeMessage(message)}`;
}

function escapeMessage(value) {
  return String(value)
    .replaceAll("%", "%25")
    .replaceAll("\r", "%0D")
    .replaceAll("\n", "%0A");
}

function escapeProperty(value) {
  return escapeMessage(value)
    .replaceAll(":", "%3A")
    .replaceAll(",", "%2C");
}
