import { pathToFileURL } from "node:url";

export function serializeReviewReport(report, format) {
  if (format === "json") {
    return JSON.stringify(report, null, 2);
  }

  if (format === "sarif") {
    return JSON.stringify(reviewReportToSarif(report), null, 2);
  }

  if (format === "markdown") {
    return formatReviewMarkdown(report);
  }

  return formatReviewText(report);
}

export function serializeDiffReport(report, format) {
  if (format === "json") {
    return JSON.stringify(report, null, 2);
  }

  if (format === "sarif") {
    return JSON.stringify(diffReportToSarif(report), null, 2);
  }

  if (format === "markdown") {
    return formatDiffMarkdown(report);
  }

  return formatDiffText(report);
}

export function serializePublishCheckReport(report, format) {
  if (format === "json") {
    return JSON.stringify(report, null, 2);
  }

  if (format === "sarif") {
    return JSON.stringify(publishCheckReportToSarif(report), null, 2);
  }

  if (format === "markdown") {
    return formatPublishCheckMarkdown(report);
  }

  return formatPublishCheckText(report);
}

export function serializeInstallPlan(plan, format) {
  if (format === "json") {
    return JSON.stringify(plan, null, 2);
  }

  if (format === "markdown") {
    return formatInstallMarkdown(plan);
  }

  return formatInstallText(plan);
}

function formatReviewText(report) {
  const lines = [
    `Project: ${report.project.name ?? "(unnamed project)"}${report.project.version ? `@${report.project.version}` : ""}`,
    `Directory: ${report.project.dir}`,
    `Verdict: ${report.verdict}`,
    `Risk: ${report.riskVerdict}`,
    "",
    `Packages: ${report.stats.totalPackages}`,
    `Direct dependencies: ${report.stats.directDependencyCount}`,
    `Packages with install scripts: ${report.stats.packagesWithInstallScripts}`,
    `Recovered lifecycle-script packages: ${report.stats.recoveredLifecycleScriptPackages}`,
    `Packages missing integrity: ${report.stats.packagesMissingIntegrity}`,
    `Direct non-registry dependencies: ${report.stats.directNonRegistryDependencyCount}`,
    `Known vulnerabilities: ${report.stats.vulnerabilities}`,
    `Direct packages checked against registry: ${report.stats.directPackagesCheckedAgainstRegistry}`,
    `Verified attestations: ${report.stats.verifiedAttestations}`,
    `Fresh packages: ${report.stats.freshPackages}`,
    `Trusted-scope collisions: ${report.stats.trustedScopeCollisions}`,
    `Tarballs inspected: ${report.stats.tarballsInspected}`,
    `Suspicious tarball packages: ${report.stats.suspiciousTarballPackages}`,
  ];

  if (report.sources.length > 0) {
    lines.push("", "Sources:");
    for (const source of report.sources) {
      const detailParts = [];
      if (source.checkedPackages !== undefined) {
        detailParts.push(`checked=${source.checkedPackages}`);
      }
      if (source.vulnerabilities !== undefined) {
        detailParts.push(`vulns=${source.vulnerabilities}`);
      }
      if (source.verifiedAttestations !== undefined) {
        detailParts.push(`verifiedAttestations=${source.verifiedAttestations}`);
      }
      if (source.freshPackages !== undefined) {
        detailParts.push(`freshPackages=${source.freshPackages}`);
      }
      if (source.trustedScopeCollisions !== undefined) {
        detailParts.push(`trustedScopeCollisions=${source.trustedScopeCollisions}`);
      }
      if (source.inspectedPackages !== undefined) {
        detailParts.push(`inspected=${source.inspectedPackages}`);
      }
      if (source.recoveredLifecycleScriptPackages !== undefined) {
        detailParts.push(`recovered=${source.recoveredLifecycleScriptPackages}`);
      }
      if (source.suspiciousPackages !== undefined) {
        detailParts.push(`suspicious=${source.suspiciousPackages}`);
      }
      if (source.failedPackages !== undefined) {
        detailParts.push(`failed=${source.failedPackages}`);
      }
      if (source.cacheHits !== undefined) {
        detailParts.push(`cacheHits=${source.cacheHits}`);
      }
      if (source.cacheWrites !== undefined) {
        detailParts.push(`cacheWrites=${source.cacheWrites}`);
      }
      if (source.invalidEntries !== undefined) {
        detailParts.push(`invalid=${source.invalidEntries}`);
      }
      if (source.missingEntries !== undefined) {
        detailParts.push(`missing=${source.missingEntries}`);
      }
      if (source.message) {
        detailParts.push(source.message);
      }
      lines.push(
        `- ${source.name}: ${source.status}${detailParts.length > 0 ? ` (${detailParts.join(", ")})` : ""}`,
      );
    }
  }

  if (report.findings.length === 0) {
    lines.push("", "No findings.");
    return lines.join("\n");
  }

  lines.push("", "Findings:");
  for (const finding of report.findings) {
    const prefix = finding.severity.toUpperCase().padEnd(5, " ");
    lines.push(`- ${prefix} ${finding.code}: ${finding.message}`);
    const context = formatFindingContext(finding);
    if (context) {
      lines.push(`        ${context}`);
    }
  }

  return lines.join("\n");
}

function formatDiffText(report) {
  const lines = [
    `Before: ${report.before}`,
    `After:  ${report.after}`,
    `Verdict: ${report.verdict}`,
    "",
    `Added package versions: ${report.added.length}`,
    `Removed package versions: ${report.removed.length}`,
    `Changed package names: ${report.changedNames.length}`,
    `Changed package artifacts: ${report.changedArtifacts.length}`,
  ];

  if (report.riskyAdds.length > 0) {
    lines.push("", "Risky added packages:");
    for (const pkg of report.riskyAdds) {
      lines.push(`- ${pkg.name}@${pkg.version} has install-time scripts`);
    }
  }

  if (report.changedNames.length > 0) {
    lines.push("", "Changed package names:");
    for (const change of report.changedNames) {
      lines.push(`- ${change.name}: ${change.before.join(", ")} -> ${change.after.join(", ")}`);
    }
  }

  if (report.changedArtifacts.length > 0) {
    lines.push("", "Changed package artifacts:");
    for (const change of report.changedArtifacts) {
      const parts = [];
      if (change.resolvedChanged) {
        parts.push(`resolved ${change.beforeResolved.join(", ")} -> ${change.afterResolved.join(", ")}`);
      }
      if (change.integrityChanged) {
        parts.push(`integrity ${change.beforeIntegrity.join(", ")} -> ${change.afterIntegrity.join(", ")}`);
      }
      lines.push(`- ${change.name}@${change.version}: ${parts.join("; ")}`);
    }
  }

  return lines.join("\n");
}

function formatPublishCheckText(report) {
  const lines = [
    `Project: ${report.project}`,
    `Workflow files: ${report.workflowCount}`,
    `Publish workflows: ${report.publishWorkflowCount}`,
    `SBOM files: ${report.sbomFileCount}`,
    `Project .npmrc: ${report.npmrcPresent ? "present" : "not found"}`,
    `Verdict: ${report.verdict}`,
  ];

  if (report.findings.length === 0) {
    lines.push("", "No findings.");
    return lines.join("\n");
  }

  lines.push("", "Findings:");
  for (const finding of report.findings) {
    lines.push(`- ${finding.severity.toUpperCase()} ${finding.code}: ${finding.message}`);
  }

  return lines.join("\n");
}

function formatInstallText(plan) {
  const lines = [
    `Project: ${plan.project.name ?? "(unnamed project)"}${plan.project.version ? `@${plan.project.version}` : ""}`,
    `Package manager: ${plan.packageManager}`,
    `Safe install mode: ${plan.mode}`,
    "",
  ];

  if (plan.stats.packagesWithInstallScripts === 0) {
    lines.push("Recommended command:");
    lines.push(`  ${plan.recommendedSteps[0]}`);
    return lines.join("\n");
  }

  lines.push("Recommended two-step install plan:");
  lines.push(`  1. ${plan.recommendedSteps[0]}`);
  lines.push(`  2. ${plan.recommendedSteps[1]}`);
  lines.push("");
  lines.push(`Packages with install scripts: ${plan.stats.packagesWithInstallScripts}`);
  lines.push(`Recovered via tarball inspection: ${plan.stats.recoveredLifecycleScriptPackages}`);
  lines.push(`Approved by policy: ${plan.stats.approvedPackages}`);
  lines.push(`Not yet approved: ${plan.stats.unapprovedPackages}`);

  if (plan.approved.length > 0) {
    lines.push("", "Approved install-script packages:");
    for (const pkg of plan.approved) {
      lines.push(`- ${formatInstallPackageLabel(pkg)}`);
      if (pkg.approvalCommand) {
        lines.push(`  approval: ${pkg.approvalCommand}`);
      }
    }
  }

  if (plan.unapproved.length > 0) {
    lines.push("", "Unapproved install-script packages:");
    for (const pkg of plan.unapproved) {
      lines.push(`- ${formatInstallPackageLabel(pkg)}`);
      if (pkg.approvalCommand) {
        lines.push(`  approval: ${pkg.approvalCommand}`);
      }
    }
  }

  return lines.join("\n");
}

function formatInstallMarkdown(plan) {
  const lines = [
    "# npm-protect install",
    "",
    `- Project: \`${plan.project.name ?? "(unnamed project)"}${plan.project.version ? `@${plan.project.version}` : ""}\``,
    `- Package manager: \`${plan.packageManager}\``,
    `- Mode: \`${plan.mode}\``,
    `- Packages with install scripts: \`${plan.stats.packagesWithInstallScripts}\``,
    `- Recovered via tarball inspection: \`${plan.stats.recoveredLifecycleScriptPackages}\``,
    `- Approved packages: \`${plan.stats.approvedPackages}\``,
    `- Unapproved packages: \`${plan.stats.unapprovedPackages}\``,
    "",
    "## Recommended Steps",
    "",
  ];

  for (const step of plan.recommendedSteps) {
    lines.push(`- ${step}`);
  }

  if (plan.approved.length > 0) {
    lines.push("", "## Approved Packages", "");
    lines.push(...renderInstallPackageTable(plan.approved));
  }

  if (plan.unapproved.length > 0) {
    lines.push("", "## Unapproved Packages", "");
    lines.push(...renderInstallPackageTable(plan.unapproved));
  }

  return lines.join("\n");
}

function formatReviewMarkdown(report) {
  const lines = [
    "# npm-protect review",
    "",
    `- Verdict: \`${report.verdict}\``,
    `- Risk: \`${report.riskVerdict}\``,
    `- Project: \`${report.project.name ?? "(unnamed project)"}${report.project.version ? `@${report.project.version}` : ""}\``,
    `- Directory: \`${report.project.dir}\``,
    `- Packages: \`${report.stats.totalPackages}\``,
    `- Direct dependencies: \`${report.stats.directDependencyCount}\``,
    `- Install-script packages: \`${report.stats.packagesWithInstallScripts}\``,
    `- Recovered lifecycle-script packages: \`${report.stats.recoveredLifecycleScriptPackages}\``,
    `- Missing integrity entries: \`${report.stats.packagesMissingIntegrity}\``,
    `- Non-registry direct dependencies: \`${report.stats.directNonRegistryDependencyCount}\``,
    `- Known vulnerabilities: \`${report.stats.vulnerabilities}\``,
    `- Registry checks: \`${report.stats.directPackagesCheckedAgainstRegistry}\``,
    `- Verified attestations: \`${report.stats.verifiedAttestations}\``,
    `- Fresh packages: \`${report.stats.freshPackages}\``,
    `- Trusted-scope collisions: \`${report.stats.trustedScopeCollisions}\``,
    `- Tarballs inspected: \`${report.stats.tarballsInspected}\``,
    `- Suspicious tarball packages: \`${report.stats.suspiciousTarballPackages}\``,
  ];

  if (report.sources.length > 0) {
    lines.push("", "## Sources", "", "| Source | Status | Details |", "| --- | --- | --- |");
    for (const source of report.sources) {
      const details = [];
      if (source.checkedPackages !== undefined) {
        details.push(`checked=${source.checkedPackages}`);
      }
      if (source.vulnerabilities !== undefined) {
        details.push(`vulns=${source.vulnerabilities}`);
      }
      if (source.verifiedAttestations !== undefined) {
        details.push(`verifiedAttestations=${source.verifiedAttestations}`);
      }
      if (source.freshPackages !== undefined) {
        details.push(`freshPackages=${source.freshPackages}`);
      }
      if (source.trustedScopeCollisions !== undefined) {
        details.push(`trustedScopeCollisions=${source.trustedScopeCollisions}`);
      }
      if (source.inspectedPackages !== undefined) {
        details.push(`inspected=${source.inspectedPackages}`);
      }
      if (source.recoveredLifecycleScriptPackages !== undefined) {
        details.push(`recovered=${source.recoveredLifecycleScriptPackages}`);
      }
      if (source.suspiciousPackages !== undefined) {
        details.push(`suspicious=${source.suspiciousPackages}`);
      }
      if (source.failedPackages !== undefined) {
        details.push(`failed=${source.failedPackages}`);
      }
      if (source.cacheHits !== undefined) {
        details.push(`cacheHits=${source.cacheHits}`);
      }
      if (source.cacheWrites !== undefined) {
        details.push(`cacheWrites=${source.cacheWrites}`);
      }
      if (source.invalidEntries !== undefined) {
        details.push(`invalid=${source.invalidEntries}`);
      }
      if (source.missingEntries !== undefined) {
        details.push(`missing=${source.missingEntries}`);
      }
      if (source.message) {
        details.push(source.message);
      }
      lines.push(
        `| ${escapeMarkdownCell(source.name)} | ${escapeMarkdownCell(source.status)} | ${escapeMarkdownCell(details.join(", "))} |`,
      );
    }
  }

  if (report.findings.length === 0) {
    lines.push("", "## Findings", "", "No findings.");
    return lines.join("\n");
  }

  lines.push(
    "",
    "## Findings",
    "",
    "| Severity | Code | Package | Path | Evidence | Message |",
    "| --- | --- | --- | --- | --- | --- |",
  );
  for (const finding of report.findings) {
    const pkg =
      finding.packageName && finding.packageVersion
        ? `${finding.packageName}@${finding.packageVersion}`
        : finding.packageName ?? "";
    lines.push(
      `| ${escapeMarkdownCell(finding.severity)} | ${escapeMarkdownCell(finding.code)} | ${escapeMarkdownCell(pkg)} | ${escapeMarkdownCell(finding.packagePath ?? "")} | ${escapeMarkdownCell(formatFindingEvidence(finding))} | ${escapeMarkdownCell(finding.message)} |`,
    );
  }

  return lines.join("\n");
}

function formatDiffMarkdown(report) {
  const lines = [
    "# npm-protect diff",
    "",
    `- Verdict: \`${report.verdict}\``,
    `- Before: \`${report.before}\``,
    `- After: \`${report.after}\``,
    `- Added package versions: \`${report.added.length}\``,
    `- Removed package versions: \`${report.removed.length}\``,
    `- Changed package names: \`${report.changedNames.length}\``,
    `- Changed package artifacts: \`${report.changedArtifacts.length}\``,
  ];

  if (report.riskyAdds.length > 0) {
    lines.push("", "## Risky Added Packages", "", "| Package | Note |", "| --- | --- |");
    for (const pkg of report.riskyAdds) {
      lines.push(`| ${escapeMarkdownCell(`${pkg.name}@${pkg.version}`)} | has install-time scripts |`);
    }
  }

  if (report.changedNames.length > 0) {
    lines.push("", "## Version Changes", "", "| Package | Before | After |", "| --- | --- | --- |");
    for (const change of report.changedNames) {
      lines.push(
        `| ${escapeMarkdownCell(change.name)} | ${escapeMarkdownCell(change.before.join(", "))} | ${escapeMarkdownCell(change.after.join(", "))} |`,
      );
    }
  }

  if (report.changedArtifacts.length > 0) {
    lines.push(
      "",
      "## Artifact Changes",
      "",
      "| Package | Resolved Drift | Integrity Drift |",
      "| --- | --- | --- |",
    );
    for (const change of report.changedArtifacts) {
      lines.push(
        `| ${escapeMarkdownCell(`${change.name}@${change.version}`)} | ${escapeMarkdownCell(change.resolvedChanged ? `${change.beforeResolved.join(", ")} -> ${change.afterResolved.join(", ")}` : "")} | ${escapeMarkdownCell(change.integrityChanged ? `${change.beforeIntegrity.join(", ")} -> ${change.afterIntegrity.join(", ")}` : "")} |`,
      );
    }
  }

  return lines.join("\n");
}

function formatPublishCheckMarkdown(report) {
  const lines = [
    "# npm-protect publish-check",
    "",
    `- Verdict: \`${report.verdict}\``,
    `- Project: \`${report.project}\``,
    `- Workflow files: \`${report.workflowCount}\``,
    `- Publish workflows: \`${report.publishWorkflowCount}\``,
    `- SBOM files: \`${report.sbomFileCount}\``,
    `- Project .npmrc: \`${report.npmrcPresent ? "present" : "not found"}\``,
  ];

  if (report.findings.length === 0) {
    lines.push("", "## Findings", "", "No findings.");
    return lines.join("\n");
  }

  lines.push("", "## Findings", "", "| Severity | Code | Message |", "| --- | --- | --- |");
  for (const finding of report.findings) {
    lines.push(
      `| ${escapeMarkdownCell(finding.severity)} | ${escapeMarkdownCell(finding.code)} | ${escapeMarkdownCell(finding.message)} |`,
    );
  }

  return lines.join("\n");
}

function reviewReportToSarif(report) {
  const rules = [];
  const seenRules = new Set();
  const results = report.findings.map((finding) => {
    if (!seenRules.has(finding.code)) {
      seenRules.add(finding.code);
      rules.push({
        id: finding.code,
        shortDescription: {
          text: finding.code.replaceAll("_", " "),
        },
        fullDescription: {
          text: finding.message,
        },
      });
    }

    return {
      ruleId: finding.code,
      level: toSarifLevel(finding.severity),
      message: {
        text: finding.message,
      },
      locations: resolveReviewLocations(report, finding),
      properties: buildFindingProperties(finding),
    };
  });

  return createSarifLog("review", rules, results, {
    verdict: report.verdict,
    riskVerdict: report.riskVerdict,
  });
}

function diffReportToSarif(report) {
  const results = [];

  for (const pkg of report.riskyAdds) {
    results.push({
      ruleId: "risky_added_package",
      level: "error",
      message: {
        text: `${pkg.name}@${pkg.version} was added and has install-time scripts`,
      },
      properties: {
        packageName: pkg.name,
        packageVersion: pkg.version,
      },
    });
  }

  for (const pkg of report.added) {
    if (report.riskyAdds.some((entry) => `${entry.name}@${entry.version}` === pkg)) {
      continue;
    }

    results.push({
      ruleId: "dependency_added",
      level: "warning",
      message: {
        text: `${pkg} was added to the dependency snapshot`,
      },
    });
  }

  for (const pkg of report.removed) {
    results.push({
      ruleId: "dependency_removed",
      level: "note",
      message: {
        text: `${pkg} was removed from the dependency snapshot`,
      },
    });
  }

  for (const change of report.changedNames) {
    results.push({
      ruleId: "dependency_version_changed",
      level: "warning",
      message: {
        text: `${change.name} changed from ${change.before.join(", ")} to ${change.after.join(", ")}`,
      },
      properties: {
        packageName: change.name,
        before: change.before,
        after: change.after,
      },
    });
  }

  for (const change of report.changedArtifacts) {
    if (change.resolvedChanged) {
      results.push({
        ruleId: "dependency_source_changed",
        level: "warning",
        message: {
          text: `${change.name}@${change.version} resolved source changed from ${change.beforeResolved.join(", ")} to ${change.afterResolved.join(", ")}`,
        },
        properties: {
          packageName: change.name,
          packageVersion: change.version,
          beforeResolved: change.beforeResolved,
          afterResolved: change.afterResolved,
        },
      });
    }

    if (change.integrityChanged) {
      results.push({
        ruleId: "dependency_integrity_changed",
        level: "error",
        message: {
          text: `${change.name}@${change.version} integrity changed from ${change.beforeIntegrity.join(", ")} to ${change.afterIntegrity.join(", ")}`,
        },
        properties: {
          packageName: change.name,
          packageVersion: change.version,
          beforeIntegrity: change.beforeIntegrity,
          afterIntegrity: change.afterIntegrity,
        },
      });
    }
  }

  const rules = [
    {
      id: "risky_added_package",
      shortDescription: {
        text: "new package with install-time scripts",
      },
    },
    {
      id: "dependency_added",
      shortDescription: {
        text: "dependency added",
      },
    },
    {
      id: "dependency_removed",
      shortDescription: {
        text: "dependency removed",
      },
    },
    {
      id: "dependency_version_changed",
      shortDescription: {
        text: "dependency versions changed",
      },
    },
    {
      id: "dependency_source_changed",
      shortDescription: {
        text: "dependency resolved source changed",
      },
    },
    {
      id: "dependency_integrity_changed",
      shortDescription: {
        text: "dependency integrity changed",
      },
    },
  ];

  return createSarifLog("diff", rules, results, {
    verdict: report.verdict,
    before: report.before,
    after: report.after,
  });
}

function publishCheckReportToSarif(report) {
  const rules = [];
  const seenRules = new Set();
  const results = report.findings.map((finding) => {
    if (!seenRules.has(finding.code)) {
      seenRules.add(finding.code);
      rules.push({
        id: finding.code,
        shortDescription: {
          text: finding.code.replaceAll("_", " "),
        },
        fullDescription: {
          text: finding.message,
        },
      });
    }

    return {
      ruleId: finding.code,
      level: toSarifLevel(finding.severity),
      message: {
        text: finding.message,
      },
      locations: resolvePublishCheckLocations(finding),
      properties: buildFindingProperties(finding),
    };
  });

  return createSarifLog("publish-check", rules, results, {
    verdict: report.verdict,
    workflowCount: report.workflowCount,
    publishWorkflowCount: report.publishWorkflowCount,
  });
}

function createSarifLog(commandName, rules, results, invocationProperties) {
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "npm-protect",
            rules,
          },
        },
        results,
        invocations: [
          {
            commandLine: `npm-protect ${commandName}`,
            executionSuccessful: true,
            properties: invocationProperties,
          },
        ],
      },
    ],
  };
}

function resolveReviewLocations(report, finding) {
  const candidate =
    finding.code === "missing_repository" || finding.code === "non_registry_direct_dependency"
      ? report.project.manifestPath
      : report.project.lockfilePath ?? report.project.manifestPath;

  if (!candidate) {
    return undefined;
  }

  return [
    {
      physicalLocation: {
        artifactLocation: {
          uri: pathToFileURL(candidate).toString(),
        },
      },
    },
  ];
}

function resolvePublishCheckLocations(finding) {
  const workflowPath = finding.details?.workflowPath;
  if (!workflowPath) {
    return undefined;
  }

  return [
    {
      physicalLocation: {
        artifactLocation: {
          uri: pathToFileURL(workflowPath).toString(),
        },
      },
    },
  ];
}

function buildFindingProperties(finding) {
  const properties = {
    severity: finding.severity,
  };

  if (finding.packageName) {
    properties.packageName = finding.packageName;
  }

  if (finding.packageVersion) {
    properties.packageVersion = finding.packageVersion;
  }

  if (finding.packagePath) {
    properties.packagePath = finding.packagePath;
  }

  if (finding.details) {
    properties.details = finding.details;
  }

  return properties;
}

function toSarifLevel(severity) {
  if (severity === "error") {
    return "error";
  }

  if (severity === "warn") {
    return "warning";
  }

  return "note";
}

function escapeMarkdownCell(value) {
  return String(value ?? "").replaceAll("|", "\\|").replaceAll("\n", " ");
}

function renderInstallPackageTable(packages) {
  const lines = [
    "| Package | Path | Source | Scripts | Approval Command |",
    "| --- | --- | --- | --- | --- |",
  ];

  for (const pkg of packages) {
    lines.push(
      `| ${escapeMarkdownCell(`${pkg.name}@${pkg.version}`)} | ${escapeMarkdownCell(pkg.path)} | ${escapeMarkdownCell(pkg.source)} | ${escapeMarkdownCell(formatInstallScripts(pkg.scriptNames))} | ${escapeMarkdownCell(pkg.approvalCommand ?? "")} |`,
    );
  }

  return lines;
}

function formatInstallPackageLabel(pkg) {
  const detailParts = [];

  if (pkg.source === "tarball") {
    detailParts.push("recovered from tarball");
  }

  if (pkg.scriptNames?.length > 0) {
    detailParts.push(`scripts: ${pkg.scriptNames.join(", ")}`);
  }

  const suffix = detailParts.length > 0 ? ` (${detailParts.join("; ")})` : "";
  return `${pkg.name}@${pkg.version}${suffix}`;
}

function formatInstallScripts(scriptNames) {
  if (!scriptNames || scriptNames.length === 0) {
    return "lockfile";
  }

  return scriptNames.join(", ");
}

function formatFindingContext(finding) {
  const parts = [];

  if (finding.packageName) {
    parts.push(
      `package=${finding.packageVersion ? `${finding.packageName}@${finding.packageVersion}` : finding.packageName}`,
    );
  }

  if (finding.packagePath) {
    parts.push(`path=${finding.packagePath}`);
  }

  const evidence = formatFindingEvidence(finding);
  if (evidence) {
    parts.push(`evidence=${evidence}`);
  }

  return parts.join("; ");
}

function formatFindingEvidence(finding) {
  const details = finding.details ?? {};
  const parts = [];

  if (details.target) {
    parts.push(`target=${details.target}`);
  }

  if (details.score !== undefined) {
    parts.push(`score=${Number(details.score).toFixed(2)}`);
  }

  if (details.spec) {
    parts.push(`spec=${details.spec}`);
  }

  if (details.scriptName) {
    parts.push(`script=${details.scriptName}`);
  }

  if (Array.isArray(details.scriptNames) && details.scriptNames.length > 0) {
    parts.push(`scripts=${details.scriptNames.join(",")}`);
  }

  if (details.indicator) {
    parts.push(`indicator=${details.indicator}`);
  }

  if (details.publishedAt) {
    parts.push(`publishedAt=${details.publishedAt}`);
  }

  if (details.source) {
    parts.push(`source=${details.source}`);
  }

  if (details.tarballUrl) {
    parts.push(`tarball=${details.tarballUrl}`);
  }

  if (details.lockfileIntegrity) {
    parts.push(`lockfileIntegrity=${details.lockfileIntegrity}`);
  }

  if (details.registryIntegrity) {
    parts.push(`registryIntegrity=${details.registryIntegrity}`);
  }

  if (details.expiredAt) {
    parts.push(`expiredAt=${details.expiredAt}`);
  }

  return parts.join(", ");
}
