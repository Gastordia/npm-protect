import {
  getProtectionServiceStatus,
  installProtectionService,
  runProtectedPackageManagerCommand,
  runProtectedNpmCommand,
  uninstallProtectionService,
} from "../lib/service.js";

export async function runServiceCommand(subcommand, argv, options = {}) {
  if (!subcommand || subcommand === "--help" || subcommand === "-h") {
    printServiceHelp();
    return;
  }

  if (subcommand === "install") {
    await runServiceInstall(parseServiceArgs(argv), options);
    return;
  }

  if (subcommand === "status") {
    await runServiceStatus(parseServiceArgs(argv), options);
    return;
  }

  if (subcommand === "doctor") {
    await runServiceDoctor(parseServiceArgs(argv), options);
    return;
  }

  if (subcommand === "uninstall") {
    await runServiceUninstall(parseServiceArgs(argv), options);
    return;
  }

  if (subcommand === "run") {
    const runArgs = parseServiceRunArgs(argv);
    const result =
      runArgs.toolName === "npm"
        ? await runProtectedNpmCommand(runArgs.args, options)
        : await runProtectedPackageManagerCommand(runArgs.toolName, runArgs.args, options);
    if (result.exitCode) {
      process.exitCode = result.exitCode;
    }
    return;
  }

  throw new Error(`unknown service subcommand "${subcommand}"`);
}

async function runServiceInstall(args, options) {
  const installResult = await installProtectionService(
    {
      binDir: asOptionalString(args.flags["bin-dir"]),
      cliPath: asOptionalString(args.flags["cli-path"]),
      nodePath: asOptionalString(args.flags["node-path"]),
      pathValue: options.pathValue,
    },
    options,
  );

  if (args.flags.json) {
    console.log(JSON.stringify(installResult, null, 2));
    return;
  }

  console.log(`Installed npm-protect wrappers in ${installResult.binDir}`);
  console.log(`Wrapped tools: ${installResult.wrappers.map((wrapper) => wrapper.name).join(", ")}`);
  console.log(`Primary npm wrapper: ${installResult.wrapperPath}`);
  console.log(`CLI path: ${installResult.cliPath}`);
  console.log(`Real npm path: ${installResult.realNpmPath ?? "(resolved at runtime)"}`);
  console.log(`Node absolute-path hook: ${installResult.nodeHookPath}`);
  console.log(`Activation script: ${installResult.envScriptPath}`);

  if (!installResult.pathActive) {
    console.log("");
    console.log("Add this to your shell profile for full wrapper activation and Node child-process interception:");
    console.log(installResult.activationSnippet);
    console.log("");
    console.log("PATH-only fallback:");
    console.log(installResult.pathShellSnippet);
  }
}

async function runServiceStatus(args, options) {
  const status = await getProtectionServiceStatus(
    {
      binDir: asOptionalString(args.flags["bin-dir"]),
      pathValue: options.pathValue,
    },
    options,
  );

  if (args.flags.json) {
    console.log(JSON.stringify(status, null, 2));
    return;
  }

  console.log(`Primary npm wrapper: ${status.wrapperPath}`);
  console.log(`Wrapper installed: ${status.wrapperExists ? "yes" : "no"}`);
  console.log(`PATH active: ${status.pathActive ? "yes" : "no"}`);
  console.log(`Current npm path: ${status.currentNpmPath ?? "(unresolved)"}`);
  console.log(`Protection active: ${status.active ? "yes" : "no"}`);
  console.log(
    `Node absolute-path guard: ${status.absolutePathProtection?.active ? "active" : "inactive"} (${status.absolutePathProtection?.provider ?? "unknown"})`,
  );
  console.log(
    `Approved rebuild sandbox: ${status.rebuildSandboxSupport?.available ? "available" : "unavailable"} (${status.rebuildSandboxSupport?.provider ?? "unknown"})`,
  );

  for (const wrapper of status.wrappers) {
    console.log(
      `- ${wrapper.name}: installed=${wrapper.wrapperExists ? "yes" : "no"} managed=${wrapper.managed ? "yes" : "no"} present=${wrapper.fileExists ? "yes" : "no"} active=${wrapper.active ? "yes" : "no"} current=${wrapper.currentPath ?? "(unresolved)"}`,
    );
  }
}

async function runServiceDoctor(args, options) {
  const status = await getProtectionServiceStatus(
    {
      binDir: asOptionalString(args.flags["bin-dir"]),
      pathValue: options.pathValue,
    },
    options,
  );
  const issues = [];
  const recommendations = [];

  if (!status.wrapperExists) {
    issues.push({
      severity: "error",
      code: "missing_primary_wrapper",
      message: `Primary npm wrapper is not installed at ${status.wrapperPath}`,
    });
    recommendations.push("Run `npm-protect service install`.");
  }

  if (!status.pathActive) {
    issues.push({
      severity: "error",
      code: "path_not_active",
      message: `${status.binDir} is not the first PATH entry, so the protection wrappers will be bypassed`,
    });
    recommendations.push(
      `Source \`${status.envScriptPath}\` from your shell profile to enable wrapper PATH priority and Node child-process interception.`,
    );
  }

  for (const wrapper of status.wrappers) {
    if (wrapper.fileExists && !wrapper.managed) {
      issues.push({
        severity: wrapper.name === "npm" ? "error" : "warn",
        code: "wrapper_unmanaged",
        message: `${wrapper.name} exists at ${wrapper.wrapperPath}, but it is not an npm-protect managed wrapper`,
      });
      recommendations.push(
        `Move or remove the conflicting ${wrapper.name} file at ${wrapper.wrapperPath}, then run \`npm-protect service install\` again.`,
      );
      continue;
    }

    if (!wrapper.wrapperExists) {
      issues.push({
        severity: "warn",
        code: "wrapper_missing",
        message: `${wrapper.name} wrapper is not installed at ${wrapper.wrapperPath}`,
      });
      continue;
    }

    if (!wrapper.active) {
      issues.push({
        severity: "warn",
        code: "wrapper_inactive",
        message: `${wrapper.name} is resolving to ${wrapper.currentPath ?? "(unresolved)"} instead of the npm-protect wrapper`,
      });
    }
  }

  if (!status.absolutePathProtection?.hookExists || !status.absolutePathProtection?.envScriptExists) {
    issues.push({
      severity: "warn",
      code: "absolute_path_hook_missing",
      message: `Node child-process interception helper files are missing from ${status.binDir}`,
    });
    recommendations.push("Run `npm-protect service install` again to recreate the activation helpers.");
  } else if (!status.absolutePathProtection.active) {
    issues.push({
      severity: "warn",
      code: "absolute_path_protection_inactive",
      message:
        "absolute npm, npx, pnpm, yarn, or corepack invocations from Node-based tools can still bypass the wrappers because the activation script is not loaded",
    });
    recommendations.push(
      `Source \`${status.envScriptPath}\` from your shell profile to catch absolute package-manager invocations spawned by Node-based tools.`,
    );
  }

  if (!status.rebuildSandboxSupport?.available) {
    issues.push({
      severity: "warn",
      code: "rebuild_sandbox_unavailable",
      message: status.rebuildSandboxSupport?.message ?? "approved rebuild sandbox support is unavailable",
    });
    recommendations.push(
      'Install bubblewrap (`bwrap`) to isolate approved install-script rebuilds, or set `service.rebuildSandbox: "require"` to fail closed when sandboxing is unavailable.',
    );
  }

  if (recommendations.length === 0) {
    recommendations.push("No action required.");
  }

  if (args.flags.json) {
    console.log(
      JSON.stringify(
        {
          status,
          issues,
          recommendations,
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`Primary npm wrapper: ${status.wrapperPath}`);
  console.log(`PATH active: ${status.pathActive ? "yes" : "no"}`);
  console.log(`Protection active: ${status.active ? "yes" : "no"}`);
  console.log(
    `Node absolute-path guard: ${status.absolutePathProtection?.active ? "active" : "inactive"} (${status.absolutePathProtection?.provider ?? "unknown"})`,
  );
  console.log(
    `Approved rebuild sandbox: ${status.rebuildSandboxSupport?.available ? "available" : "unavailable"} (${status.rebuildSandboxSupport?.provider ?? "unknown"})`,
  );
  console.log("");
  if (issues.length === 0) {
    console.log("No service issues detected.");
  } else {
    console.log("Issues:");
    for (const issue of issues) {
      console.log(`- ${issue.severity.toUpperCase()} ${issue.code}: ${issue.message}`);
    }
  }

  console.log("");
  console.log("Recommendations:");
  for (const recommendation of recommendations) {
    console.log(`- ${recommendation}`);
  }
}

async function runServiceUninstall(args, options) {
  const result = await uninstallProtectionService({
    binDir: asOptionalString(args.flags["bin-dir"]),
  });

  if (args.flags.json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  for (const wrapper of result.removedWrappers) {
    console.log(`Removed ${wrapper.wrapperPath}`);
  }

  for (const wrapper of result.skippedWrappers) {
    console.log(`Skipped ${wrapper.wrapperPath} because it is not an npm-protect managed wrapper`);
  }

  for (const helperPath of result.removedHelperFiles ?? []) {
    console.log(`Removed ${helperPath}`);
  }

  console.log(`Removed ${result.manifestPath}`);
}

function printServiceHelp() {
  console.log(`npm-protect service

Usage:
  npm-protect service install [--bin-dir <dir>] [--json]
  npm-protect service status [--bin-dir <dir>] [--json]
  npm-protect service doctor [--bin-dir <dir>] [--json]
  npm-protect service uninstall [--bin-dir <dir>] [--json]
`);
}

function parseServiceArgs(argv) {
  const flags = {};
  const positionals = [];

  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index];

    if (!current.startsWith("--")) {
      positionals.push(current);
      continue;
    }

    const withoutPrefix = current.slice(2);
    if (withoutPrefix.includes("=")) {
      const [key, value] = withoutPrefix.split(/=(.+)/, 2);
      flags[key] = value;
      continue;
    }

    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      flags[withoutPrefix] = true;
      continue;
    }

    flags[withoutPrefix] = next;
    index += 1;
  }

  return { flags, positionals };
}

function parseServiceRunArgs(argv) {
  const separatorIndex = argv.indexOf("--");
  const serviceArgs = separatorIndex === -1 ? argv : argv.slice(0, separatorIndex);
  const forwardedArgs = separatorIndex === -1 ? [] : argv.slice(separatorIndex + 1);
  const parsed = parseServiceArgs(serviceArgs);

  return {
    toolName: asOptionalString(parsed.flags.tool) ?? process.env.NPM_PROTECT_TOOL ?? "npm",
    args: separatorIndex === -1 ? parsed.positionals : forwardedArgs,
  };
}

function asOptionalString(value) {
  return typeof value === "string" && value.length > 0 ? value : null;
}
