import { chmod } from "node:fs/promises";

import {
  getProtectionServiceStatus,
  installProtectionService,
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

  if (subcommand === "uninstall") {
    await runServiceUninstall(parseServiceArgs(argv), options);
    return;
  }

  if (subcommand === "run") {
    const result = await runProtectedNpmCommand(argv, options);
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
      realNpmPath: asOptionalString(args.flags["real-npm"]),
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

  console.log(`Installed npm-protect wrapper at ${installResult.wrapperPath}`);
  console.log(`Real npm path: ${installResult.realNpmPath}`);
  console.log(`CLI path: ${installResult.cliPath}`);

  if (!installResult.pathActive) {
    console.log("");
    console.log("Add this to your shell profile so the wrapper is used first:");
    console.log(installResult.shellSnippet);
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

  console.log(`Wrapper path: ${status.wrapperPath}`);
  console.log(`Wrapper installed: ${status.wrapperExists ? "yes" : "no"}`);
  console.log(`PATH active: ${status.pathActive ? "yes" : "no"}`);
  console.log(`Current npm path: ${status.currentNpmPath ?? "(unresolved)"}`);
  console.log(`Protection active: ${status.active ? "yes" : "no"}`);
}

async function runServiceUninstall(args, options) {
  const result = await uninstallProtectionService({
    binDir: asOptionalString(args.flags["bin-dir"]),
  });

  if (args.flags.json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  console.log(`Removed ${result.wrapperPath}`);
  console.log(`Removed ${result.manifestPath}`);
}

function printServiceHelp() {
  console.log(`npm-protect service

Usage:
  npm-protect service install [--bin-dir <dir>] [--real-npm <path>] [--json]
  npm-protect service status [--bin-dir <dir>] [--json]
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

function asOptionalString(value) {
  return typeof value === "string" && value.length > 0 ? value : null;
}
