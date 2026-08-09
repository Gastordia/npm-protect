import { runDiffCommand } from "./commands/diff.js";
import { runInstallCommand } from "./commands/install.js";
import { runPolicyCommand } from "./commands/policy.js";
import { runPublishCheckCommand } from "./commands/publish-check.js";
import { runReviewCommand } from "./commands/review.js";
import { runSbomCommand } from "./commands/sbom.js";
import { runServiceCommand } from "./commands/service.js";
import { runVerifyCommand } from "./commands/verify.js";

const HELP_TEXT = `npm-protect

Usage:
  npm-protect <command> [options]

Commands:
  review           Inspect the current project and evaluate local policy
  verify           Alias of review
  diff             Compare two project snapshots or lockfiles
  install          Print a safer install plan
  publish-check    Check local publisher posture signals
  sbom             Export a CycloneDX SBOM from the local npm snapshot
  service          Install or run the always-on package-manager protection shims
  policy init      Write a sample npm-protect.yml
  policy validate  Validate config or defaults

Common options:
  --project <dir>  Project directory to inspect
  --config <path>  Explicit config path
  --online         Enable default external intelligence collectors
  --inspect-tarballs[=all] Fetch and inspect published tarballs; use "=all" to inspect all resolved registry packages
  --audit-signatures Run npm audit signatures for verified signatures and attestations
  --cache-dir <dir> Cache remote lookup responses in a local directory
  --cache-ttl-hours <n> Reuse cached remote responses for this many hours (default 24)
  --before-ref <git ref> Load the before snapshot from a git ref
  --after-ref <git ref>  Load the after snapshot from a git ref
  --lockfile-path <path> Override the lockfile path when diffing git refs
  --osv-url <url>  Override the OSV querybatch endpoint
  --registry-url <url> Override the npm registry base URL
  --json           Print JSON output
  --format <name>  Explicit output format (command-specific)
  --output <path>  Write output to a file instead of stdout
  --help           Show this help text
`;

export async function runCli(argv, options = {}) {
  const [command, ...rest] = argv;

  if (!command || command === "--help" || command === "-h") {
    console.log(HELP_TEXT);
    return;
  }

  if (command === "review") {
    await runReviewCommand(parseArgs(rest), options);
    return;
  }

  if (command === "verify") {
    await runVerifyCommand(parseArgs(rest), options);
    return;
  }

  if (command === "diff") {
    await runDiffCommand(parseArgs(rest), options);
    return;
  }

  if (command === "install") {
    await runInstallCommand(parseArgs(rest), options);
    return;
  }

  if (command === "publish-check") {
    await runPublishCheckCommand(parseArgs(rest));
    return;
  }

  if (command === "sbom") {
    await runSbomCommand(parseArgs(rest));
    return;
  }

  if (command === "policy") {
    const [subcommand, ...policyArgs] = rest;
    await runPolicyCommand(subcommand, parseArgs(policyArgs));
    return;
  }

  if (command === "service") {
    const [subcommand, ...serviceArgs] = rest;
    await runServiceCommand(subcommand, serviceArgs, options);
    return;
  }

  throw new Error(`unknown command "${command}"`);
}

export function parseArgs(argv) {
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
