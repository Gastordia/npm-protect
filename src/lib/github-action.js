import path from "node:path";

const MARKDOWN_COMMANDS = new Set(["review", "verify", "diff", "publish-check", "install"]);
const ANNOTATION_COMMANDS = new Set(["review", "verify", "diff", "publish-check"]);

export function buildGitHubActionPlan(env) {
  const command = normalize(env.INPUT_COMMAND) ?? "review";
  const project = normalize(env.INPUT_PROJECT) ?? env.GITHUB_WORKSPACE ?? process.cwd();
  const format = normalize(env.INPUT_FORMAT) ?? "json";
  const runnerTemp = env.RUNNER_TEMP ?? process.cwd();
  const outputPath =
    normalize(env.INPUT_OUTPUT) ?? path.join(runnerTemp, `npm-protect-result.${extensionForFormat(format)}`);
  const writeSummary = parseBoolean(env.INPUT_WRITE_SUMMARY, true);
  const annotateFindings = parseBoolean(env.INPUT_ANNOTATE_FINDINGS, true);
  const summaryPath = path.join(runnerTemp, "npm-protect-summary.md");
  const annotationPath = path.join(runnerTemp, "npm-protect-annotations.json");

  const baseArgs = [command, "--project", project];
  pushValue(baseArgs, "--config", env.INPUT_CONFIG);
  pushValue(baseArgs, "--before", env.INPUT_BEFORE);
  pushValue(baseArgs, "--after", env.INPUT_AFTER);
  pushValue(baseArgs, "--before-ref", env.INPUT_BEFORE_REF);
  pushValue(baseArgs, "--after-ref", env.INPUT_AFTER_REF);
  pushValue(baseArgs, "--lockfile-path", env.INPUT_LOCKFILE_PATH);
  pushValue(baseArgs, "--cache-dir", env.INPUT_CACHE_DIR);
  pushValue(baseArgs, "--cache-ttl-hours", env.INPUT_CACHE_TTL_HOURS);
  pushValue(baseArgs, "--osv-url", env.INPUT_OSV_URL);
  pushValue(baseArgs, "--registry-url", env.INPUT_REGISTRY_URL);
  pushBoolean(baseArgs, "--online", env.INPUT_ONLINE);
  pushBoolean(baseArgs, "--inspect-tarballs", env.INPUT_INSPECT_TARBALLS);
  pushBoolean(baseArgs, "--audit-signatures", env.INPUT_AUDIT_SIGNATURES);

  return {
    command,
    format,
    outputPath,
    writeSummary,
    annotateFindings,
    summaryPath,
    annotationPath,
    args: [...baseArgs, "--format", format, "--output", outputPath],
    summaryArgs:
      writeSummary && supportsMarkdownSummary(command)
        ? [...baseArgs, "--format", "markdown", "--output", summaryPath]
        : null,
    annotationArgs:
      annotateFindings && supportsGitHubAnnotations(command) && format !== "json"
        ? [...baseArgs, "--format", "json", "--output", annotationPath]
        : null,
  };
}

export function supportsMarkdownSummary(command) {
  return MARKDOWN_COMMANDS.has(command);
}

export function supportsGitHubAnnotations(command) {
  return ANNOTATION_COMMANDS.has(command);
}

function pushValue(args, flag, value) {
  const normalized = normalize(value);
  if (!normalized) {
    return;
  }

  args.push(flag, normalized);
}

function pushBoolean(args, flag, value) {
  if (parseBoolean(value, false)) {
    args.push(flag);
  }
}

function parseBoolean(value, fallback) {
  if (value === undefined) {
    return fallback;
  }

  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }

  return fallback;
}

function extensionForFormat(format) {
  if (format === "sarif") {
    return "sarif";
  }
  if (format === "markdown") {
    return "md";
  }
  if (format === "text") {
    return "txt";
  }

  return "json";
}

function normalize(value) {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}
