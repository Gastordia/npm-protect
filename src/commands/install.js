import { loadConfig } from "../lib/config.js";
import { buildInstallPlan } from "../lib/install-plan.js";
import {
  assertSupportedFormat,
  emitOutput,
  resolveOutputFormat,
  resolveOutputPath,
} from "../lib/output.js";
import { loadProjectSnapshot } from "../lib/project.js";
import { serializeInstallPlan } from "../lib/reporters.js";

export async function runInstallCommand(args, options = {}) {
  const projectDir = String(args.flags.project ?? process.cwd());
  const configPath = typeof args.flags.config === "string" ? args.flags.config : null;
  const format = resolveOutputFormat(args.flags);
  const outputPath = resolveOutputPath(args.flags);
  assertSupportedFormat("install", format, ["text", "json", "markdown"]);

  const project = await loadProjectSnapshot(projectDir);
  const configState = await loadConfig(projectDir, configPath);
  const plan = await buildInstallPlan(project, configState.config, {
    flags: args.flags,
    fetchImpl: options.fetchImpl,
    now: options.now,
  });

  await emitOutput(serializeInstallPlan(plan, format), outputPath);
}
