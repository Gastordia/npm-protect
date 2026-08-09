import { loadConfig } from "../lib/config.js";
import { collectExternalIntelligence } from "../lib/intelligence.js";
import {
  assertSupportedFormat,
  emitOutput,
  resolveOutputFormat,
  resolveOutputPath,
} from "../lib/output.js";
import { evaluateProjectWithIntelligence } from "../lib/policy.js";
import { loadProjectSnapshot } from "../lib/project.js";
import { serializeReviewReport } from "../lib/reporters.js";

export async function runReviewCommand(args, options = {}) {
  const projectDir = String(args.flags.project ?? process.cwd());
  const configPath = typeof args.flags.config === "string" ? args.flags.config : null;
  const format = resolveOutputFormat(args.flags);
  const outputPath = resolveOutputPath(args.flags);
  assertSupportedFormat("review", format, ["text", "json", "sarif", "markdown"]);

  const project = await loadProjectSnapshot(projectDir);
  const configState = await loadConfig(projectDir, configPath);
  const intelligence = await collectExternalIntelligence(project, configState.config, {
    flags: args.flags,
    fetchImpl: options.fetchImpl,
    auditSignaturesRunner: options.auditSignaturesRunner,
    now: options.now,
  });
  const report = evaluateProjectWithIntelligence(project, configState.config, {
    validationErrors: configState.validationErrors,
    securityWarnings: configState.securityWarnings,
    intelligence,
  });

  await emitOutput(serializeReviewReport(report, format), outputPath);

  if (report.verdict === "block") {
    process.exitCode = 2;
  }
}
