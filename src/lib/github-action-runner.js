import path from "node:path";

import { buildGitHubActionPlan } from "./github-action.js";
import { buildGitHubAnnotations, supportsGitHubAnnotations } from "./github-annotations.js";

export async function executeGitHubAction(env, deps) {
  const plan = buildGitHubActionPlan(env);

  await deps.ensureDir(path.dirname(plan.outputPath));
  const mainExitCode = await deps.runCliCommand(plan.args);

  if (plan.summaryArgs) {
    await deps.ensureDir(path.dirname(plan.summaryPath));
    await deps.runCliCommand(plan.summaryArgs);

    if (env.GITHUB_STEP_SUMMARY) {
      const summary = await deps.readText(plan.summaryPath);
      await deps.appendText(env.GITHUB_STEP_SUMMARY, `${summary}\n`);
    }
  }

  let annotationCount = 0;
  if (plan.annotateFindings && supportsGitHubAnnotations(plan.command)) {
    const annotationReportPath =
      plan.format === "json" ? plan.outputPath : plan.annotationPath;

    if (plan.annotationArgs) {
      await deps.ensureDir(path.dirname(plan.annotationPath));
      await deps.runCliCommand(plan.annotationArgs);
    }

    const parsed = JSON.parse(await deps.readText(annotationReportPath));
    const annotations = buildGitHubAnnotations(plan.command, parsed);
    annotationCount = annotations.length;
    for (const annotation of annotations) {
      deps.log(annotation);
    }
  }

  const outputs = {
    command: plan.command,
    format: plan.format,
    result_path: plan.outputPath,
    summary_path: plan.summaryArgs ? plan.summaryPath : "",
    annotation_count: String(annotationCount),
  };

  if (env.GITHUB_OUTPUT) {
    const content = Object.entries(outputs)
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");
    await deps.appendText(env.GITHUB_OUTPUT, `${content}\n`);
  }

  return {
    exitCode: mainExitCode,
    outputs,
    annotationCount,
  };
}
