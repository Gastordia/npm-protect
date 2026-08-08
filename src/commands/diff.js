import {
  assertSupportedFormat,
  emitOutput,
  resolveOutputFormat,
  resolveOutputPath,
} from "../lib/output.js";
import { diffSnapshots, loadGitRefSnapshot, loadSnapshotTarget } from "../lib/project.js";
import { serializeDiffReport } from "../lib/reporters.js";

export async function runDiffCommand(args, options = {}) {
  const format = resolveOutputFormat(args.flags);
  const outputPath = resolveOutputPath(args.flags);
  assertSupportedFormat("diff", format, ["text", "json", "sarif", "markdown"]);
  const beforeSnapshot = await resolveDiffSnapshot(args, "before", options);
  const afterSnapshot = await resolveDiffSnapshot(args, "after", options);
  const report = diffSnapshots(beforeSnapshot, afterSnapshot);

  await emitOutput(serializeDiffReport(report, format), outputPath);

  if (report.verdict === "block") {
    process.exitCode = 2;
  }
}

async function resolveDiffSnapshot(args, side, options) {
  const refFlag = args.flags[`${side}-ref`];
  if (typeof refFlag === "string" && refFlag.length > 0) {
    const repoDir = String(args.flags.project ?? process.cwd());
    const lockfilePath =
      typeof args.flags["lockfile-path"] === "string" ? args.flags["lockfile-path"] : null;
    return loadGitRefSnapshot(repoDir, refFlag, lockfilePath, {
      readGitFile: options.gitReadFile,
    });
  }

  const positionalIndex = side === "before" ? 0 : 1;
  const target = String(args.flags[side] ?? args.positionals[positionalIndex] ?? ".");
  return loadSnapshotTarget(target);
}
