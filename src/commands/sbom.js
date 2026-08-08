import { assertSupportedFormat, emitOutput, resolveOutputFormat, resolveOutputPath } from "../lib/output.js";
import { loadProjectSnapshot } from "../lib/project.js";
import { buildCycloneDxSbom } from "../lib/sbom.js";

export async function runSbomCommand(args) {
  const projectDir = String(args.flags.project ?? process.cwd());
  const format = resolveOutputFormat(args.flags, "json");
  const outputPath = resolveOutputPath(args.flags);
  assertSupportedFormat("sbom", format, ["json", "cyclonedx", "cyclonedx-json"]);

  const project = await loadProjectSnapshot(projectDir);
  const bom = buildCycloneDxSbom(project);

  await emitOutput(JSON.stringify(bom, null, 2), outputPath);
}
