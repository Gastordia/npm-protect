import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

export function resolveOutputFormat(flags, defaultFormat = "text") {
  if (typeof flags.format === "string" && flags.format.length > 0) {
    return flags.format.toLowerCase();
  }

  if (flags.json) {
    return "json";
  }

  return defaultFormat;
}

export function resolveOutputPath(flags) {
  if (typeof flags.output !== "string" || flags.output.length === 0) {
    return null;
  }

  return path.resolve(flags.output);
}

export function assertSupportedFormat(commandName, format, supportedFormats) {
  if (supportedFormats.includes(format)) {
    return;
  }

  throw new Error(
    `${commandName} does not support format "${format}"; supported formats: ${supportedFormats.join(", ")}`,
  );
}

export async function emitOutput(content, outputPath = null) {
  if (outputPath) {
    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, content.endsWith("\n") ? content : `${content}\n`, "utf8");
    return;
  }

  console.log(content);
}
