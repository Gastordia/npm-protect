import { appendFile, mkdir, readFile } from "node:fs/promises";

import { runCli } from "../src/cli.js";
import { executeGitHubAction } from "../src/lib/github-action-runner.js";

try {
  const result = await executeGitHubAction(process.env, {
    async ensureDir(dirPath) {
      await mkdir(dirPath, { recursive: true });
    },
    async runCliCommand(args) {
      const originalExitCode = process.exitCode;
      process.exitCode = undefined;
      await runCli(args, {});
      const exitCode = process.exitCode ?? 0;
      process.exitCode = originalExitCode;
      return exitCode;
    },
    async readText(filePath) {
      return await readFile(filePath, "utf8");
    },
    async appendText(filePath, content) {
      await appendFile(filePath, content, "utf8");
    },
    log(line) {
      console.log(line);
    },
  });

  process.exitCode = result.exitCode;
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = process.exitCode ?? 1;
}
