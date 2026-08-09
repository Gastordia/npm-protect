import { lstat } from "node:fs/promises";

export async function inspectLocalPolicyFile(filePath, label) {
  const warnings = [];

  try {
    const stats = await lstat(filePath);

    if (stats.isSymbolicLink()) {
      warnings.push(
        `${label} at ${filePath} is a symlink; keep npm-protect policy files as regular files to reduce redirection risk`,
      );
      return warnings;
    }

    if (!stats.isFile()) {
      warnings.push(
        `${label} at ${filePath} is not a regular file; keep npm-protect policy files as regular files to reduce tampering risk`,
      );
      return warnings;
    }

    if ((stats.mode & 0o022) !== 0) {
      warnings.push(
        `${label} at ${filePath} is writable by group or other users; restrict it to the current user to reduce tampering risk`,
      );
    }
  } catch (error) {
    warnings.push(
      `unable to inspect ${label} at ${filePath}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  return warnings;
}
