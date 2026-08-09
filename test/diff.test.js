import assert from "node:assert/strict";
import test from "node:test";

import { diffSnapshots, loadGitRefSnapshot } from "../src/lib/project.js";

test("diffSnapshots blocks when newly added packages contain install scripts", () => {
  const before = {
    label: "before",
    packages: [],
  };
  const after = {
    label: "after",
    packages: [
      {
        name: "esbuild",
        version: "0.25.0",
        hasInstallScript: true,
      },
    ],
  };

  const report = diffSnapshots(before, after);

  assert.equal(report.verdict, "block");
  assert.deepEqual(report.added, ["esbuild@0.25.0"]);
  assert.equal(report.riskyAdds.length, 1);
});

test("diffSnapshots returns allow when there are no dependency changes", () => {
  const snapshot = {
    label: "same",
    packages: [
      {
        name: "zod",
        version: "4.0.0",
        hasInstallScript: false,
      },
    ],
  };

  const report = diffSnapshots(snapshot, snapshot);

  assert.equal(report.verdict, "allow");
  assert.equal(report.added.length, 0);
  assert.equal(report.removed.length, 0);
  assert.equal(report.changedNames.length, 0);
  assert.equal(report.changedArtifacts.length, 0);
});

test("diffSnapshots blocks when the same package version changes integrity", () => {
  const before = {
    label: "before",
    packages: [
      {
        name: "left-pad",
        version: "1.3.0",
        resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        integrity: "sha512-before",
        hasInstallScript: false,
      },
    ],
  };
  const after = {
    label: "after",
    packages: [
      {
        name: "left-pad",
        version: "1.3.0",
        resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        integrity: "sha512-after",
        hasInstallScript: false,
      },
    ],
  };

  const report = diffSnapshots(before, after);

  assert.equal(report.verdict, "block");
  assert.equal(report.changedArtifacts.length, 1);
  assert.equal(report.changedArtifacts[0].integrityChanged, true);
  assert.equal(report.changedArtifacts[0].resolvedChanged, false);
});

test("diffSnapshots warns when the same package version changes resolved source", () => {
  const before = {
    label: "before",
    packages: [
      {
        name: "left-pad",
        version: "1.3.0",
        resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        integrity: "sha512-same",
        hasInstallScript: false,
      },
    ],
  };
  const after = {
    label: "after",
    packages: [
      {
        name: "left-pad",
        version: "1.3.0",
        resolved: "https://mirror.example/left-pad-1.3.0.tgz",
        integrity: "sha512-same",
        hasInstallScript: false,
      },
    ],
  };

  const report = diffSnapshots(before, after);

  assert.equal(report.verdict, "warn");
  assert.equal(report.changedArtifacts.length, 1);
  assert.equal(report.changedArtifacts[0].resolvedChanged, true);
  assert.equal(report.changedArtifacts[0].integrityChanged, false);
});

test("loadGitRefSnapshot reads lockfiles from git refs", async () => {
  const refs = {
    refA: {
      "package-lock.json": JSON.stringify({
        name: "demo",
        version: "1.0.0",
        lockfileVersion: 3,
        packages: {
          "": {
            name: "demo",
            version: "1.0.0",
            dependencies: {
              react: "19.0.0",
            },
          },
          "node_modules/react": {
            version: "19.0.0",
            resolved: "https://registry.npmjs.org/react/-/react-19.0.0.tgz",
            integrity: "sha512-react",
          },
        },
      }),
    },
    refB: {
      "package-lock.json": JSON.stringify({
        name: "demo",
        version: "1.0.0",
        lockfileVersion: 3,
        packages: {
          "": {
            name: "demo",
            version: "1.0.0",
            dependencies: {
              esbuild: "0.25.0",
            },
          },
          "node_modules/esbuild": {
            version: "0.25.0",
            resolved: "https://registry.npmjs.org/esbuild/-/esbuild-0.25.0.tgz",
            integrity: "sha512-esbuild",
            hasInstallScript: true,
          },
        },
      }),
    },
  };

  const readGitFile = async (repoDir, ref, filePath) => {
    const content = refs[ref]?.[filePath];
    if (!content) {
      throw new Error(`git path "${filePath}" was not found in ref "${ref}"`);
    }
    return content;
  };

  const before = await loadGitRefSnapshot("/tmp/demo-repo", "refA", null, {
    readGitFile,
  });
  const after = await loadGitRefSnapshot("/tmp/demo-repo", "refB", null, {
    readGitFile,
  });
  const report = diffSnapshots(before, after);

  assert.equal(report.verdict, "block");
  assert.ok(report.added.includes("esbuild@0.25.0"));
  assert.ok(report.removed.includes("react@19.0.0"));
});

test("loadGitRefSnapshot also reads pnpm lockfiles from git refs", async () => {
  const refs = {
    refA: {
      "pnpm-lock.yaml": `
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: 19.0.0
        version: 19.0.0
packages:
  react@19.0.0:
    resolution:
      integrity: sha512-react
`,
    },
    refB: {
      "pnpm-lock.yaml": `
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      esbuild:
        specifier: 0.25.0
        version: 0.25.0
packages:
  esbuild@0.25.0:
    resolution:
      integrity: sha512-esbuild
    requiresBuild: true
`,
    },
  };

  const readGitFile = async (_repoDir, ref, filePath) => {
    const content = refs[ref]?.[filePath];
    if (!content) {
      throw new Error(`git path "${filePath}" was not found in ref "${ref}"`);
    }
    return content;
  };

  const before = await loadGitRefSnapshot("/tmp/demo-repo", "refA", null, {
    readGitFile,
  });
  const after = await loadGitRefSnapshot("/tmp/demo-repo", "refB", null, {
    readGitFile,
  });
  const report = diffSnapshots(before, after);

  assert.equal(report.verdict, "block");
  assert.ok(report.added.includes("esbuild@0.25.0"));
  assert.ok(report.removed.includes("react@19.0.0"));
});
