import assert from "node:assert/strict";
import test from "node:test";

import { parseLockfile, parsePnpmLockfile } from "../src/lib/lockfile.js";

test("parseLockfile handles npm lockfile v3 packages", () => {
  const parsed = parseLockfile({
    lockfileVersion: 3,
    packages: {
      "": {
        name: "fixture",
        version: "1.0.0",
      },
      "node_modules/esbuild": {
        version: "0.25.0",
        integrity: "sha512-aaa",
        hasInstallScript: true,
      },
      "node_modules/@scope/pkg": {
        version: "2.0.0",
        integrity: "sha512-bbb",
      },
    },
  });

  assert.equal(parsed.lockfileVersion, 3);
  assert.equal(parsed.packageCount, 2);
  assert.deepEqual(
    parsed.packages.map((pkg) => pkg.name),
    ["esbuild", "@scope/pkg"],
  );
  assert.equal(parsed.packages[0].hasInstallScript, true);
});

test("parseLockfile handles legacy dependency trees", () => {
  const parsed = parseLockfile({
    lockfileVersion: 1,
    dependencies: {
      leftpad: {
        version: "1.0.0",
        integrity: "sha512-aaa",
        dependencies: {
          subdep: {
            version: "2.0.0",
          },
        },
      },
    },
  });

  assert.equal(parsed.lockfileVersion, 1);
  assert.equal(parsed.packageCount, 2);
  assert.deepEqual(
    parsed.packages.map((pkg) => pkg.path),
    [
      "node_modules/leftpad",
      "node_modules/leftpad/node_modules/subdep",
    ],
  );
  assert.equal(parsed.packages[0].hasInstallScript, null);
});

test("parsePnpmLockfile handles pnpm lockfiles with direct dependencies and build requirements", () => {
  const parsed = parsePnpmLockfile(`
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      esbuild:
        specifier: 0.25.0
        version: 0.25.0
      react:
        specifier: 19.0.0
        version: 19.0.0

packages:
  esbuild@0.25.0:
    resolution:
      integrity: sha512-esbuild
      tarball: https://registry.npmjs.org/esbuild/-/esbuild-0.25.0.tgz
    requiresBuild: true
  react@19.0.0:
    resolution: {integrity: sha512-react}
`);

  assert.equal(parsed.packageManager, "pnpm");
  assert.equal(parsed.lockfileVersion, 9);
  assert.equal(parsed.packageCount, 2);
  assert.ok(parsed.directDependencyKeys.includes("esbuild@0.25.0"));
  assert.ok(parsed.directDependencyKeys.includes("react@19.0.0"));
  assert.equal(parsed.packages[0].name, "esbuild");
  assert.equal(parsed.packages[0].hasInstallScript, true);
  assert.equal(parsed.packages[0].path, "node_modules/esbuild");
  assert.equal(parsed.packages[1].integrity, "sha512-react");
});
