import assert from "node:assert/strict";
import test from "node:test";

import { parseLockfile } from "../src/lib/lockfile.js";

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
