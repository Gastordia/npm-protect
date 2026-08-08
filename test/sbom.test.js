import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import { loadProjectSnapshot } from "../src/lib/project.js";
import { buildCycloneDxSbom } from "../src/lib/sbom.js";

const fixturesDir = path.join(process.cwd(), "test", "fixtures");

test("buildCycloneDxSbom includes root metadata and direct dependencies", async () => {
  const project = await loadProjectSnapshot(path.join(fixturesDir, "block-project"));
  const bom = buildCycloneDxSbom(project);

  assert.equal(bom.bomFormat, "CycloneDX");
  assert.equal(bom.specVersion, "1.6");
  assert.equal(bom.metadata.component.name, "block-project");
  assert.ok(
    bom.metadata.properties.some((property) => property.name === "npm-protect:lockfilePath"),
  );
  assert.ok(
    bom.components.some(
      (component) =>
        component.name === "esbuild" &&
        component.properties.some(
          (property) =>
            property.name === "npm-protect:isDirectDependency" && property.value === "true",
        ),
    ),
  );
  assert.ok(
    bom.dependencies[0].dependsOn.some((ref) => ref === "pkg:npm/esbuild@0.25.0"),
  );
});
