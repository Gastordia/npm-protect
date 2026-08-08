import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

export function resolveCacheSettings(flags) {
  if (typeof flags["cache-dir"] !== "string" || flags["cache-dir"].length === 0) {
    return null;
  }

  const ttlHours =
    typeof flags["cache-ttl-hours"] === "string" || typeof flags["cache-ttl-hours"] === "number"
      ? Number(flags["cache-ttl-hours"])
      : 24;

  return {
    dir: path.resolve(String(flags["cache-dir"])),
    ttlMs: Number.isFinite(ttlHours) && ttlHours >= 0 ? ttlHours * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
  };
}

export async function readCache(cache, key) {
  if (!cache) {
    return null;
  }

  const filePath = cacheFilePath(cache.dir, key);

  try {
    const parsed = JSON.parse(await readFile(filePath, "utf8"));
    if (!isFresh(parsed, cache.ttlMs)) {
      return null;
    }

    return parsed;
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return null;
    }

    return null;
  }
}

export async function writeCache(cache, key, record) {
  if (!cache) {
    return false;
  }

  const filePath = cacheFilePath(cache.dir, key);

  try {
    await mkdir(cache.dir, { recursive: true });
    await writeFile(
      filePath,
      JSON.stringify(
        {
          storedAt: Date.now(),
          ...record,
        },
        null,
        2,
      ),
      "utf8",
    );
    return true;
  } catch {
    return false;
  }
}

export function buildCacheKey(parts) {
  return createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}

function cacheFilePath(cacheDir, key) {
  return path.join(cacheDir, `${key}.json`);
}

function isFresh(record, ttlMs) {
  if (!record || typeof record.storedAt !== "number") {
    return false;
  }

  if (ttlMs === 0) {
    return false;
  }

  return Date.now() - record.storedAt <= ttlMs;
}
