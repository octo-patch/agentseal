/**
 * Malicious skill blocklist client.
 *
 * Maintains a local cache of known-malicious skill hashes.
 * Auto-updates from agentseal.org on each run (with 1-hour cache TTL).
 * Works fully offline — falls back to cached or empty blocklist.
 *
 * Port of Python agentseal/blocklist.py — same logic.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export class Blocklist {
  static readonly REMOTE_URL = "https://agentseal.org/api/v1/blocklist/skills.json";
  static readonly CACHE_TTL = 3600; // 1 hour in seconds

  private _hashes = new Set<string>();
  private _loaded = false;
  private _cacheDir: string;
  private _cachePath: string;

  constructor(cacheDir?: string) {
    this._cacheDir = cacheDir ?? join(homedir(), ".agentseal");
    this._cachePath = join(this._cacheDir, "blocklist.json");
  }

  /** Override cache dir (useful for testing). */
  setCacheDir(dir: string): void {
    this._cacheDir = dir;
    this._cachePath = join(dir, "blocklist.json");
    this._loaded = false;
    this._hashes.clear();
  }

  private _load(): void {
    if (this._loaded) return;

    // Check cache freshness
    if (existsSync(this._cachePath)) {
      try {
        const age = (Date.now() / 1000) - statSync(this._cachePath).mtimeMs / 1000;
        if (age < Blocklist.CACHE_TTL) {
          this._loadFromFile(this._cachePath);
          this._loaded = true;
          return;
        }
      } catch {
        // ignore OS errors
      }
    }

    // Try remote fetch (synchronous for simplicity — matches Python behavior)
    if (this._tryRemoteFetch()) {
      this._loaded = true;
      return;
    }

    // Fall back to stale cache
    if (existsSync(this._cachePath)) {
      this._loadFromFile(this._cachePath);
    }

    this._loaded = true;
  }

  private _loadFromFile(path: string): void {
    try {
      const raw = readFileSync(path, "utf-8");
      const data = JSON.parse(raw);
      const hashes: string[] = data.sha256_hashes ?? [];
      this._hashes = new Set(hashes);
    } catch {
      this._hashes = new Set();
    }
  }

  private _tryRemoteFetch(): boolean {
    // Use synchronous XMLHttpRequest-like approach or just skip in Node
    // For Node.js, we'll do an async-compatible approach but cache the result
    // In practice, the remote fetch is best done async — for now, return false
    // and let the cache/seed hashes work. Users can call loadAsync() explicitly.
    return false;
  }

  /** Async remote fetch — call this once at startup if you want remote blocklist. */
  async loadAsync(): Promise<void> {
    if (this._loaded) return;

    // Check cache freshness
    if (existsSync(this._cachePath)) {
      try {
        const age = (Date.now() / 1000) - statSync(this._cachePath).mtimeMs / 1000;
        if (age < Blocklist.CACHE_TTL) {
          this._loadFromFile(this._cachePath);
          this._loaded = true;
          return;
        }
      } catch {
        // ignore
      }
    }

    // Try remote fetch
    try {
      const resp = await fetch(Blocklist.REMOTE_URL, {
        signal: AbortSignal.timeout(5000),
      });
      if (resp.ok) {
        const data = await resp.json() as { sha256_hashes?: string[] };
        this._hashes = new Set(data.sha256_hashes ?? []);
        // Cache locally
        mkdirSync(this._cacheDir, { recursive: true });
        writeFileSync(this._cachePath, JSON.stringify(data), "utf-8");
        this._loaded = true;
        return;
      }
    } catch {
      // Network unavailable — that's fine
    }

    // Fall back to stale cache
    if (existsSync(this._cachePath)) {
      this._loadFromFile(this._cachePath);
    }

    this._loaded = true;
  }

  /** Check if a SHA256 hash is in the blocklist. */
  isBlocked(sha256: string): boolean {
    this._load();
    return this._hashes.has(sha256.toLowerCase());
  }

  /** Number of hashes in the blocklist. */
  get size(): number {
    this._load();
    return this._hashes.size;
  }

  /** Manually add hashes (for testing or seed data). */
  addHashes(hashes: string[]): void {
    for (const h of hashes) {
      this._hashes.add(h.toLowerCase());
    }
  }
}

/** Compute SHA256 hash of content. */
export function sha256(content: string): string {
  return createHash("sha256").update(content, "utf-8").digest("hex");
}
