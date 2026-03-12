import { describe, it, expect } from "vitest";
import {
  PROFILES,
  resolveProfile,
  applyProfile,
  listProfiles,
  type ProfileConfig,
} from "../src/profiles.js";

// ═══════════════════════════════════════════════════════════════════════
// resolveProfile
// ═══════════════════════════════════════════════════════════════════════

describe("resolveProfile", () => {
  it("resolves all known profiles", () => {
    for (const name of Object.keys(PROFILES)) {
      const cfg = resolveProfile(name);
      expect(cfg).toBe(PROFILES[name]);
    }
  });

  it("throws for unknown profile", () => {
    expect(() => resolveProfile("nope")).toThrow(/Unknown profile 'nope'/);
  });

  it("error message lists valid profiles", () => {
    try {
      resolveProfile("nope");
    } catch (e: any) {
      for (const name of Object.keys(PROFILES)) {
        expect(e.message).toContain(name);
      }
    }
  });

  it("is case-insensitive", () => {
    expect(resolveProfile("Quick")).toBe(PROFILES.quick);
    expect(resolveProfile("FULL")).toBe(PROFILES.full);
    expect(resolveProfile("Code-Agent")).toBe(PROFILES["code-agent"]);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// applyProfile
// ═══════════════════════════════════════════════════════════════════════

function makeOpts(overrides: Record<string, any> = {}): Record<string, any> {
  return {
    adaptive: false, semantic: false, mcp: false, rag: false,
    multimodal: false, genome: false, useCanaryOnly: false,
    concurrency: undefined, timeout: undefined, output: undefined, minScore: undefined,
    ...overrides,
  };
}

describe("applyProfile", () => {
  it("sets flags from profile", () => {
    const opts = makeOpts();
    applyProfile(opts, resolveProfile("code-agent"));
    expect(opts.adaptive).toBe(true);
    expect(opts.mcp).toBe(true);
    expect(opts.semantic).toBe(true);
    expect(opts.rag).toBe(false);
    expect(opts.multimodal).toBe(false);
  });

  it("explicit user flag wins", () => {
    const opts = makeOpts({ adaptive: true });
    applyProfile(opts, resolveProfile("default"));
    expect(opts.adaptive).toBe(true);
  });

  it("does not set undefined optional fields", () => {
    const opts = makeOpts();
    applyProfile(opts, resolveProfile("default"));
    expect(opts.concurrency).toBeUndefined();
    expect(opts.timeout).toBeUndefined();
    expect(opts.output).toBeUndefined();
  });

  it("sets concurrency from profile", () => {
    const opts = makeOpts();
    applyProfile(opts, resolveProfile("quick"));
    expect(opts.concurrency).toBe(5);
    expect(opts.timeout).toBe(15);
  });

  it("user concurrency wins over profile", () => {
    const opts = makeOpts({ concurrency: 10 });
    applyProfile(opts, resolveProfile("quick"));
    expect(opts.concurrency).toBe(10);
  });

  it("default profile changes nothing", () => {
    const opts = makeOpts();
    const original = { ...opts };
    applyProfile(opts, resolveProfile("default"));
    expect(opts).toEqual(original);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Profile-specific
// ═══════════════════════════════════════════════════════════════════════

describe("profile presets", () => {
  it("quick profile uses canary only", () => {
    const cfg = resolveProfile("quick");
    expect(cfg.useCanaryOnly).toBe(true);
    expect(cfg.concurrency).toBe(5);
    expect(cfg.timeout).toBe(15);
  });

  it("full profile enables all flags", () => {
    const cfg = resolveProfile("full");
    expect(cfg.adaptive).toBe(true);
    expect(cfg.semantic).toBe(true);
    expect(cfg.mcp).toBe(true);
    expect(cfg.rag).toBe(true);
    expect(cfg.multimodal).toBe(true);
    expect(cfg.genome).toBe(true);
  });

  it("ci profile sets output json", () => {
    const cfg = resolveProfile("ci");
    expect(cfg.output).toBe("json");
    expect(cfg.concurrency).toBe(5);
    expect(cfg.timeout).toBe(15);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// listProfiles
// ═══════════════════════════════════════════════════════════════════════

describe("listProfiles", () => {
  it("returns string containing all profile names", () => {
    const result = listProfiles();
    expect(typeof result).toBe("string");
    for (const name of Object.keys(PROFILES)) {
      expect(result).toContain(name);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Misc
// ═══════════════════════════════════════════════════════════════════════

describe("misc", () => {
  it("profiles dict has at least 8 entries", () => {
    expect(Object.keys(PROFILES).length).toBeGreaterThanOrEqual(8);
  });

  it("default ProfileConfig values", () => {
    const cfg: ProfileConfig = { description: "test" };
    expect(cfg.adaptive).toBeUndefined();
    expect(cfg.semantic).toBeUndefined();
    expect(cfg.concurrency).toBeUndefined();
  });
});
