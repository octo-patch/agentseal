/**
 * Integration tests — verify the package's build output, exports, and usability.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, existsSync, statSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(__dirname, "..");
const DIST = resolve(ROOT, "dist");

// ═══════════════════════════════════════════════════════════════════════
// 1. Build output files exist and are reasonable
// ═══════════════════════════════════════════════════════════════════════

describe("Build output", () => {
  const expectedFiles = [
    "index.js",
    "index.cjs",
    "index.d.ts",
    "index.d.cts",
    "agentseal.js",
    "index.js.map",
    "index.cjs.map",
  ];

  for (const file of expectedFiles) {
    it(`dist/${file} exists`, () => {
      expect(existsSync(resolve(DIST, file))).toBe(true);
    });
  }

  it("CLI has shebang line", () => {
    const cli = readFileSync(resolve(DIST, "agentseal.js"), "utf-8");
    expect(cli.startsWith("#!/usr/bin/env node")).toBe(true);
  });

  it("dist/index.js is reasonable size (>10KB, <500KB)", () => {
    const stat = statSync(resolve(DIST, "index.js"));
    expect(stat.size).toBeGreaterThan(10_000);
    expect(stat.size).toBeLessThan(500_000);
  });

  it("dist/index.cjs is reasonable size (>10KB, <500KB)", () => {
    const stat = statSync(resolve(DIST, "index.cjs"));
    expect(stat.size).toBeGreaterThan(10_000);
    expect(stat.size).toBeLessThan(500_000);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 2. package.json correctness
// ═══════════════════════════════════════════════════════════════════════

describe("package.json", () => {
  const pkg = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf-8"));

  it("main points to existing file", () => {
    expect(existsSync(resolve(ROOT, pkg.main))).toBe(true);
  });

  it("module points to existing file", () => {
    expect(existsSync(resolve(ROOT, pkg.module))).toBe(true);
  });

  it("types points to existing file", () => {
    expect(existsSync(resolve(ROOT, pkg.types))).toBe(true);
  });

  it("bin entry points to existing file", () => {
    expect(existsSync(resolve(ROOT, pkg.bin.agentseal))).toBe(true);
  });

  it("exports.import.types points to existing file", () => {
    expect(existsSync(resolve(ROOT, pkg.exports["."].import.types))).toBe(true);
  });

  it("exports.import.default points to existing file", () => {
    expect(existsSync(resolve(ROOT, pkg.exports["."].import.default))).toBe(true);
  });

  it("exports.require.types points to existing file", () => {
    expect(existsSync(resolve(ROOT, pkg.exports["."].require.types))).toBe(true);
  });

  it("exports.require.default points to existing file", () => {
    expect(existsSync(resolve(ROOT, pkg.exports["."].require.default))).toBe(true);
  });

  it("root LICENSE file exists", () => {
    expect(existsSync(resolve(ROOT, "..", "LICENSE"))).toBe(true);
  });

  it("engines.node >= 18", () => {
    expect(pkg.engines.node).toBe(">=18.0.0");
  });

  it("all peer dependencies are optional", () => {
    for (const dep of Object.keys(pkg.peerDependencies)) {
      expect(pkg.peerDependenciesMeta[dep]?.optional).toBe(true);
    }
  });

  it("repository URL uses git+https format or plain https", () => {
    expect(pkg.repository.url).toMatch(/^(git\+)?https:\/\//);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 3. Export completeness — every barrel export is importable
// ═══════════════════════════════════════════════════════════════════════

describe("Export completeness", () => {
  it("ESM exports all expected symbols", async () => {
    const m = await import("../dist/index.js");
    const keys = Object.keys(m);

    // Core types/const objects
    expect(keys).toContain("Verdict");
    expect(keys).toContain("Severity");
    expect(keys).toContain("TrustLevel");
    expect(keys).toContain("trustLevelFromScore");

    // Errors
    expect(keys).toContain("AgentSealError");
    expect(keys).toContain("ProbeTimeoutError");
    expect(keys).toContain("ProviderError");
    expect(keys).toContain("ValidationError");

    // Constants
    expect(keys).toContain("EXTRACTION_WEIGHT");
    expect(keys).toContain("INJECTION_WEIGHT");
    expect(keys).toContain("BOUNDARY_WEIGHT");
    expect(keys).toContain("CONSISTENCY_WEIGHT");
    expect(keys).toContain("BOUNDARY_CATEGORIES");
    expect(keys).toContain("REFUSAL_PHRASES");
    expect(keys).toContain("COMMON_WORDS");
    expect(keys).toContain("SEMANTIC_HIGH_THRESHOLD");
    expect(keys).toContain("SEMANTIC_MODERATE_THRESHOLD");

    // Validator
    expect(keys).toContain("AgentValidator");

    // Scoring
    expect(keys).toContain("verdictScore");
    expect(keys).toContain("computeScores");

    // Fingerprinting
    expect(keys).toContain("fingerprintDefense");

    // Detection
    expect(keys).toContain("detectCanary");
    expect(keys).toContain("isRefusal");
    expect(keys).toContain("detectExtraction");
    expect(keys).toContain("extractUniquePhrases");
    expect(keys).toContain("computeSemanticSimilarity");
    expect(keys).toContain("fuseVerdicts");
    expect(keys).toContain("detectExtractionWithSemantic");

    // Probes
    expect(keys).toContain("generateCanary");
    expect(keys).toContain("buildExtractionProbes");
    expect(keys).toContain("buildInjectionProbes");

    // Mutations
    expect(keys).toContain("TRANSFORMS");
    expect(keys).toContain("base64Wrap");
    expect(keys).toContain("rot13Wrap");
    expect(keys).toContain("unicodeHomoglyphs");
    expect(keys).toContain("zeroWidthInject");
    expect(keys).toContain("leetspeak");
    expect(keys).toContain("caseScramble");
    expect(keys).toContain("reverseEmbed");
    expect(keys).toContain("prefixPadding");
    expect(keys).toContain("generateMutations");

    // Providers
    expect(keys).toContain("fromOpenAI");
    expect(keys).toContain("fromAnthropic");
    expect(keys).toContain("fromVercelAI");
    expect(keys).toContain("fromLangChain");
    expect(keys).toContain("fromEndpoint");
    expect(keys).toContain("fromOllama");

    // Remediation
    expect(keys).toContain("generateRemediation");

    // Compare
    expect(keys).toContain("compareReports");
  });

  it("CJS exports match ESM exports", async () => {
    const esm = await import("../dist/index.js");
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const cjs = require("../dist/index.cjs");

    const esmKeys = Object.keys(esm).filter(k => k !== "default").sort();
    const cjsKeys = Object.keys(cjs).filter(k => k !== "default").sort();
    expect(cjsKeys).toEqual(esmKeys);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 4. d.ts file contains all exported types
// ═══════════════════════════════════════════════════════════════════════

describe("Type declarations", () => {
  const dts = readFileSync(resolve(DIST, "index.d.ts"), "utf-8");

  const expectedTypes = [
    "ChatFn", "EmbedFn", "ProgressFn", "Probe", "ProbeResult",
    "ScanReport", "ScoreBreakdown", "DefenseProfile", "ValidatorOptions",
    "AffectedProbe", "RemediationItem", "RemediationReport", "CompareResult",
  ];

  for (const t of expectedTypes) {
    it(`exports type ${t}`, () => {
      expect(dts).toContain(t);
    });
  }

  it("d.ts and d.cts have the same content", () => {
    const dcts = readFileSync(resolve(DIST, "index.d.cts"), "utf-8");
    expect(dts).toEqual(dcts);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 5. Runtime smoke tests on exported functions
// ═══════════════════════════════════════════════════════════════════════

describe("Runtime smoke tests", () => {
  it("Verdict const object has expected values", async () => {
    const { Verdict } = await import("../dist/index.js");
    expect(Verdict.BLOCKED).toBe("blocked");
    expect(Verdict.LEAKED).toBe("leaked");
    expect(Verdict.PARTIAL).toBe("partial");
    expect(Verdict.ERROR).toBe("error");
  });

  it("trustLevelFromScore works", async () => {
    const { trustLevelFromScore } = await import("../dist/index.js");
    expect(trustLevelFromScore(95)).toBe("excellent");
    expect(trustLevelFromScore(75)).toBe("high");
    expect(trustLevelFromScore(55)).toBe("medium");
    expect(trustLevelFromScore(35)).toBe("low");
    expect(trustLevelFromScore(10)).toBe("critical");
  });

  it("verdictScore returns numeric", async () => {
    const { verdictScore } = await import("../dist/index.js");
    const score = verdictScore("blocked", 0.9);
    expect(typeof score).toBe("number");
    expect(score).toBeGreaterThan(0);
  });

  it("generateCanary returns unique strings", async () => {
    const { generateCanary } = await import("../dist/index.js");
    const a = generateCanary();
    const b = generateCanary();
    expect(typeof a).toBe("string");
    expect(a.length).toBeGreaterThan(5);
    expect(a).not.toBe(b);
  });

  it("buildExtractionProbes returns non-empty array", async () => {
    const { buildExtractionProbes } = await import("../dist/index.js");
    const probes = buildExtractionProbes();
    expect(Array.isArray(probes)).toBe(true);
    expect(probes.length).toBeGreaterThan(0);
    expect(probes[0]).toHaveProperty("probe_id");
    expect(probes[0]).toHaveProperty("payload");
  });

  it("buildInjectionProbes returns non-empty array", async () => {
    const { buildInjectionProbes } = await import("../dist/index.js");
    const probes = buildInjectionProbes();
    expect(Array.isArray(probes)).toBe(true);
    expect(probes.length).toBeGreaterThan(0);
    expect(probes[0]).toHaveProperty("canary");
  });

  it("error classes extend Error", async () => {
    const { AgentSealError, ProbeTimeoutError, ProviderError, ValidationError } = await import("../dist/index.js");
    expect(new AgentSealError("test")).toBeInstanceOf(Error);
    expect(new ProbeTimeoutError("p1", 5000)).toBeInstanceOf(AgentSealError);
    expect(new ProviderError("openai", "fail")).toBeInstanceOf(AgentSealError);
    expect(new ValidationError("bad")).toBeInstanceOf(AgentSealError);
  });

  it("TRANSFORMS has all 8 mutation functions", async () => {
    const { TRANSFORMS } = await import("../dist/index.js");
    expect(Object.keys(TRANSFORMS).length).toBe(8);
    for (const fn of Object.values(TRANSFORMS)) {
      expect(typeof fn).toBe("function");
    }
  });

  it("AgentValidator constructor works with mock chatFn", async () => {
    const { AgentValidator } = await import("../dist/index.js");
    const mockChat = async () => "I cannot share that information.";
    const validator = new AgentValidator({ agentFn: mockChat });
    expect(validator).toBeDefined();
    expect(typeof validator.run).toBe("function");
  });
});
