import { describe, it, expect } from "vitest";
import {
  classifyServer,
  analyzeToxicFlows,
  KNOWN_SERVER_LABELS,
  LABEL_PUBLIC_SINK,
  LABEL_DESTRUCTIVE,
  LABEL_UNTRUSTED,
  LABEL_PRIVATE,
} from "../src/toxic-flows.js";

// ═══════════════════════════════════════════════════════════════════════
// SERVER CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════

describe("classifyServer", () => {
  it("classifies filesystem server", () => {
    const labels = classifyServer({ name: "filesystem", command: "npx" });
    expect(labels.has(LABEL_PRIVATE)).toBe(true);
    expect(labels.has(LABEL_DESTRUCTIVE)).toBe(true);
  });

  it("classifies slack as public sink", () => {
    const labels = classifyServer({ name: "slack", command: "npx" });
    expect(labels.has(LABEL_PUBLIC_SINK)).toBe(true);
  });

  it("classifies fetch as untrusted", () => {
    const labels = classifyServer({ name: "fetch", command: "npx" });
    expect(labels.has(LABEL_UNTRUSTED)).toBe(true);
  });

  it("classifies by substring match in name", () => {
    const labels = classifyServer({ name: "my-slack-bot", command: "node" });
    expect(labels.has(LABEL_PUBLIC_SINK)).toBe(true);
  });

  it("classifies by command/args", () => {
    const labels = classifyServer({
      name: "custom",
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem"],
    });
    expect(labels.has(LABEL_PRIVATE)).toBe(true);
  });

  it("uses heuristics for unknown servers", () => {
    const labels = classifyServer({ name: "my-web-scraper", command: "node" });
    expect(labels.has(LABEL_UNTRUSTED)).toBe(true);
  });

  it("returns empty for truly unknown server", () => {
    const labels = classifyServer({ name: "xyzzy", command: "custom-binary" });
    expect(labels.size).toBe(0);
  });

  it("classifies database servers", () => {
    const labels = classifyServer({ name: "postgres", command: "npx" });
    expect(labels.has(LABEL_PRIVATE)).toBe(true);
    expect(labels.has(LABEL_DESTRUCTIVE)).toBe(true);
  });

  it("classifies github as both private and sink", () => {
    const labels = classifyServer({ name: "github", command: "npx" });
    expect(labels.has(LABEL_PUBLIC_SINK)).toBe(true);
    expect(labels.has(LABEL_PRIVATE)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// TOXIC FLOW ANALYSIS
// ═══════════════════════════════════════════════════════════════════════

describe("analyzeToxicFlows", () => {
  it("returns empty for single server", () => {
    const flows = analyzeToxicFlows([{ name: "filesystem", command: "npx" }]);
    expect(flows).toEqual([]);
  });

  it("returns empty for two safe servers", () => {
    const flows = analyzeToxicFlows([
      { name: "xyzzy1", command: "a" },
      { name: "xyzzy2", command: "b" },
    ]);
    expect(flows).toEqual([]);
  });

  it("detects data exfiltration (private + sink)", () => {
    const flows = analyzeToxicFlows([
      { name: "filesystem", command: "npx" },
      { name: "slack", command: "npx" },
    ]);
    expect(flows.length).toBeGreaterThanOrEqual(1);
    expect(flows.some((f) => f.risk_type === "data_exfiltration")).toBe(true);
    expect(flows[0]!.risk_level).toBe("high");
  });

  it("detects remote code execution (untrusted + destructive)", () => {
    const flows = analyzeToxicFlows([
      { name: "fetch", command: "npx" },
      { name: "shell", command: "bash" },
    ]);
    expect(flows.some((f) => f.risk_type === "remote_code_execution")).toBe(true);
  });

  it("detects full chain (untrusted + private + sink)", () => {
    const flows = analyzeToxicFlows([
      { name: "fetch", command: "npx" },
      { name: "filesystem", command: "npx" },
      { name: "slack", command: "npx" },
    ]);
    expect(flows).toHaveLength(1);
    expect(flows[0]!.risk_type).toBe("full_chain");
  });

  it("full chain subsumes individual combos", () => {
    const flows = analyzeToxicFlows([
      { name: "puppeteer", command: "npx" },
      { name: "filesystem", command: "npx" },
      { name: "email", command: "npx" },
    ]);
    // Should only have full_chain, not individual combos
    expect(flows.filter((f) => f.risk_type === "full_chain")).toHaveLength(1);
    expect(flows.filter((f) => f.risk_type === "data_exfiltration")).toHaveLength(0);
  });

  it("detects data destruction (private + destructive from different servers)", () => {
    const flows = analyzeToxicFlows([
      { name: "memory", command: "npx" },       // private only
      { name: "docker", command: "npx" },        // destructive only
    ]);
    expect(flows.some((f) => f.risk_type === "data_destruction")).toBe(true);
    expect(flows.find((f) => f.risk_type === "data_destruction")!.risk_level).toBe("medium");
  });

  it("does NOT flag data destruction when same server has both labels", () => {
    // filesystem has both private + destructive, but it's the same server
    const flows = analyzeToxicFlows([
      { name: "filesystem", command: "npx" },
      { name: "xyzzy", command: "unknown" },
    ]);
    expect(flows.some((f) => f.risk_type === "data_destruction")).toBe(false);
  });

  it("includes remediation text", () => {
    const flows = analyzeToxicFlows([
      { name: "filesystem", command: "npx" },
      { name: "slack", command: "npx" },
    ]);
    expect(flows[0]!.remediation.length).toBeGreaterThan(10);
  });

  it("includes servers_involved", () => {
    const flows = analyzeToxicFlows([
      { name: "filesystem", command: "npx" },
      { name: "slack", command: "npx" },
    ]);
    expect(flows[0]!.servers_involved).toContain("filesystem");
    expect(flows[0]!.servers_involved).toContain("slack");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

describe("KNOWN_SERVER_LABELS", () => {
  it("has many entries", () => {
    expect(Object.keys(KNOWN_SERVER_LABELS).length).toBeGreaterThan(40);
  });
});
