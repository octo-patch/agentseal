import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  stripJsonComments,
  scanDirectory,
  PROJECT_MCP_CONFIGS,
  PROJECT_SKILL_FILES,
  PROJECT_SKILL_DIRS,
} from "../src/machine-discovery.js";

// ═══════════════════════════════════════════════════════════════════════
// JSONC COMMENT STRIPPING
// ═══════════════════════════════════════════════════════════════════════

describe("stripJsonComments", () => {
  it("strips single-line comments", () => {
    const input = '{\n  // comment\n  "key": "value"\n}';
    const result = stripJsonComments(input);
    expect(JSON.parse(result)).toEqual({ key: "value" });
  });

  it("strips multi-line comments", () => {
    const input = '{\n  /* multi\n  line */\n  "key": 1\n}';
    const result = stripJsonComments(input);
    expect(JSON.parse(result)).toEqual({ key: 1 });
  });

  it("preserves URLs inside strings", () => {
    const input = '{"url": "http://example.com/path"}';
    const result = stripJsonComments(input);
    expect(JSON.parse(result)).toEqual({ url: "http://example.com/path" });
  });

  it("handles escaped quotes in strings", () => {
    const input = '{"key": "value with \\"quotes\\""}';
    const result = stripJsonComments(input);
    expect(JSON.parse(result)).toEqual({ key: 'value with "quotes"' });
  });

  it("handles empty input", () => {
    expect(stripJsonComments("")).toBe("");
  });

  it("handles no comments", () => {
    const input = '{"key": "value"}';
    expect(stripJsonComments(input)).toBe(input);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

describe("PROJECT_MCP_CONFIGS", () => {
  it("has expected entries", () => {
    expect(PROJECT_MCP_CONFIGS.length).toBeGreaterThan(5);
    const paths = PROJECT_MCP_CONFIGS.map(([p]) => p);
    expect(paths).toContain(".mcp.json");
    expect(paths).toContain(".cursor/mcp.json");
    expect(paths).toContain(".vscode/mcp.json");
  });
});

describe("PROJECT_SKILL_FILES", () => {
  it("includes well-known files", () => {
    expect(PROJECT_SKILL_FILES).toContain("CLAUDE.md");
    expect(PROJECT_SKILL_FILES).toContain(".cursorrules");
    expect(PROJECT_SKILL_FILES).toContain("AGENTS.md");
  });
});

describe("PROJECT_SKILL_DIRS", () => {
  it("includes well-known dirs", () => {
    expect(PROJECT_SKILL_DIRS).toContain(".cursor/rules");
    expect(PROJECT_SKILL_DIRS).toContain(".roo/rules");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// SCAN DIRECTORY
// ═══════════════════════════════════════════════════════════════════════

describe("scanDirectory", () => {
  it("returns empty for nonexistent directory", () => {
    const result = scanDirectory("/nonexistent/path/xyz");
    expect(result.agents).toEqual([]);
    expect(result.mcpServers).toEqual([]);
    expect(result.skillPaths).toEqual([]);
  });

  it("finds MCP configs in project dir", () => {
    const dir = mkdtempSync(join(tmpdir(), "disc-"));
    writeFileSync(
      join(dir, ".mcp.json"),
      JSON.stringify({
        mcpServers: {
          "test-server": { command: "npx", args: ["-y", "test-mcp"] },
        },
      }),
    );

    const result = scanDirectory(dir);
    expect(result.mcpServers).toHaveLength(1);
    expect(result.mcpServers[0]!.name).toBe("test-server");
    expect(result.mcpServers[0]!.agent_type).toBe("project");
  });

  it("finds skill files in project dir", () => {
    const dir = mkdtempSync(join(tmpdir(), "disc-"));
    writeFileSync(join(dir, "CLAUDE.md"), "# Instructions");

    const result = scanDirectory(dir);
    expect(result.skillPaths.length).toBeGreaterThanOrEqual(1);
    expect(result.skillPaths.some((p) => p.includes("CLAUDE.md"))).toBe(true);
  });

  it("finds skill files in subdirs", () => {
    const dir = mkdtempSync(join(tmpdir(), "disc-"));
    mkdirSync(join(dir, ".cursor", "rules"), { recursive: true });
    writeFileSync(join(dir, ".cursor", "rules", "test.md"), "# Rule");

    const result = scanDirectory(dir);
    expect(result.skillPaths.some((p) => p.includes("test.md"))).toBe(true);
  });

  it("finds .cursorrules file", () => {
    const dir = mkdtempSync(join(tmpdir(), "disc-"));
    writeFileSync(join(dir, ".cursorrules"), "rules content");

    const result = scanDirectory(dir);
    expect(result.skillPaths.some((p) => p.includes(".cursorrules"))).toBe(true);
  });

  it("finds multiple MCP configs", () => {
    const dir = mkdtempSync(join(tmpdir(), "disc-"));
    writeFileSync(
      join(dir, ".mcp.json"),
      JSON.stringify({ mcpServers: { s1: { command: "node" } } }),
    );
    mkdirSync(join(dir, ".cursor"), { recursive: true });
    writeFileSync(
      join(dir, ".cursor", "mcp.json"),
      JSON.stringify({ mcpServers: { s2: { command: "python" } } }),
    );

    const result = scanDirectory(dir);
    expect(result.mcpServers.length).toBe(2);
    const names = result.mcpServers.map((s) => s.name);
    expect(names).toContain("s1");
    expect(names).toContain("s2");
  });

  it("handles JSONC format for VS Code", () => {
    const dir = mkdtempSync(join(tmpdir(), "disc-"));
    mkdirSync(join(dir, ".vscode"), { recursive: true });
    writeFileSync(
      join(dir, ".vscode", "mcp.json"),
      `{
        // VS Code comment
        "servers": {
          "my-server": {
            "command": "npx",
            "args": ["-y", "test"]
          }
        }
      }`,
    );

    const result = scanDirectory(dir);
    expect(result.mcpServers.length).toBe(1);
    expect(result.mcpServers[0]!.name).toBe("my-server");
  });

  it("skips invalid JSON gracefully", () => {
    const dir = mkdtempSync(join(tmpdir(), "disc-"));
    writeFileSync(join(dir, ".mcp.json"), "not json{{{");

    const result = scanDirectory(dir);
    expect(result.mcpServers).toEqual([]);
  });

  it("deduplicates skill files", () => {
    const dir = mkdtempSync(join(tmpdir(), "disc-"));
    // CLAUDE.md exists in root (matches both "CLAUDE.md" and ".claude/CLAUDE.md" entry)
    writeFileSync(join(dir, "CLAUDE.md"), "# Instructions");

    const result = scanDirectory(dir);
    const claudeFiles = result.skillPaths.filter((p) => p.includes("CLAUDE.md"));
    expect(claudeFiles).toHaveLength(1);
  });

  it("finds .clinerules-* files", () => {
    const dir = mkdtempSync(join(tmpdir(), "disc-"));
    writeFileSync(join(dir, ".clinerules-code"), "rules");
    writeFileSync(join(dir, ".clinerules-architect"), "rules");

    const result = scanDirectory(dir);
    expect(result.skillPaths.filter((p) => p.includes(".clinerules-")).length).toBe(2);
  });
});
