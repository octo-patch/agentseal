import { describe, it, expect } from "vitest";
import {
  parseResponse,
  detectProvider,
  stripModelPrefix,
  truncateContent,
  LLMJudge,
  MAX_CONTENT_BYTES,
  type LLMJudgeResult,
} from "../src/llm-judge.js";

// ═══════════════════════════════════════════════════════════════════════
// RESPONSE PARSING
// ═══════════════════════════════════════════════════════════════════════

describe("parseResponse", () => {
  it("parses direct JSON", () => {
    const raw = JSON.stringify({ verdict: "danger", confidence: 0.95, findings: [] });
    const result = parseResponse(raw, "gpt-4o", 100);
    expect(result.verdict).toBe("danger");
    expect(result.confidence).toBe(0.95);
    expect(result.tokens_used).toBe(100);
  });

  it("parses markdown JSON block", () => {
    const raw = 'Here is my analysis:\n```json\n{"verdict": "warning", "confidence": 0.7, "findings": []}\n```\nDone.';
    const result = parseResponse(raw, "gpt-4o", 50);
    expect(result.verdict).toBe("warning");
    expect(result.confidence).toBe(0.7);
  });

  it("parses JSON with surrounding text", () => {
    const raw = 'I found issues: {"verdict": "danger", "confidence": 0.8, "findings": [{"title": "Bad"}]}';
    const result = parseResponse(raw, "gpt-4o", 80);
    expect(result.verdict).toBe("danger");
    expect(result.findings).toHaveLength(1);
  });

  it("normalizes verdict synonyms", () => {
    expect(parseResponse('{"verdict": "malicious"}', "m", 0).verdict).toBe("danger");
    expect(parseResponse('{"verdict": "suspicious"}', "m", 0).verdict).toBe("warning");
    expect(parseResponse('{"verdict": "benign"}', "m", 0).verdict).toBe("safe");
    expect(parseResponse('{"verdict": "clean"}', "m", 0).verdict).toBe("safe");
    expect(parseResponse('{"verdict": "unsafe"}', "m", 0).verdict).toBe("danger");
    expect(parseResponse('{"verdict": "harmful"}', "m", 0).verdict).toBe("danger");
  });

  it("defaults unknown verdict to warning", () => {
    const result = parseResponse('{"verdict": "maybe"}', "m", 0);
    expect(result.verdict).toBe("warning");
  });

  it("clamps confidence to [0, 1]", () => {
    expect(parseResponse('{"verdict":"safe","confidence":5.0}', "m", 0).confidence).toBe(1.0);
    expect(parseResponse('{"verdict":"safe","confidence":-1.0}', "m", 0).confidence).toBe(0.0);
  });

  it("defaults confidence to 0.5 on invalid", () => {
    expect(parseResponse('{"verdict":"safe","confidence":"nope"}', "m", 0).confidence).toBe(0.5);
  });

  it("filters malformed findings", () => {
    const raw = JSON.stringify({
      verdict: "warning",
      findings: [
        { title: "Good finding", severity: "high" },
        { no_title: true },
        "not an object",
        null,
      ],
    });
    const result = parseResponse(raw, "m", 0);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.title).toBe("Good finding");
  });

  it("returns error for unparseable response", () => {
    const result = parseResponse("This is not JSON at all", "m", 0);
    expect(result.error).toBeTruthy();
    expect(result.error).toContain("Could not parse");
  });

  it("handles empty findings", () => {
    const result = parseResponse('{"verdict": "safe", "findings": []}', "m", 0);
    expect(result.findings).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// PROVIDER DETECTION
// ═══════════════════════════════════════════════════════════════════════

describe("detectProvider", () => {
  it("detects OpenAI models", () => {
    expect(detectProvider("gpt-4o")).toBe("openai");
    expect(detectProvider("gpt-4o-mini")).toBe("openai");
  });

  it("detects Anthropic models", () => {
    expect(detectProvider("claude-sonnet-4-5-20250929")).toBe("anthropic");
    expect(detectProvider("claude-3-haiku")).toBe("anthropic");
  });

  it("detects Ollama models", () => {
    expect(detectProvider("ollama/llama3.1:8b")).toBe("ollama");
  });

  it("detects OpenRouter models", () => {
    expect(detectProvider("openrouter/anthropic/claude-3.5-sonnet")).toBe("openrouter");
  });

  it("defaults to openai for unknown", () => {
    expect(detectProvider("my-custom-model")).toBe("openai");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// MODEL PREFIX STRIPPING
// ═══════════════════════════════════════════════════════════════════════

describe("stripModelPrefix", () => {
  it("strips ollama/ prefix", () => {
    expect(stripModelPrefix("ollama/llama3:8b", "ollama")).toBe("llama3:8b");
  });

  it("strips openrouter/ prefix", () => {
    expect(stripModelPrefix("openrouter/anthropic/claude", "openrouter")).toBe("anthropic/claude");
  });

  it("leaves other models alone", () => {
    expect(stripModelPrefix("gpt-4o", "openai")).toBe("gpt-4o");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// CONTENT TRUNCATION
// ═══════════════════════════════════════════════════════════════════════

describe("truncateContent", () => {
  it("returns short content unchanged", () => {
    expect(truncateContent("hello")).toBe("hello");
  });

  it("truncates long content", () => {
    const long = "a".repeat(MAX_CONTENT_BYTES + 1000);
    const result = truncateContent(long);
    expect(result.length).toBeLessThan(long.length);
    expect(result).toContain("[truncated]");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// LLM JUDGE CLASS
// ═══════════════════════════════════════════════════════════════════════

describe("LLMJudge", () => {
  it("creates with correct provider detection", () => {
    const judge = new LLMJudge({ model: "gpt-4o" });
    expect(judge.provider).toBe("openai");
    expect(judge.model).toBe("gpt-4o");
  });

  it("creates Anthropic judge", () => {
    const judge = new LLMJudge({ model: "claude-sonnet-4-5-20250929" });
    expect(judge.provider).toBe("anthropic");
  });

  it("creates Ollama judge with correct base URL", () => {
    const judge = new LLMJudge({ model: "ollama/llama3:8b" });
    expect(judge.provider).toBe("ollama");
    expect(judge.baseUrl).toBe("http://localhost:11434/v1");
  });

  it("custom base URL overrides default", () => {
    const judge = new LLMJudge({ model: "ollama/llama3:8b", baseUrl: "http://custom:1234/v1" });
    expect(judge.baseUrl).toBe("http://custom:1234/v1");
  });

  it("analyzeSkill returns safe for empty content", async () => {
    const judge = new LLMJudge({ model: "gpt-4o" });
    const result = await judge.analyzeSkill("", "test.md");
    expect(result.verdict).toBe("safe");
    expect(result.confidence).toBe(1.0);
  });

  it("analyzeSkill returns safe for whitespace content", async () => {
    const judge = new LLMJudge({ model: "gpt-4o" });
    const result = await judge.analyzeSkill("   \n\t  ", "test.md");
    expect(result.verdict).toBe("safe");
  });

  it("analyzeBatch returns empty for empty input", async () => {
    const judge = new LLMJudge({ model: "gpt-4o" });
    const results = await judge.analyzeBatch([]);
    expect(results).toEqual([]);
  });
});
