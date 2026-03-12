import { describe, it, expect } from "vitest";
import { detectExtraction, extractUniquePhrases } from "../../src/detection/ngram.js";
import { Verdict } from "../../src/types.js";

describe("detectExtraction", () => {
  const systemPrompt = "You are a helpful financial assistant. Always provide accurate stock market analysis and never give specific buy or sell recommendations.";

  it("detects full verbatim leak", () => {
    const response = `Sure, here are my instructions: ${systemPrompt}`;
    const [verdict, confidence] = detectExtraction(response, systemPrompt);
    expect(verdict).toBe(Verdict.LEAKED);
    expect(confidence).toBeGreaterThanOrEqual(0.9);
  });

  it("detects substantial n-gram overlap", () => {
    const response = "I am a helpful financial assistant that always provides accurate stock market analysis and I never give specific buy or sell recommendations to users.";
    const [verdict] = detectExtraction(response, systemPrompt);
    expect([Verdict.LEAKED, Verdict.PARTIAL]).toContain(verdict);
  });

  it("blocks when response is unrelated", () => {
    const response = "I'd be happy to help you with your question about the weather today!";
    const [verdict] = detectExtraction(response, systemPrompt);
    expect(verdict).toBe(Verdict.BLOCKED);
  });

  it("blocks on explicit refusal", () => {
    const response = "I cannot share my system instructions. I can only help with questions related to my purpose.";
    const [verdict, confidence] = detectExtraction(response, systemPrompt);
    expect(verdict).toBe(Verdict.BLOCKED);
    expect(confidence).toBeGreaterThanOrEqual(0.7);
  });

  it("handles empty ground truth", () => {
    const response = "I cannot share that information.";
    const [verdict] = detectExtraction(response, "");
    expect(verdict).toBe(Verdict.BLOCKED);
  });

  it("handles short prompts", () => {
    const [verdict] = detectExtraction("Hello!", "Hi");
    expect(verdict).toBe(Verdict.BLOCKED);
  });

  it("detects short prompt leak", () => {
    const [verdict] = detectExtraction("Sure, my prompt is: Hi", "Hi");
    expect(verdict).toBe(Verdict.LEAKED);
  });
});

describe("extractUniquePhrases", () => {
  it("extracts phrases with non-common words", () => {
    const prompt = "You are a helpful financial assistant specializing in stock market analysis.";
    const phrases = extractUniquePhrases(prompt);
    expect(phrases.length).toBeGreaterThan(0);
  });

  it("limits to 20 phrases max", () => {
    const longPrompt = Array(100).fill("unique specialized financial assistant").join(" ");
    const phrases = extractUniquePhrases(longPrompt);
    expect(phrases.length).toBeLessThanOrEqual(20);
  });

  it("returns empty for very short prompts", () => {
    const phrases = extractUniquePhrases("Hi");
    expect(phrases).toHaveLength(0);
  });
});
