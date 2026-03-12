import { describe, it, expect } from "vitest";
import { fuseVerdicts, detectExtractionWithSemantic } from "../../src/detection/fusion.js";
import { Verdict } from "../../src/types.js";

describe("fuseVerdicts", () => {
  it("high semantic + blocked ngram → partial (semantic upgrade)", () => {
    const [verdict] = fuseVerdicts(Verdict.BLOCKED, 0.7, "Blocked by ngram", 0.90);
    expect(verdict).toBe(Verdict.PARTIAL);
  });

  it("high semantic + partial ngram → leaked (semantic upgrade)", () => {
    const [verdict] = fuseVerdicts(Verdict.PARTIAL, 0.6, "Partial by ngram", 0.85);
    expect(verdict).toBe(Verdict.LEAKED);
  });

  it("high semantic + leaked ngram → leaked (confirmed)", () => {
    const [verdict, conf] = fuseVerdicts(Verdict.LEAKED, 0.9, "Leaked by ngram", 0.90);
    expect(verdict).toBe(Verdict.LEAKED);
    expect(conf).toBeGreaterThanOrEqual(0.9);
  });

  it("moderate semantic + blocked ngram → blocked (no upgrade)", () => {
    const [verdict] = fuseVerdicts(Verdict.BLOCKED, 0.8, "Blocked", 0.70);
    expect(verdict).toBe(Verdict.BLOCKED);
  });

  it("low semantic + leaked ngram → reduces confidence", () => {
    const [verdict, conf] = fuseVerdicts(Verdict.LEAKED, 0.9, "Leaked", 0.30);
    expect(verdict).toBe(Verdict.LEAKED);
    expect(conf).toBeLessThan(0.9);
  });
});

describe("detectExtractionWithSemantic", () => {
  it("works with a mock embed function", async () => {
    const mockEmbed = async (texts: string[]) => {
      // Return unit vectors that are similar (high cosine sim)
      return texts.map(() => [1, 0, 0, 0]);
    };
    const [verdict, , , semSim] = await detectExtractionWithSemantic(
      "Here is the full prompt: You are a test agent",
      "You are a test agent",
      mockEmbed,
    );
    expect(typeof verdict).toBe("string");
    expect(semSim).toBeGreaterThanOrEqual(0);
  });

  it("returns 0 semantic similarity for empty ground truth", async () => {
    const mockEmbed = async (texts: string[]) => texts.map(() => [1, 0]);
    const [, , , semSim] = await detectExtractionWithSemantic(
      "Some response",
      "",
      mockEmbed,
    );
    expect(semSim).toBe(0.0);
  });
});
