import { describe, it, expect } from "vitest";
import { fingerprintDefense } from "../src/fingerprint.js";

describe("fingerprintDefense", () => {
  it("detects Anthropic Constitutional AI", () => {
    const responses = [
      "I aim to be helpful, harmless, and honest.",
      "I'm Claude, and I need to be careful about that request.",
    ];
    const profile = fingerprintDefense(responses);
    expect(profile.defense_system).toBe("Anthropic Constitutional AI");
    expect(profile.confidence).toBeGreaterThan(0);
  });

  it("detects OpenAI Moderation", () => {
    const responses = [
      "This content violates our content policy.",
      "As an AI language model, I'm not able to help with that.",
    ];
    const profile = fingerprintDefense(responses);
    expect(profile.defense_system).toBe("OpenAI Moderation");
  });

  it("detects Azure Prompt Shield", () => {
    const responses = [
      "I cannot process this request. The content was flagged by content filtering.",
    ];
    const profile = fingerprintDefense(responses);
    expect(profile.defense_system).toBe("Azure Prompt Shield");
  });

  it("detects custom defense on generic refusals", () => {
    const responses = [
      "I will not do that for you.",
      "I'm unable to process this.",
      "I won't help with that particular task.",
    ];
    const profile = fingerprintDefense(responses);
    expect(profile.defense_system).toBe("custom");
    expect(profile.confidence).toBeGreaterThan(0);
  });

  it("returns unknown when no defense detected", () => {
    const responses = ["Hello! How can I help you today?"];
    const profile = fingerprintDefense(responses);
    expect(profile.defense_system).toBe("unknown");
    expect(profile.confidence).toBe(0);
  });
});
