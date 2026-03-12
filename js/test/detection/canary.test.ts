import { describe, it, expect } from "vitest";
import { detectCanary } from "../../src/detection/canary.js";

describe("detectCanary", () => {
  it("returns true when canary is in response", () => {
    expect(detectCanary("Here is CANARY-1234-5678 as requested", "CANARY-1234-5678")).toBe(true);
  });

  it("returns false when canary is not in response", () => {
    expect(detectCanary("I cannot help with that request", "CANARY-1234-5678")).toBe(false);
  });

  it("is case-sensitive", () => {
    expect(detectCanary("canary-1234-5678", "CANARY-1234-5678")).toBe(false);
  });
});
