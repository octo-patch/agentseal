// agentseal/errors.ts — Error hierarchy

export class AgentSealError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentSealError";
  }
}

export class ProbeTimeoutError extends AgentSealError {
  constructor(probeId: string, timeoutMs: number) {
    super(`Probe ${probeId} timed out after ${timeoutMs}ms`);
    this.name = "ProbeTimeoutError";
  }
}

export class ProviderError extends AgentSealError {
  constructor(provider: string, message: string) {
    super(`[${provider}] ${message}`);
    this.name = "ProviderError";
  }
}

export class ValidationError extends AgentSealError {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}
