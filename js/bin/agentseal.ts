// bin/agentseal.ts — CLI entry point

import { Command } from "commander";
import { AgentValidator } from "../src/validator.js";
import { fromEndpoint } from "../src/providers/http.js";
import { fromOllama } from "../src/providers/ollama.js";
import { generateRemediation } from "../src/remediation.js";
import { compareReports } from "../src/compare.js";
import type { ScanReport } from "../src/types.js";
import { readFileSync, writeFileSync } from "node:fs";

const VERSION = "0.1.0";

function printBanner() {
  const R = "\x1b[0m";
  const D = "\x1b[90m";
  const C = "\x1b[36m";
  console.log();
  console.log(`  ${C}╔═══════════════════════════════════════╗${R}`);
  console.log(`  ${C}║         A G E N T S E A L             ║${R}`);
  console.log(`  ${C}╚═══════════════════════════════════════╝${R}`);
  console.log(`  ${D}v${VERSION}  Security Validator for AI Agents${R}`);
  console.log();
}

function resolveApiKey(args: { apiKey?: string; model?: string }): string | undefined {
  if (args.apiKey) return args.apiKey;
  if (args.model?.startsWith("claude") || args.model?.startsWith("anthropic/")) {
    return process.env["ANTHROPIC_API_KEY"];
  }
  return process.env["OPENAI_API_KEY"];
}

async function buildValidator(
  systemPrompt: string,
  args: {
    model?: string;
    apiKey?: string;
    ollamaUrl?: string;
    name?: string;
    concurrency?: number;
    timeout?: number;
    verbose?: boolean;
    adaptive?: boolean;
  },
): Promise<AgentValidator> {
  const model = args.model;
  if (!model) {
    console.error("Error: --model is required when using --prompt or --file");
    process.exit(1);
  }

  const commonOpts = {
    agentName: args.name ?? "My Agent",
    concurrency: args.concurrency ?? 3,
    timeoutPerProbe: args.timeout ?? 30,
    verbose: args.verbose ?? false,
    adaptive: args.adaptive ?? false,
  };

  // Ollama
  if (model.startsWith("ollama/")) {
    const ollamaModel = model.replace("ollama/", "");
    return AgentValidator.fromOllama({
      model: ollamaModel,
      systemPrompt,
      baseUrl: args.ollamaUrl ?? "http://localhost:11434",
      ...commonOpts,
    });
  }

  // Anthropic
  if (model.startsWith("claude")) {
    const apiKey = resolveApiKey(args);
    if (!apiKey) {
      console.error("Error: ANTHROPIC_API_KEY not found. Set via --api-key or env variable.");
      process.exit(1);
    }
    const agentFn = async (message: string): Promise<string> => {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model,
          max_tokens: 1024,
          system: systemPrompt,
          messages: [{ role: "user", content: message }],
        }),
      });
      const data = await res.json() as { content?: { text?: string }[] };
      return data.content?.[0]?.text ?? "";
    };
    return new AgentValidator({
      agentFn,
      groundTruthPrompt: systemPrompt,
      ...commonOpts,
    });
  }

  // Default: OpenAI-compatible
  const apiKey = resolveApiKey(args);
  if (!apiKey) {
    console.error("Error: OPENAI_API_KEY not found. Set via --api-key or env variable.");
    process.exit(1);
  }
  const agentFn = async (message: string): Promise<string> => {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: message },
        ],
      }),
    });
    const data = await res.json() as { choices?: { message?: { content?: string } }[] };
    return data.choices?.[0]?.message?.content ?? "";
  };
  return new AgentValidator({
    agentFn,
    groundTruthPrompt: systemPrompt,
    ...commonOpts,
  });
}

function printReport(report: ScanReport) {
  const R = "\x1b[0m";
  const G = "\x1b[32m";
  const Y = "\x1b[33m";
  const RED = "\x1b[31m";
  const D = "\x1b[90m";
  const B = "\x1b[1m";

  const scoreColor = report.trust_score >= 70 ? G : report.trust_score >= 50 ? Y : RED;

  console.log(`${B}Results:${R}`);
  console.log(`  Agent:          ${report.agent_name}`);
  console.log(`  Trust Score:    ${scoreColor}${B}${report.trust_score.toFixed(1)}${R} / 100 (${report.trust_level})`);
  console.log(`  Duration:       ${report.duration_seconds.toFixed(1)}s`);
  console.log();
  console.log(`  ${G}Blocked: ${report.probes_blocked}${R}  ${RED}Leaked: ${report.probes_leaked}${R}  ${Y}Partial: ${report.probes_partial}${R}  ${D}Error: ${report.probes_error}${R}`);
  console.log();
  console.log(`${B}Score Breakdown:${R}`);
  console.log(`  Extraction Resistance: ${report.score_breakdown.extraction_resistance.toFixed(1)}`);
  console.log(`  Injection Resistance:  ${report.score_breakdown.injection_resistance.toFixed(1)}`);
  console.log(`  Boundary Integrity:    ${report.score_breakdown.boundary_integrity.toFixed(1)}`);
  console.log(`  Consistency:           ${report.score_breakdown.consistency.toFixed(1)}`);

  if (report.defense_profile) {
    console.log();
    console.log(`${B}Defense Profile:${R} ${report.defense_profile.defense_system} (${(report.defense_profile.confidence * 100).toFixed(0)}% confidence)`);
  }

  if (report.mutation_resistance !== undefined) {
    console.log();
    console.log(`${B}Mutation Resistance:${R} ${report.mutation_resistance.toFixed(1)}%`);
  }
}

const program = new Command();

program
  .name("agentseal")
  .description("Security validator for AI agents")
  .version(VERSION);

program
  .command("scan")
  .description("Run security scan against an agent")
  .option("-p, --prompt <text>", "System prompt to test")
  .option("-f, --file <path>", "Path to file containing system prompt")
  .option("--url <url>", "HTTP endpoint URL to test")
  .option("-m, --model <name>", "Model to test (e.g. gpt-4o, claude-sonnet-4-5-20250929, ollama/qwen3)")
  .option("--api-key <key>", "API key")
  .option("--ollama-url <url>", "Ollama base URL", "http://localhost:11434")
  .option("--message-field <field>", "HTTP request message field", "message")
  .option("--response-field <field>", "HTTP response field", "response")
  .option("-o, --output <format>", "Output format: terminal, json", "terminal")
  .option("--save <path>", "Save JSON report to file")
  .option("--name <name>", "Agent name for report", "My Agent")
  .option("--concurrency <n>", "Max parallel probes", "3")
  .option("--timeout <seconds>", "Timeout per probe", "30")
  .option("-v, --verbose", "Show each probe result")
  .option("--adaptive", "Enable adaptive mutation phase")
  .option("--min-score <score>", "Exit code 1 if below (CI mode)")
  .option("--json-remediation", "Include structured remediation in JSON output")
  .argument("[prompt]", "Quick inline prompt")
  .action(async (inlinePrompt, opts) => {
    printBanner();

    let systemPrompt: string | undefined;

    if (opts.prompt) {
      systemPrompt = opts.prompt;
    } else if (inlinePrompt) {
      systemPrompt = inlinePrompt;
    } else if (opts.file) {
      systemPrompt = readFileSync(opts.file, "utf-8").trim();
    }

    let validator: AgentValidator;

    if (opts.url) {
      validator = AgentValidator.fromEndpoint({
        url: opts.url,
        messageField: opts.messageField,
        responseField: opts.responseField,
        agentName: opts.name,
        concurrency: parseInt(opts.concurrency),
        timeoutPerProbe: parseFloat(opts.timeout),
        verbose: opts.verbose,
        adaptive: opts.adaptive,
        ...(systemPrompt ? { groundTruthPrompt: systemPrompt } : {}),
      });
    } else if (systemPrompt) {
      validator = await buildValidator(systemPrompt, {
        model: opts.model,
        apiKey: opts.apiKey,
        ollamaUrl: opts.ollamaUrl,
        name: opts.name,
        concurrency: parseInt(opts.concurrency),
        timeout: parseFloat(opts.timeout),
        verbose: opts.verbose,
        adaptive: opts.adaptive,
      });
    } else {
      console.error("Error: Provide --prompt, --file, or --url");
      process.exit(1);
    }

    console.log("Starting security scan...\n");

    const report = await validator.run();

    if (opts.output === "json") {
      const output: Record<string, unknown> = { ...report };
      if (opts.jsonRemediation) {
        output.remediation = generateRemediation(report);
      }
      const json = JSON.stringify(output, null, 2);
      console.log(json);
    } else {
      printReport(report);

      // Show top failures
      const leaked = report.results.filter((r) => r.verdict === "leaked");
      if (leaked.length > 0) {
        console.log(`\n\x1b[1mTop Failures:\x1b[0m`);
        for (const r of leaked.slice(0, 5)) {
          console.log(`  \x1b[31m✗\x1b[0m ${r.probe_id} (${r.category}) — ${r.reasoning.slice(0, 80)}`);
        }
      }

      // Show remediation summary
      const remediation = generateRemediation(report);
      if (remediation.items.length > 0 && remediation.items[0]!.category !== "") {
        console.log(`\n\x1b[1mRemediation:\x1b[0m`);
        for (const item of remediation.items.slice(0, 5)) {
          console.log(`  [${item.priority}] ${item.title}`);
        }
        console.log(`\n  Run with --output json --json-remediation for full fix instructions.`);
      }
    }

    if (opts.save) {
      writeFileSync(opts.save, JSON.stringify(report, null, 2));
      console.log(`\nReport saved to ${opts.save}`);
    }

    // CI mode
    if (opts.minScore) {
      const threshold = parseInt(opts.minScore);
      if (report.trust_score < threshold) {
        console.error(`\nCI check failed: score ${report.trust_score.toFixed(1)} < threshold ${threshold}`);
        process.exit(1);
      }
    }
  });

program
  .command("compare")
  .description("Compare two scan reports")
  .argument("<baseline>", "Path to baseline report (JSON)")
  .argument("<current>", "Path to current report (JSON)")
  .option("-o, --output <format>", "Output format: terminal, json", "terminal")
  .action((baselinePath, currentPath, opts) => {
    const baseline = JSON.parse(readFileSync(baselinePath, "utf-8")) as ScanReport;
    const current = JSON.parse(readFileSync(currentPath, "utf-8")) as ScanReport;
    const result = compareReports(baseline, current);

    if (opts.output === "json") {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(result.summary);
      if (result.regressions.length > 0) {
        console.log(`\nRegressions:`);
        for (const r of result.regressions) {
          console.log(`  \x1b[31m↓\x1b[0m ${r.probe_id} — now ${r.verdict}`);
        }
      }
      if (result.improvements.length > 0) {
        console.log(`\nImprovements:`);
        for (const r of result.improvements) {
          console.log(`  \x1b[32m↑\x1b[0m ${r.probe_id} — now ${r.verdict}`);
        }
      }
    }
  });

program.parse();
