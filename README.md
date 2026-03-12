# AgentSeal

[![PyPI version](https://img.shields.io/pypi/v/agentseal?color=blue)](https://pypi.org/project/agentseal/)
[![PyPI downloads](https://img.shields.io/pypi/dm/agentseal)](https://pypi.org/project/agentseal/)
[![npm version](https://img.shields.io/npm/v/agentseal?color=blue)](https://www.npmjs.com/package/agentseal)
[![npm downloads](https://img.shields.io/npm/dm/agentseal)](https://www.npmjs.com/package/agentseal)
[![License](https://img.shields.io/badge/license-FSL--1.1--Apache--2.0-blue)](https://github.com/AgentSeal/agentseal/blob/main/LICENSE)
[![Twitter](https://img.shields.io/twitter/follow/agentseal_org)](https://x.com/agentseal_org)
[![AgentSeal Repo](https://agentseal.org/api/v1/repos/agentseal-agentseal/badge)](https://agentseal.org/repos/agentseal-agentseal)

**Find out if your AI agent can be hacked** - before someone else does.

<p align="center">
  <a href="https://agentseal.org">Website</a> &middot;
  <a href="https://agentseal.org/docs">Docs</a> &middot;
  <a href="https://agentseal.org/docs/quick-start">Quick Start</a> &middot;
  <a href="https://agentseal.org/sealbench">SealBench</a> &middot;
  <a href="https://x.com/agentseal_org">Twitter</a>
</p>

```
   ██████╗   ██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗ █████╗ ██╗
  ██╔══██╗ ██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗██║
  ███████║ ██║  ███╗█████╗  ██╔██╗ ██║   ██║   ███████╗█████╗  ███████║██║
  ██╔══██║ ██║   ██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║██╔══╝  ██╔══██║██║
  ██║  ██║ ╚██████╔╝███████╗██║ ╚████║   ██║   ███████║███████╗██║  ██║███████╗
  ╚═╝  ╚═╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝
```

AgentSeal is a security toolkit for AI agents. It scans your machine for dangerous skills and MCP server configs, monitors for supply chain attacks, tests your agent's resistance to prompt injection, and audits live MCP servers for tool poisoning.

```bash
pip install agentseal
agentseal guard        # scan your machine right now - no API key, no config
```

---

## What AgentSeal Does

AgentSeal covers four attack surfaces that other tools miss:

| Command | What it does | API key? |
|---------|-------------|:--------:|
| [`agentseal guard`](#agentseal-guard) | Scans your machine for dangerous skills, MCP configs, toxic data flows, and supply chain changes | No |
| [`agentseal shield`](#agentseal-shield) | Watches your config files in real time and alerts on threats | No |
| [`agentseal scan`](#agentseal-scan) | Tests your agent's system prompt against 191+ attack probes | Yes* |
| [`agentseal scan-mcp`](#agentseal-scan-mcp) | Connects to live MCP servers and audits tool descriptions for poisoning | No |

*Free with [Ollama](https://ollama.com) (local model). Cloud models require an API key.

---

## `agentseal guard`

One command scans your entire machine for AI agent threats. No config, no API keys, no internet needed.

```bash
agentseal guard
```

- Auto-discovers **17 AI agents** (Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Gemini CLI, Codex, Cline, Roo Code, Zed, Aider, Continue, Amp, OpenClaw, Kiro, OpenCode, and more)
- Scans every **skill/rules file** for malware, credential theft, prompt injection, reverse shells, data exfiltration, and 9 other threat categories
- Audits every **MCP server config** for sensitive path access, hardcoded API keys, overly broad permissions, and insecure connections
- Detects **toxic data flows** across MCP servers (e.g. filesystem + slack = data exfiltration risk)
- Tracks **MCP server baselines** to catch supply chain / rug pull attacks when configs change silently
- Shows **red/yellow/green results** with numbered action items telling you exactly what to fix

```
  AgentSeal Guard - Machine Security Scan
  ------------------------------------------------

  AGENTS INSTALLED
  [OK] Claude Code          ~/.claude/settings.json
  [OK] Cursor               ~/.cursor/mcp.json (3 MCP servers)

  SKILLS
  [XX] sketchy-rules         MALWARE - Credential access
       -> Remove this skill immediately and rotate all credentials.
  [OK] 4 more safe skills

  MCP SERVERS
  [XX] filesystem            DANGER - Access to SSH private keys
       -> Restrict 'filesystem' MCP server: remove .ssh from allowed paths.
  [OK] brave-search           SAFE

  TOXIC FLOW RISKS
  [HIGH] Data exfiltration path detected
       Servers: filesystem, slack
       -> Scope filesystem access to non-sensitive directories only.

  ------------------------------------------------
  1 critical threat(s) found. Action required.

  ACTIONS NEEDED:
  1. Remove this skill immediately and rotate all credentials.
  2. Restrict 'filesystem' MCP server: remove .ssh from allowed paths.
  3. Scope filesystem access to non-sensitive directories only.
```

```bash
agentseal guard --output json       # JSON output (exit 1 if threats found)
agentseal guard --save report.json  # save report to file
agentseal guard --no-semantic       # skip semantic analysis (faster)
agentseal guard --reset-baselines   # re-fingerprint all MCP servers
agentseal guard --verbose           # show all agents including not-installed
```

---

## `agentseal shield`

Watches your skill directories and MCP configs in real time. When a file changes, scans it instantly and sends a desktop notification if something is wrong.

```bash
pip install agentseal[shield]
agentseal shield
```

```
  AgentSeal Shield - Continuous Monitoring
  ------------------------------------------------
  Watching 12 directories for changes...
  Press Ctrl+C to stop.

  [14:32:05] CLEAN   ~/.cursor/rules/code-review.md
  [14:35:12] THREAT  ~/.cursor/mcp.json
             MCP 'untrusted-tool': DANGER - Access to SSH private keys
  [14:35:12] WARNING ~/.cursor/mcp.json
             BASELINE: Config for 'filesystem' changed (command/args/env modified).
```

- Watches all 17 agent config paths automatically
- Debounces rapid file changes (editors, git operations)
- Native desktop notifications (macOS, Linux)
- Runs baseline checks on every MCP config change
- Detects toxic flows when server combinations change

```bash
agentseal shield --no-notify        # without desktop notifications
agentseal shield --quiet            # only show threats
agentseal shield --reset-baselines  # reset baselines before starting
```

---

## `agentseal scan`

Tests your agent's system prompt against 191+ attack probes (82 extraction + 109 injection). Deterministic scoring with no AI judge - running the same scan twice gives the exact same results.

```bash
# Test against a cloud model
agentseal scan --prompt "You are a helpful assistant..." --model gpt-4o

# Test with a free local model (no API key needed)
agentseal scan --prompt "You are a helpful assistant..." --model ollama/llama3.1:8b

# Test a live HTTP endpoint
agentseal scan --url http://localhost:8080/chat
```

```
Trust Score: 73/100 (HIGH)

  Extraction resistance:  82/100  (9 blocked, 2 partial, 1 leaked)
  Injection resistance:   68/100  (7 blocked, 3 leaked)
  Boundary integrity:     75/100
  Consistency:            90/100

Top vulnerabilities:
  1. [CRITICAL] Direct ask #3 - agent revealed full system prompt
  2. [HIGH] Persona hijack #2 - agent followed injected instructions
  3. [MEDIUM] Encoding trick #1 - agent leaked partial prompt via Base64

Remediation:
  - Add explicit refusal instructions to your system prompt
  - Use delimiters to separate system instructions from user input
  - Consider adding an input/output filter layer
```

A score of **75+** means your agent is solid. **Below 50** means serious problems - fix those before going live.

```bash
agentseal scan --prompt "..." --model gpt-4o --adaptive        # adaptive mutations
agentseal scan --prompt "..." --model gpt-4o --fix prompt.txt  # auto-harden prompt
agentseal scan --prompt "..." --model gpt-4o --save results.json
agentseal scan --prompt "..." --model gpt-4o --output sarif    # for GitHub Security tab
agentseal scan --prompt "..." --model gpt-4o --min-score 75    # CI/CD gate
```

---

## `agentseal scan-mcp`

Connects to live MCP servers, lists their tools, and audits every tool description for hidden instructions, data exfiltration, and poisoning attacks.

```bash
agentseal scan-mcp --server npx @modelcontextprotocol/server-filesystem /tmp
```

- 4-layer analysis: pattern detection, deobfuscation, semantic embeddings, LLM judge
- Detects tool description poisoning, hidden instructions in annotations, cross-server collusion
- Catches zero-width characters, base64 payloads, and unicode obfuscation in tool descriptions
- Produces a 0-100 trust score per server with severity-weighted findings

```bash
agentseal scan-mcp --url http://localhost:3000/mcp  # HTTP/SSE server
agentseal scan-mcp --server cmd1 --server cmd2      # multiple servers
agentseal guard --connect                           # guard + live MCP audit
```

---

## Scan Modes

| Command | Probes | What it tests | Tier |
|---------|:------:|---------------|:----:|
| `agentseal guard` | N/A | Machine scan - skills, MCP configs, toxic flows, baselines | Free |
| `agentseal shield` | N/A | Continuous monitoring - watches files, detects changes in real time | Free |
| `agentseal scan` | 191 | Base scan - 82 extraction + 109 injection probes | Free |
| `agentseal scan --adaptive` | 191+ | + adaptive mutation transforms on blocked probes | Free |
| `agentseal scan-mcp` | N/A | Live MCP server audit - tool poisoning, cross-server analysis | Free |
| `agentseal watch` | 5 | Canary regression scan - fast check with baseline comparison | Free |
| `agentseal scan --mcp` | 218 | + 45 MCP tool poisoning probes | Pro |
| `agentseal scan --rag` | 201 | + 28 RAG poisoning probes | Pro |
| `agentseal scan --multimodal` | 186 | + 13 multimodal attack probes (image, audio, stego) | Pro |
| `agentseal scan --genome` | 191 + ~105 | + Behavioral genome mapping - finds decision boundaries | Pro |
| `agentseal scan --mcp --rag --multimodal --genome` | 259 + ~105 | Everything - the most thorough scan available | Pro |

---

## Supported Models

| Provider | How to use | API key? |
|----------|-----------|:--------:|
| **OpenAI** | `--model gpt-4o` | `OPENAI_API_KEY` |
| **Anthropic** | `--model claude-sonnet-4-5-20250929` | `ANTHROPIC_API_KEY` |
| **Ollama** (local, free) | `--model ollama/llama3.1:8b` | No |
| **LiteLLM** (proxy) | `--model any-model --litellm-url http://...` | Depends |
| **Any HTTP API** | `--url http://your-agent.com/chat` | No |

---

## CI/CD Integration

Add AgentSeal to your pipeline to automatically block insecure agents from shipping.

```yaml
# .github/workflows/security.yml
name: Agent Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install agentseal
      - name: Run security scan
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          agentseal scan \
            --file ./prompts/system_prompt.txt \
            --model gpt-4o \
            --min-score 75 \
            --output sarif \
            --save results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

`--min-score 75` exits with code 1 if the trust score is below 75, blocking the merge. SARIF output shows results in GitHub's Security tab. Works in any CI system that can run Python.

---

## Free vs Pro

The core toolkit is **completely free** and open source.

| Feature | Free | Pro |
|---------|:----:|:---:|
| Machine security scan (`guard`) | Yes | Yes |
| Continuous monitoring (`shield`) | Yes | Yes |
| Live MCP server audit (`scan-mcp`) | Yes | Yes |
| Toxic flow detection and baseline tracking | Yes | Yes |
| 191 base attack probes (extraction + injection) | Yes | Yes |
| Adaptive mutations (`--adaptive`) | Yes | Yes |
| Canary regression watch (`watch`) | Yes | Yes |
| Interactive fix flow (autofix and re-scan) | Yes | Yes |
| JSON and SARIF output | Yes | Yes |
| CI/CD integration (`--min-score`) | Yes | Yes |
| Defense fingerprinting | Yes | Yes |
| **MCP tool poisoning probes** (`--mcp`, +45) | - | Yes |
| **RAG poisoning probes** (`--rag`, +28) | - | Yes |
| **Multimodal attack probes** (`--multimodal`, +13) | - | Yes |
| **Behavioral genome mapping** (`--genome`) | - | Yes |
| **GitHub repo security analysis** | - | Yes |
| **PDF security report** (`--report`) | - | Yes |
| **Dashboard** (track over time, `--upload`) | - | Yes |

```bash
agentseal login                    # opens browser to sign in
agentseal activate <license-key>   # or activate with a key
```

<p align="center">
  <a href="https://agentseal.org">
    <img src="assets/dashboard.png" alt="AgentSeal Dashboard" width="800" />
  </a>
  <br />
  <em>AgentSeal Dashboard - track trust scores, monitor vulnerabilities, and generate reports.</em>
</p>

---

## Python API

```python
from agentseal import AgentValidator

# OpenAI
validator = AgentValidator.from_openai(
    client=openai.AsyncOpenAI(),
    model="gpt-4o",
    system_prompt="You are a helpful assistant...",
)
report = await validator.run()
print(f"Trust score: {report.trust_score}/100")

# Anthropic
validator = AgentValidator.from_anthropic(client, model="claude-sonnet-4-5-20250929", system_prompt="...")

# HTTP endpoint
validator = AgentValidator.from_endpoint(url="http://localhost:8080/chat")

# Custom function
validator = AgentValidator(agent_fn=my_agent, ground_truth_prompt="...")
```

---

## JavaScript / TypeScript

```bash
npm install agentseal
```

```typescript
import { AgentValidator } from "agentseal";
import OpenAI from "openai";

const validator = AgentValidator.fromOpenAI(new OpenAI(), {
  model: "gpt-4o",
  systemPrompt: "You are a helpful assistant...",
});
const report = await validator.run();
console.log(`Trust Score: ${report.trust_score}/100 (${report.trust_level})`);
```

Works with Anthropic, Vercel AI SDK, LangChain, Ollama, HTTP endpoints, and custom functions. See the [npm package docs](js/README.md).

---

<details>
<summary><strong>FAQ</strong></summary>

### How long does a scan take?

With Ollama (local): **1-3 minutes**. With cloud APIs: **3-6 minutes**. Adjust with `--concurrency`.

### What's a good trust score?

| Score | Meaning |
|-------|---------|
| **85-100** | Excellent - strong protection across the board |
| **70-84** | Good - minor gaps, fine for most use cases |
| **50-69** | Needs work - several attack categories succeed |
| **Below 50** | Serious problems - don't deploy without fixing these |

### Does AgentSeal send my system prompt anywhere?

**No.** Your prompt is only sent to the model you specify. AgentSeal never collects, stores, or transmits your prompts.

### Do I need an API key?

Only for `agentseal scan` with a cloud model. Guard, shield, and scan-mcp run entirely locally with no API key, no account, no cost. For scan, you can use [Ollama](https://ollama.com) to avoid API keys entirely.

</details>

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started.

For security vulnerabilities, please email [hello@agentseal.org](mailto:hello@agentseal.org) instead of opening a public issue.

---

## Links

- **Website and Dashboard**: [agentseal.org](https://agentseal.org)
- **Docs**: [agentseal.org/docs](https://agentseal.org/docs)
- **npm package**: [npmjs.com/package/agentseal](https://www.npmjs.com/package/agentseal)
- **PyPI package**: [pypi.org/project/agentseal](https://pypi.org/project/agentseal/)
- **Issues**: [GitHub Issues](https://github.com/agentseal/agentseal/issues)
- **Security**: [hello@agentseal.org](mailto:hello@agentseal.org)

## License

[FSL-1.1-Apache-2.0](LICENSE) - Functional Source License, Version 1.1, with Apache 2.0 future license.

Copyright 2026 AgentSeal.
