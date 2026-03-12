# AgentSeal

[![PyPI version](https://img.shields.io/pypi/v/agentseal?color=blue)](https://pypi.org/project/agentseal/)
[![Python](https://img.shields.io/pypi/pyversions/agentseal)](https://pypi.org/project/agentseal/)
[![Downloads](https://img.shields.io/pypi/dm/agentseal)](https://pypi.org/project/agentseal/)
[![GitHub stars](https://img.shields.io/github/stars/AgentSeal/agentseal)](https://github.com/AgentSeal/agentseal)
[![License](https://img.shields.io/github/license/AgentSeal/agentseal)](https://github.com/AgentSeal/agentseal/blob/main/LICENSE)

**Find out if your AI agent can be hacked** - before someone else does.

AgentSeal is a security toolkit for AI agents. It scans your machine for dangerous skills and MCP configs, monitors for supply chain attacks, tests your agent's resistance to prompt injection, and audits live MCP servers for tool poisoning.

```bash
pip install agentseal
agentseal guard        # scan your machine right now - no API key, no config
```

## What It Does

| Command | What it does | API key? |
|---------|-------------|:--------:|
| `agentseal guard` | Scans your machine for dangerous skills, MCP configs, toxic data flows, and supply chain changes | No |
| `agentseal shield` | Watches your config files in real time and alerts on threats | No |
| `agentseal scan` | Tests your agent's system prompt against 191+ attack probes | Yes* |
| `agentseal scan-mcp` | Connects to live MCP servers and audits tool descriptions for poisoning | No |

*Free with [Ollama](https://ollama.com) (local model). Cloud models require an API key.

## Guard - Machine Security Scan

```bash
agentseal guard
```

Auto-discovers 17 AI agents (Claude Code, Cursor, Windsurf, VS Code, Gemini CLI, Codex, and more), scans every skill and MCP config for threats, detects toxic data flows across servers, and tracks baselines to catch supply chain attacks.

```
  SKILLS
  [XX] sketchy-rules         MALWARE - Credential access
       -> Remove this skill immediately and rotate all credentials.
  [OK] 4 more safe skills

  MCP SERVERS
  [XX] filesystem            DANGER - Access to SSH private keys
       -> Restrict 'filesystem' MCP server: remove .ssh from allowed paths.

  TOXIC FLOW RISKS
  [HIGH] Data exfiltration path detected
       Servers: filesystem, slack
```

## Shield - Continuous Monitoring

```bash
pip install agentseal[shield]
agentseal shield
```

Watches all agent config paths in real time. Desktop notifications on threats. Baseline checks on every MCP config change.

## Scan - Prompt Security Testing

```bash
# Cloud model
agentseal scan --prompt "You are a helpful assistant..." --model gpt-4o

# Free local model (no API key)
agentseal scan --prompt "You are a helpful assistant..." --model ollama/llama3.1:8b

# Live endpoint
agentseal scan --url http://localhost:8080/chat
```

191 attack probes (82 extraction + 109 injection). Deterministic scoring - no AI judge, same result every time.

## Scan-MCP - Live MCP Server Audit

```bash
agentseal scan-mcp --server npx @modelcontextprotocol/server-filesystem /tmp
```

4-layer analysis of tool descriptions: pattern detection, deobfuscation, semantic embeddings, LLM judge. Catches poisoning, hidden instructions, and cross-server collusion.

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

## CI/CD

```bash
agentseal scan --file ./prompt.txt --model gpt-4o --min-score 75
# Exit code 1 if below threshold. SARIF output with --output sarif.
```

## Supported Models

| Provider | Usage | API key? |
|----------|-------|:--------:|
| **OpenAI** | `--model gpt-4o` | `OPENAI_API_KEY` |
| **Anthropic** | `--model claude-sonnet-4-5-20250929` | `ANTHROPIC_API_KEY` |
| **Ollama** (free) | `--model ollama/llama3.1:8b` | No |
| **LiteLLM** | `--model any --litellm-url http://...` | Depends |
| **HTTP API** | `--url http://your-agent.com/chat` | No |

## Pro Features

[AgentSeal Pro](https://agentseal.org) extends the open source toolkit with MCP tool poisoning probes (+45), RAG poisoning probes (+28), multimodal attack probes (+13), behavioral genome mapping, GitHub repo security analysis, PDF reports, and a dashboard.

## Links

- **Website and Dashboard**: [agentseal.org](https://agentseal.org)
- **Docs**: [agentseal.org/docs](https://agentseal.org/docs)
- **GitHub**: [github.com/AgentSeal/agentseal](https://github.com/AgentSeal/agentseal)
- **npm package**: [npmjs.com/package/agentseal](https://www.npmjs.com/package/agentseal)

## License

[FSL-1.1-Apache-2.0](LICENSE) - Functional Source License, Version 1.1, with Apache 2.0 future license. Copyright 2026 AgentSeal.
