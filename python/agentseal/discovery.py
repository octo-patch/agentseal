# agentseal/discovery.py
"""
Agent Auto-Discovery Engine

The whole point: you run `agentseal scan ./` and we find EVERYTHING.

We scan your codebase and automatically discover:
- System prompts in Python files (OpenAI, Anthropic, LangChain, CrewAI, etc.)
- System prompts in JavaScript/TypeScript files
- Claude Desktop config (MCP servers)
- Cursor / Windsurf / Cline configs
- CrewAI agent definitions (YAML)
- LangChain agent definitions
- AutoGen agent definitions
- .env files with prompts
- YAML/JSON/TOML config files with prompts
- Ollama Modelfiles
- OpenAI Assistants defined in code

The user does NOTHING manual. We do ALL the work.
"""

import ast
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredAgent:
    """An agent we found automatically."""
    name: str                           # Human-readable name
    source_file: str                    # Where we found it
    source_line: Optional[int]          # Line number (if from code)
    system_prompt: str                  # The actual prompt text
    model: Optional[str]                # Model if we could detect it
    framework: str                      # "openai", "anthropic", "crewai", "langchain", "ollama", etc.
    tools: list[str] = field(default_factory=list)        # Tool/function names if found
    mcp_servers: list[dict] = field(default_factory=list) # MCP server configs if found
    warnings: list[str] = field(default_factory=list)     # Security warnings during discovery
    confidence: float = 1.0             # How sure we are this is real (0-1)

    def short_prompt(self, max_len: int = 80) -> str:
        preview = self.system_prompt.replace("\n", " ")[:max_len]
        return f"{preview}{'...' if len(self.system_prompt) > max_len else ''}"


@dataclass
class DiscoveryReport:
    """Everything we found in a project."""
    root_path: str
    agents: list[DiscoveredAgent]
    files_scanned: int
    warnings: list[str]                 # Global warnings (exposed credentials, etc.)

    def print_summary(self):
        """Pretty print what we found."""
        G = "\033[92m"
        Y = "\033[93m"
        R = "\033[91m"
        B = "\033[94m"
        D = "\033[2m"
        BOLD = "\033[1m"
        RST = "\033[0m"

        print()
        print(f"  {B}AgentSeal Discovery{RST}")
        print(f"  {D}Scanned: {self.root_path}{RST}")
        print(f"  {D}Files checked: {self.files_scanned}{RST}")
        print()

        if not self.agents:
            print(f"  {Y}No agents found.{RST}")
            print(f"  {D}Try pointing at a directory with Python/JS files, YAML configs, or Modelfiles.{RST}")
            return

        print(f"  {G}Found {len(self.agents)} agent(s):{RST}")
        print()

        for i, agent in enumerate(self.agents, 1):
            model_str = f" ({agent.model})" if agent.model else ""
            print(f"  {BOLD}{i}. {agent.name}{model_str}{RST}")
            print(f"     {D}Source: {agent.source_file}"
                  f"{f':{agent.source_line}' if agent.source_line else ''}{RST}")
            print(f"     {D}Framework: {agent.framework}{RST}")
            print(f"     {D}Prompt: {agent.short_prompt()}{RST}")
            if agent.tools:
                print(f"     {D}Tools: {', '.join(agent.tools[:5])}"
                      f"{'...' if len(agent.tools) > 5 else ''}{RST}")
            if agent.mcp_servers:
                names = [s.get("name", "unnamed") for s in agent.mcp_servers]
                print(f"     {D}MCP Servers: {', '.join(names)}{RST}")
            for w in agent.warnings:
                print(f"     {Y}⚠ {w}{RST}")
            print()

        if self.warnings:
            print(f"  {R}Global warnings:{RST}")
            for w in self.warnings:
                print(f"  {R}⚠ {w}{RST}")
            print()


class AgentDiscovery:
    """
    Crawls a directory and finds all AI agents automatically.

    Usage:
        discovery = AgentDiscovery("/path/to/project")
        report = discovery.scan()
        report.print_summary()      # Show what we found
        for agent in report.agents:  # Iterate and scan each
            ...
    """

    # File patterns to ignore
    IGNORE_DIRS = {
        "node_modules", ".git", "__pycache__", ".venv", "venv",
        "env", ".env", "dist", "build", ".next", ".cache",
        "site-packages", ".tox", ".pytest_cache", ".mypy_cache",
    }

    # Max file size to parse (skip huge files)
    MAX_FILE_SIZE = 500_000  # 500KB

    def __init__(self, root_path: str = "."):
        self.root = Path(root_path).resolve()
        self.agents: list[DiscoveredAgent] = []
        self.warnings: list[str] = []
        self.files_scanned = 0

    def scan(self) -> DiscoveryReport:
        """Scan the directory tree and discover all agents."""
        self.agents = []
        self.warnings = []
        self.files_scanned = 0

        # Walk the directory tree
        for path in self._walk_files():
            self.files_scanned += 1
            rel = str(path.relative_to(self.root))

            try:
                if path.suffix == ".py":
                    self._parse_python(path, rel)
                elif path.suffix in (".js", ".ts", ".jsx", ".tsx"):
                    self._parse_javascript(path, rel)
                elif path.suffix in (".yaml", ".yml"):
                    self._parse_yaml(path, rel)
                elif path.suffix == ".json":
                    self._parse_json_config(path, rel)
                elif path.suffix == ".toml":
                    self._parse_toml(path, rel)
                elif path.name == "Modelfile":
                    self._parse_modelfile(path, rel)
                elif path.name == ".cursorrules":
                    self._parse_cursorrules(path, rel)
                elif path.name in (".env", ".env.local", ".env.production"):
                    self._check_env_file(path, rel)
            except Exception:
                # Don't crash on unparseable files - just skip
                logger.debug("Skipped unparseable file: %s", path)

        # Check well-known config locations outside the project
        self._check_claude_desktop()
        self._check_cursor_global()

        # Deduplicate agents with same prompt
        self._deduplicate()

        return DiscoveryReport(
            root_path=str(self.root),
            agents=self.agents,
            files_scanned=self.files_scanned,
            warnings=self.warnings,
        )

    # ── File walking ─────────────────────────────────────────────────

    def _walk_files(self):
        """Yield all relevant files, skipping ignore dirs."""
        for dirpath, dirnames, filenames in os.walk(self.root):
            # Skip ignored directories (modifying dirnames in-place)
            dirnames[:] = [d for d in dirnames if d not in self.IGNORE_DIRS]

            for fname in filenames:
                path = Path(dirpath) / fname
                if path.stat().st_size <= self.MAX_FILE_SIZE:
                    yield path

    # ── Python parsing ───────────────────────────────────────────────

    def _parse_python(self, path: Path, rel: str):
        """Parse Python files for system prompts and agent definitions."""
        source = path.read_text(errors="ignore")

        # Strategy 1: AST parsing - find string assignments that look like prompts
        try:
            tree = ast.parse(source)
            self._find_prompts_in_ast(tree, source, rel)
        except SyntaxError:
            pass

        # Strategy 2: Regex for common patterns (catches things AST misses)
        self._find_prompts_by_pattern(source, rel)

    def _find_prompts_in_ast(self, tree: ast.AST, source: str, rel: str):
        """Walk AST to find system prompt assignments."""

        # Variable names that likely contain system prompts
        PROMPT_VARS = {
            "system_prompt", "system_message", "system_instruction",
            "system_instructions", "sys_prompt", "sys_message",
            "SYSTEM_PROMPT", "SYSTEM_MESSAGE", "SYSTEM_INSTRUCTION",
            "instructions", "INSTRUCTIONS", "persona", "PERSONA",
            "backstory", "BACKSTORY", "agent_prompt", "AGENT_PROMPT",
            "prompt", "system", "role_prompt", "base_prompt",
        }

        for node in ast.walk(tree):
            # Assignment: system_prompt = "You are..."
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in PROMPT_VARS:
                        value = self._extract_string_value(node.value, source)
                        if value and len(value) > 15:
                            self.agents.append(DiscoveredAgent(
                                name=f"{target.id} ({Path(rel).stem})",
                                source_file=rel,
                                source_line=node.lineno,
                                system_prompt=value,
                                model=self._find_nearby_model(source, node.lineno),
                                framework=self._detect_framework(source),
                                tools=self._find_tools_in_file(source),
                            ))

            # Function call: openai.chat.completions.create(messages=[{"role": "system", ...}])
            if isinstance(node, ast.Call):
                self._check_llm_call(node, source, rel)

    def _extract_string_value(self, node: ast.expr, source: str) -> Optional[str]:
        """Extract string value from an AST node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            # f-string - try to get the static parts
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                else:
                    parts.append("{...}")
            return "".join(parts) if parts else None
        # Multi-line string concatenation
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._extract_string_value(node.left, source)
            right = self._extract_string_value(node.right, source)
            if left and right:
                return left + right
        return None

    def _check_llm_call(self, node: ast.Call, source: str, rel: str):
        """Check if this is an LLM API call with a system message."""
        # Look for messages=[{...}] in keyword arguments
        for kw in node.keywords:
            if kw.arg == "messages" and isinstance(kw.value, ast.List):
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Dict):
                        self._extract_system_from_dict(elt, source, rel, node.lineno)

            # Anthropic style: system="..."
            if kw.arg == "system":
                value = self._extract_string_value(kw.value, source)
                if value and len(value) > 15:
                    model = self._find_model_in_call(node, source)
                    self.agents.append(DiscoveredAgent(
                        name=f"anthropic_agent ({Path(rel).stem})",
                        source_file=rel,
                        source_line=node.lineno,
                        system_prompt=value,
                        model=model,
                        framework="anthropic",
                        tools=self._find_tools_in_file(source),
                    ))

    def _extract_system_from_dict(self, node: ast.Dict, source: str, rel: str, lineno: int):
        """Extract system message from a messages dict like {"role": "system", "content": "..."}."""
        role_val = None
        content_val = None

        for key, value in zip(node.keys, node.values):
            key_str = self._extract_string_value(key, source) if key else None
            if key_str == "role":
                role_val = self._extract_string_value(value, source)
            elif key_str == "content":
                content_val = self._extract_string_value(value, source)

        if role_val == "system" and content_val and len(content_val) > 15:
            self.agents.append(DiscoveredAgent(
                name=f"openai_agent ({Path(rel).stem})",
                source_file=rel,
                source_line=lineno,
                system_prompt=content_val,
                model=self._find_nearby_model(source, lineno),
                framework="openai",
                tools=self._find_tools_in_file(source),
            ))

    def _find_prompts_by_pattern(self, source: str, rel: str):
        """Regex fallback for patterns AST can't catch."""
        lines = source.split("\n")

        # Pattern: ChatOpenAI / ChatAnthropic / ChatOllama with system message
        # LangChain: SystemMessage(content="...")
        for match in re.finditer(r'SystemMessage\s*\(\s*content\s*=\s*["\'](.+?)["\']', source, re.DOTALL):
            prompt = match.group(1)
            if len(prompt) > 15:
                lineno = source[:match.start()].count("\n") + 1
                self.agents.append(DiscoveredAgent(
                    name=f"langchain_agent ({Path(rel).stem})",
                    source_file=rel,
                    source_line=lineno,
                    system_prompt=prompt,
                    model=None,
                    framework="langchain",
                    confidence=0.8,
                ))

        # CrewAI: Agent(role="...", backstory="...", goal="...")
        for match in re.finditer(
            r'Agent\s*\([^)]*backstory\s*=\s*["\'\s]*(.+?)["\'][^)]*\)',
            source, re.DOTALL
        ):
            backstory = match.group(1).strip()
            if len(backstory) > 15:
                lineno = source[:match.start()].count("\n") + 1

                # Try to get role and goal too
                role_match = re.search(r'role\s*=\s*["\'](.+?)["\']', match.group(0))
                role = role_match.group(1) if role_match else "unnamed"

                self.agents.append(DiscoveredAgent(
                    name=f"{role} ({Path(rel).stem})",
                    source_file=rel,
                    source_line=lineno,
                    system_prompt=backstory,
                    model=None,
                    framework="crewai",
                    confidence=0.9,
                ))

        # AutoGen: ConversableAgent(system_message="...")
        for match in re.finditer(
            r'(?:ConversableAgent|AssistantAgent)\s*\([^)]*system_message\s*=\s*["\'](.+?)["\']',
            source, re.DOTALL
        ):
            prompt = match.group(1)
            if len(prompt) > 15:
                lineno = source[:match.start()].count("\n") + 1
                self.agents.append(DiscoveredAgent(
                    name=f"autogen_agent ({Path(rel).stem})",
                    source_file=rel,
                    source_line=lineno,
                    system_prompt=prompt,
                    model=None,
                    framework="autogen",
                    confidence=0.85,
                ))

    def _find_nearby_model(self, source: str, lineno: int) -> Optional[str]:
        """Search near a line number for a model string."""
        lines = source.split("\n")
        start = max(0, lineno - 10)
        end = min(len(lines), lineno + 10)
        window = "\n".join(lines[start:end])

        models = [
            "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo",
            "claude-sonnet-4-5-20250929", "claude-haiku-4-5-20251001", "claude-opus-4-5-20250918",
            "claude-3-5-sonnet", "claude-3-5-haiku",
        ]
        for m in models:
            if m in window:
                return m

        # Ollama models
        ollama_match = re.search(r'model\s*=\s*["\']([a-z0-9._:-]+)["\']', window)
        if ollama_match:
            return ollama_match.group(1)

        return None

    def _find_model_in_call(self, node: ast.Call, source: str) -> Optional[str]:
        """Find model parameter in a function call."""
        for kw in node.keywords:
            if kw.arg == "model":
                val = self._extract_string_value(kw.value, source)
                return val
        return None

    def _detect_framework(self, source: str) -> str:
        """Detect which framework this file uses."""
        if "from openai" in source or "import openai" in source:
            return "openai"
        if "from anthropic" in source or "import anthropic" in source:
            return "anthropic"
        if "from crewai" in source or "import crewai" in source:
            return "crewai"
        if "from langchain" in source or "import langchain" in source:
            return "langchain"
        if "from autogen" in source or "import autogen" in source:
            return "autogen"
        if "litellm" in source:
            return "litellm"
        return "unknown"

    def _find_tools_in_file(self, source: str) -> list[str]:
        """Find tool/function definitions in a file."""
        tools = []
        # OpenAI function calling
        for match in re.finditer(r'"name"\s*:\s*"(\w+)"', source):
            name = match.group(1)
            if name not in ("system", "user", "assistant", "function", "tool"):
                tools.append(name)
        # LangChain @tool decorator
        for match in re.finditer(r'@tool\s*\ndef\s+(\w+)', source):
            tools.append(match.group(1))
        return list(set(tools))[:20]  # Cap at 20

    # ── JavaScript/TypeScript parsing ────────────────────────────────

    def _parse_javascript(self, path: Path, rel: str):
        """Parse JS/TS files for system prompts."""
        source = path.read_text(errors="ignore")

        # OpenAI Node SDK: { role: "system", content: "..." }
        for match in re.finditer(
            r'role\s*:\s*["\']system["\']\s*,\s*content\s*:\s*[`"\'](.+?)[`"\']',
            source, re.DOTALL
        ):
            prompt = match.group(1).strip()
            if len(prompt) > 15:
                lineno = source[:match.start()].count("\n") + 1
                self.agents.append(DiscoveredAgent(
                    name=f"js_agent ({Path(rel).stem})",
                    source_file=rel,
                    source_line=lineno,
                    system_prompt=prompt,
                    model=self._find_js_model(source, lineno),
                    framework="openai-js",
                ))

        # Anthropic Node SDK: system: "..."
        for match in re.finditer(
            r'system\s*:\s*[`"\'](.{15,}?)[`"\']',
            source, re.DOTALL
        ):
            prompt = match.group(1).strip()
            lineno = source[:match.start()].count("\n") + 1
            self.agents.append(DiscoveredAgent(
                name=f"anthropic_js ({Path(rel).stem})",
                source_file=rel,
                source_line=lineno,
                system_prompt=prompt,
                model=None,
                framework="anthropic-js",
                confidence=0.7,
            ))

    def _find_js_model(self, source: str, near_line: int) -> Optional[str]:
        """Find model in JS source near a line."""
        models = ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"]
        lines = source.split("\n")
        start = max(0, near_line - 10)
        end = min(len(lines), near_line + 10)
        window = "\n".join(lines[start:end])
        for m in models:
            if m in window:
                return m
        return None

    # ── YAML parsing ─────────────────────────────────────────────────

    def _parse_yaml(self, path: Path, rel: str):
        """Parse YAML files for agent definitions."""
        try:
            import yaml
        except ImportError:
            # PyYAML not installed - skip YAML files
            return

        source = path.read_text(errors="ignore")
        try:
            data = yaml.safe_load(source)
        except Exception:
            return

        if not isinstance(data, dict):
            return

        # CrewAI agents.yaml format
        if "agents" in data and isinstance(data["agents"], dict):
            for agent_name, config in data["agents"].items():
                if isinstance(config, dict):
                    backstory = config.get("backstory", "")
                    role = config.get("role", agent_name)
                    goal = config.get("goal", "")

                    # Build effective system prompt from CrewAI fields
                    prompt_parts = []
                    if role:
                        prompt_parts.append(f"Role: {role}")
                    if goal:
                        prompt_parts.append(f"Goal: {goal}")
                    if backstory:
                        prompt_parts.append(f"Backstory: {backstory}")

                    system_prompt = "\n".join(prompt_parts)
                    if len(system_prompt) > 15:
                        tools = config.get("tools", [])
                        self.agents.append(DiscoveredAgent(
                            name=f"{agent_name}",
                            source_file=rel,
                            source_line=None,
                            system_prompt=system_prompt,
                            model=None,
                            framework="crewai",
                            tools=tools if isinstance(tools, list) else [],
                        ))

        # Generic YAML with system_prompt / prompt / instructions key
        for key in ("system_prompt", "prompt", "instructions", "system_message", "persona"):
            if key in data and isinstance(data[key], str) and len(data[key]) > 15:
                self.agents.append(DiscoveredAgent(
                    name=f"{key} ({Path(rel).stem})",
                    source_file=rel,
                    source_line=None,
                    system_prompt=data[key],
                    model=data.get("model"),
                    framework="yaml-config",
                ))

        # Nested agents list
        if "agents" in data and isinstance(data["agents"], list):
            for i, agent_config in enumerate(data["agents"]):
                if isinstance(agent_config, dict):
                    prompt = (
                        agent_config.get("system_prompt")
                        or agent_config.get("prompt")
                        or agent_config.get("instructions")
                        or agent_config.get("backstory")
                        or ""
                    )
                    if prompt and len(prompt) > 15:
                        name = agent_config.get("name") or agent_config.get("role") or f"agent_{i}"
                        self.agents.append(DiscoveredAgent(
                            name=name,
                            source_file=rel,
                            source_line=None,
                            system_prompt=prompt,
                            model=agent_config.get("model"),
                            framework="yaml-config",
                        ))

    # ── JSON config parsing ──────────────────────────────────────────

    def _parse_json_config(self, path: Path, rel: str):
        """Parse JSON config files."""
        source = path.read_text(errors="ignore")
        try:
            data = json.loads(source)
        except json.JSONDecodeError:
            return

        if not isinstance(data, dict):
            return

        # MCP server configs (Claude Desktop, Cursor, etc.)
        if "mcpServers" in data:
            self._extract_mcp_servers(data["mcpServers"], rel)

        # Generic prompt keys
        for key in ("system_prompt", "prompt", "instructions", "system_message"):
            if key in data and isinstance(data[key], str) and len(data[key]) > 15:
                self.agents.append(DiscoveredAgent(
                    name=f"{key} ({Path(rel).stem})",
                    source_file=rel,
                    source_line=None,
                    system_prompt=data[key],
                    model=data.get("model"),
                    framework="json-config",
                ))

        # OpenAI Assistants format
        if "instructions" in data and "model" in data:
            self.agents.append(DiscoveredAgent(
                name=data.get("name", f"assistant ({Path(rel).stem})"),
                source_file=rel,
                source_line=None,
                system_prompt=data["instructions"],
                model=data["model"],
                framework="openai-assistant",
            ))

    def _extract_mcp_servers(self, mcp_config: dict, rel: str):
        """Extract MCP server configs and check for issues."""
        servers = []
        warnings = []

        sensitive_paths = [".ssh", ".aws", ".gnupg", "credentials", "secrets", ".env"]
        sensitive_env_keys = [
            "API_KEY", "SECRET", "PASSWORD", "TOKEN", "CREDENTIAL",
            "DATABASE_URL", "PRIVATE_KEY",
        ]

        for name, config in mcp_config.items():
            server = {"name": name, **config}
            servers.append(server)

            # Check args for sensitive paths
            args = config.get("args", [])
            for arg in args:
                if isinstance(arg, str):
                    for sp in sensitive_paths:
                        if sp in arg:
                            warnings.append(
                                f"MCP server '{name}' has access to sensitive path: {arg}"
                            )

            # Check env for credentials
            env = config.get("env", {})
            for key, value in env.items():
                for sk in sensitive_env_keys:
                    if sk in key.upper() and value and not value.startswith("${"):
                        warnings.append(
                            f"MCP server '{name}' has hardcoded credential: {key}"
                        )

        if servers:
            # Create a pseudo-agent for the MCP config
            self.agents.append(DiscoveredAgent(
                name=f"mcp_config ({Path(rel).stem})",
                source_file=rel,
                source_line=None,
                system_prompt="[MCP server configuration - no system prompt, but tools need security review]",
                model=None,
                framework="mcp",
                mcp_servers=servers,
                warnings=warnings,
                confidence=0.5,  # Not a "real" agent, but needs scanning
            ))

    # ── TOML parsing ─────────────────────────────────────────────────

    def _parse_toml(self, path: Path, rel: str):
        """Parse TOML config files."""
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                return

        source = path.read_bytes()
        try:
            data = tomllib.loads(source.decode("utf-8"))
        except Exception:
            return

        # Check for prompt keys
        for key in ("system_prompt", "prompt", "instructions"):
            if key in data and isinstance(data[key], str) and len(data[key]) > 15:
                self.agents.append(DiscoveredAgent(
                    name=f"{key} ({Path(rel).stem})",
                    source_file=rel,
                    source_line=None,
                    system_prompt=data[key],
                    model=data.get("model"),
                    framework="toml-config",
                ))

    # ── Modelfile parsing ────────────────────────────────────────────

    def _parse_modelfile(self, path: Path, rel: str):
        """Parse Ollama Modelfile for SYSTEM directive."""
        source = path.read_text(errors="ignore")

        model = None
        system_prompt = None

        for line in source.split("\n"):
            stripped = line.strip()

            if stripped.upper().startswith("FROM "):
                model = stripped[5:].strip()

            if stripped.upper().startswith("SYSTEM "):
                # Single-line: SYSTEM "You are..."
                rest = stripped[7:].strip()
                if rest.startswith('"""'):
                    # Multi-line
                    start_idx = source.index('"""', source.index("SYSTEM")) + 3
                    end_idx = source.index('"""', start_idx)
                    system_prompt = source[start_idx:end_idx].strip()
                elif rest.startswith('"') and rest.endswith('"'):
                    system_prompt = rest[1:-1]
                else:
                    system_prompt = rest

        if system_prompt and len(system_prompt) > 5:
            self.agents.append(DiscoveredAgent(
                name=f"ollama ({model or 'unknown'})",
                source_file=rel,
                source_line=None,
                system_prompt=system_prompt,
                model=model,
                framework="ollama",
            ))

    # ── Cursorrules parsing ──────────────────────────────────────────

    def _parse_cursorrules(self, path: Path, rel: str):
        """Parse .cursorrules file as a system prompt."""
        content = path.read_text(errors="ignore").strip()
        if content and len(content) > 15:
            self.agents.append(DiscoveredAgent(
                name="cursor_rules",
                source_file=rel,
                source_line=None,
                system_prompt=content,
                model=None,
                framework="cursor",
            ))

    # ── Env file checking ────────────────────────────────────────────

    def _check_env_file(self, path: Path, rel: str):
        """Check .env files for exposed credentials (warning only)."""
        source = path.read_text(errors="ignore")
        dangerous_keys = ["API_KEY", "SECRET", "PASSWORD", "TOKEN", "PRIVATE_KEY"]

        for line in source.split("\n"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip("'\"")
                for dk in dangerous_keys:
                    if dk in key.upper() and value and len(value) > 5:
                        self.warnings.append(
                            f"Exposed credential in {rel}: {key}={value[:8]}***"
                        )

    # ── Well-known config locations ──────────────────────────────────

    def _check_claude_desktop(self):
        """Check Claude Desktop config if it exists."""
        import platform
        if platform.system() == "Darwin":
            config_path = Path.home() / "Library/Application Support/Claude/claude_desktop_config.json"
        elif platform.system() == "Windows":
            appdata = os.environ.get("APPDATA", "")
            config_path = Path(appdata) / "Claude/claude_desktop_config.json" if appdata else None
        else:
            config_path = Path.home() / ".config/claude/claude_desktop_config.json"

        if config_path and config_path.exists():
            try:
                data = json.loads(config_path.read_text())
                if "mcpServers" in data:
                    self._extract_mcp_servers(
                        data["mcpServers"],
                        str(config_path),
                    )
            except Exception:
                pass

    def _check_cursor_global(self):
        """Check global Cursor config if it exists."""
        cursor_mcp = Path.home() / ".cursor" / "mcp.json"
        if cursor_mcp.exists():
            try:
                data = json.loads(cursor_mcp.read_text())
                if "mcpServers" in data:
                    self._extract_mcp_servers(data["mcpServers"], str(cursor_mcp))
            except Exception:
                pass

    # ── Deduplication ────────────────────────────────────────────────

    def _deduplicate(self):
        """Remove duplicate agents (same prompt from different detection methods)."""
        seen_prompts = set()
        unique = []
        for agent in self.agents:
            # Normalize for comparison
            normalized = agent.system_prompt.strip().lower()[:200]
            if normalized not in seen_prompts:
                seen_prompts.add(normalized)
                unique.append(agent)
        self.agents = unique
