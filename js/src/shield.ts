/**
 * Shield — continuous filesystem monitoring for AI agent security.
 *
 * Watches skill directories, MCP config files, and agent config dirs.
 * When a file changes, triggers an incremental scan and optionally sends
 * desktop notifications.
 *
 * Uses Node.js built-in fs.watch (recursive on macOS/Windows).
 *
 * Port of Python agentseal/shield.py.
 */

import { existsSync, readFileSync, statSync, watch, type FSWatcher } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, extname, join, resolve } from "node:path";

import { BaselineStore } from "./baselines.js";
import { Blocklist } from "./blocklist.js";
import { GuardVerdict, type SkillFinding } from "./guard-models.js";
import {
  getWellKnownConfigs,
  stripJsonComments,
  PROJECT_SKILL_DIRS,
  PROJECT_SKILL_FILES,
} from "./machine-discovery.js";
import { MCPConfigChecker } from "./mcp-checker.js";
import { Notifier } from "./notify.js";
import { SkillScanner } from "./skill-scanner.js";
import { analyzeToxicFlows } from "./toxic-flows.js";
import { scanSkillFile, computeVerdict } from "./guard.js";

// ═══════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════

/** Callback: (eventType, path, resultSummary) */
export type ShieldCallback = (eventType: string, path: string, summary: string) => void;

export interface ShieldOptions {
  /** Enable semantic analysis. Default: false */
  semantic?: boolean;
  /** Enable desktop notifications. Default: true */
  notify?: boolean;
  /** Debounce seconds for filesystem events. Default: 2.0 */
  debounceSeconds?: number;
  /** Callback for shield events. */
  onEvent?: ShieldCallback;
}

// ═══════════════════════════════════════════════════════════════════════
// DEBOUNCED HANDLER
// ═══════════════════════════════════════════════════════════════════════

/**
 * Per-path debouncing for filesystem events.
 * Accumulates events and fires only after a quiet period.
 */
export class DebouncedHandler {
  private _onChange: (filePath: string) => void;
  private _debounceMs: number;
  private _timers = new Map<string, ReturnType<typeof setTimeout>>();

  constructor(onChange: (filePath: string) => void, debounceMs = 2000) {
    this._onChange = onChange;
    this._debounceMs = debounceMs;
  }

  /** Handle a filesystem event. Skips directories and temp files. */
  handleEvent(filePath: string, isDirectory = false): void {
    if (isDirectory) return;

    // Skip temp/swap files from editors
    if (
      filePath.endsWith("~") ||
      filePath.endsWith(".swp") ||
      filePath.endsWith(".swx") ||
      filePath.endsWith(".tmp") ||
      filePath.endsWith(".DS_Store")
    ) {
      return;
    }

    // Cancel existing timer for this path
    const existing = this._timers.get(filePath);
    if (existing !== undefined) {
      clearTimeout(existing);
    }

    // Schedule new scan after debounce
    const timer = setTimeout(() => {
      this._timers.delete(filePath);
      this._onChange(filePath);
    }, this._debounceMs);

    this._timers.set(filePath, timer);
  }

  /** Cancel all pending timers. */
  cancelAll(): void {
    for (const timer of this._timers.values()) {
      clearTimeout(timer);
    }
    this._timers.clear();
  }

  /** Number of pending timers (for testing). */
  get pendingCount(): number {
    return this._timers.size;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// PATH CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════

const MCP_CONFIG_NAMES = new Set([
  "claude_desktop_config.json",
  "mcp.json",
  "mcp_config.json",
  "cline_mcp_settings.json",
]);

const AGENT_PATH_MARKERS = [
  ".claude", ".cursor", ".gemini", ".codex", ".kiro", ".opencode",
  ".continue", ".aider", ".roo", ".amp", "windsurf", "zed",
];

/** Classify a changed file as 'skill', 'mcp_config', or 'unknown'. */
export function classifyPath(filePath: string): string {
  const name = basename(filePath).toLowerCase();
  const ext = extname(filePath).toLowerCase();

  // MCP config files
  if (MCP_CONFIG_NAMES.has(name)) return "mcp_config";

  // Agent settings that may contain MCP config
  if ((name === "settings.json" || name === "config.json")) {
    const lower = filePath.toLowerCase();
    if (AGENT_PATH_MARKERS.some((marker) => lower.includes(marker))) {
      return "mcp_config";
    }
  }

  // Skill files
  if ([".md", ".txt", ".yaml", ".yml"].includes(ext)) return "skill";
  if (name === ".cursorrules") return "skill";

  return "unknown";
}

// ═══════════════════════════════════════════════════════════════════════
// WATCH PATH COLLECTION
// ═══════════════════════════════════════════════════════════════════════

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function fileExists(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

/** Collect all paths that shield should monitor. */
export function collectWatchPaths(homeOverride?: string): { dirs: string[]; files: string[] } {
  const home = homeOverride ?? homedir();
  const plat =
    process.platform === "darwin"
      ? "Darwin"
      : process.platform === "win32"
        ? "Windows"
        : "Linux";

  const configs = getWellKnownConfigs();

  const dirs: string[] = [];
  const files: string[] = [];
  const seen = new Set<string>();

  const addDir = (p: string) => {
    const resolved = resolve(p);
    if (!seen.has(resolved) && isDir(p)) {
      seen.add(resolved);
      dirs.push(p);
    }
  };

  const addFile = (p: string) => {
    const resolved = resolve(p);
    if (!seen.has(resolved) && fileExists(p)) {
      seen.add(resolved);
      files.push(p);
    }
  };

  // MCP config files from all known agents — watch parent directories
  for (const cfg of configs) {
    const paths = cfg.paths as Record<string, string | undefined>;
    let cfgPath = paths[plat] ?? paths.all;
    if (!cfgPath) continue;
    cfgPath = cfgPath.replace(/^~/, home);
    const parent = dirname(cfgPath);
    if (isDir(parent)) addDir(parent);
  }

  // Skill directories
  for (const skillDirRel of PROJECT_SKILL_DIRS) {
    const skillDir = join(home, skillDirRel);
    addDir(skillDir);
  }

  // Single skill files — watch parent dirs
  for (const skillFileRel of PROJECT_SKILL_FILES) {
    const skillFile = join(home, skillFileRel);
    const parent = dirname(skillFile);
    if (isDir(parent)) addDir(parent);
  }

  // CWD skill files
  try {
    const cwd = process.cwd();
    for (const name of [".cursorrules", "CLAUDE.md", ".github"]) {
      const candidate = join(cwd, name);
      if (isDir(candidate)) addDir(candidate);
      else if (fileExists(candidate)) addFile(candidate);
    }
  } catch {
    // ignore
  }

  return { dirs, files };
}

// ═══════════════════════════════════════════════════════════════════════
// SHIELD CLASS
// ═══════════════════════════════════════════════════════════════════════

export class Shield {
  private _onEvent: ShieldCallback;
  private _notifier: Notifier;
  private _scanner: SkillScanner;
  private _mcpChecker: MCPConfigChecker;
  private _blocklist: Blocklist;
  private _baselineStore: BaselineStore;
  private _debounceMs: number;
  private _watchers: FSWatcher[] = [];
  private _handler: DebouncedHandler | null = null;
  private _running = false;
  private _scanCount = 0;
  private _threatCount = 0;

  constructor(options: ShieldOptions = {}) {
    this._onEvent = options.onEvent ?? (() => {});
    this._notifier = new Notifier(options.notify ?? true);
    this._scanner = new SkillScanner();
    this._mcpChecker = new MCPConfigChecker();
    this._blocklist = new Blocklist();
    this._baselineStore = new BaselineStore();
    this._debounceMs = (options.debounceSeconds ?? 2.0) * 1000;
  }

  get scanCount(): number {
    return this._scanCount;
  }

  get threatCount(): number {
    return this._threatCount;
  }

  get running(): boolean {
    return this._running;
  }

  /** Handle a single file change event. */
  handleChange(filePath: string): void {
    if (!fileExists(filePath)) return;

    const fileType = classifyPath(filePath);
    this._scanCount++;

    if (fileType === "skill") {
      this._scanSkill(filePath);
    } else if (fileType === "mcp_config") {
      this._scanMcpConfig(filePath);
    } else {
      // Unknown file type — try skill scan for text-like files
      const ext = extname(filePath).toLowerCase();
      if ([".md", ".txt", ".yaml", ".yml"].includes(ext)) {
        this._scanSkill(filePath);
      }
    }
  }

  private _scanSkill(filePath: string): void {
    try {
      const result = scanSkillFile(filePath, this._scanner, this._blocklist);

      if (result.verdict === GuardVerdict.DANGER) {
        this._threatCount++;
        const detail = result.findings[0]?.title ?? "Threat detected";
        this._onEvent("threat", filePath, `DANGER - ${detail}`);
        this._notifier.notifyThreat(
          result.name,
          "Skill",
          result.findings[0]?.severity ?? "high",
          detail,
        );
      } else if (result.verdict === GuardVerdict.WARNING) {
        const detail = result.findings[0]?.title ?? "Warning";
        this._onEvent("warning", filePath, `WARNING - ${detail}`);
      } else {
        this._onEvent("clean", filePath, "CLEAN");
      }
    } catch {
      this._onEvent("error", filePath, "Failed to scan file");
    }
  }

  private _scanMcpConfig(filePath: string): void {
    let data: Record<string, any>;
    try {
      const raw = readFileSync(filePath, "utf-8");
      data = JSON.parse(stripJsonComments(raw));
    } catch {
      this._onEvent("error", filePath, "Failed to parse config");
      return;
    }

    // Try common MCP keys
    let servers: Record<string, any> = {};
    for (const key of ["mcpServers", "servers", "context_servers"]) {
      if (key in data && typeof data[key] === "object" && data[key] !== null) {
        servers = data[key];
        break;
      }
    }

    if (Object.keys(servers).length === 0) {
      this._onEvent("clean", filePath, "No MCP servers in config");
      return;
    }

    let hasThreat = false;
    const serverDicts: Array<Record<string, any>> = [];

    for (const [srvName, srvCfg] of Object.entries(servers)) {
      if (typeof srvCfg !== "object" || srvCfg === null) continue;
      const serverDict = { name: srvName, source_file: filePath, ...srvCfg };
      serverDicts.push(serverDict);

      // MCP config check
      const result = this._mcpChecker.check(serverDict);
      if (result.verdict === GuardVerdict.DANGER) {
        hasThreat = true;
        this._threatCount++;
        const detail = result.findings[0]?.title ?? "Threat detected";
        this._onEvent("threat", filePath, `MCP '${srvName}': DANGER - ${detail}`);
        this._notifier.notifyThreat(
          srvName,
          "MCP Server",
          result.findings[0]?.severity ?? "high",
          detail,
        );
      } else if (result.verdict === GuardVerdict.WARNING) {
        const detail = result.findings[0]?.title ?? "Warning";
        this._onEvent("warning", filePath, `MCP '${srvName}': WARNING - ${detail}`);
      }

      // Baseline check (rug pull detection)
      const change = this._baselineStore.checkServer(serverDict);
      if (change && (change.change_type === "config_changed" || change.change_type === "binary_changed")) {
        this._threatCount++;
        this._onEvent("warning", filePath, `BASELINE: ${change.detail}`);
        this._notifier.notifyThreat(srvName, "MCP Baseline", "high", change.detail);
      }
    }

    // Toxic flow analysis across all servers
    if (serverDicts.length >= 2) {
      const flows = analyzeToxicFlows(serverDicts);
      for (const flow of flows) {
        this._onEvent("warning", filePath, `TOXIC FLOW: ${flow.title}`);
      }
    }

    if (!hasThreat) {
      this._onEvent("clean", filePath, `MCP config OK (${Object.keys(servers).length} servers)`);
    }
  }

  /**
   * Start watching. Returns { dirsWatched, filesWatched }.
   *
   * Uses Node.js fs.watch with recursive option (macOS/Windows).
   * Does NOT block — call stop() to clean up.
   */
  start(homeOverride?: string): { dirsWatched: number; filesWatched: number } {
    const { dirs, files } = collectWatchPaths(homeOverride);

    this._handler = new DebouncedHandler(
      (fp) => this.handleChange(fp),
      this._debounceMs,
    );

    let watchedCount = 0;

    for (const d of dirs) {
      try {
        const watcher = watch(d, { recursive: true }, (_eventType, filename) => {
          if (filename) {
            this._handler?.handleEvent(join(d, filename));
          }
        });
        this._watchers.push(watcher);
        watchedCount++;
      } catch {
        // Permission denied or path disappeared
      }
    }

    // For individual files, watch their parent directory (non-recursive)
    const fileParents = new Set<string>();
    for (const f of files) {
      const parent = dirname(f);
      if (!fileParents.has(parent)) {
        fileParents.add(parent);
        try {
          const watcher = watch(parent, { recursive: false }, (_eventType, filename) => {
            if (filename) {
              this._handler?.handleEvent(join(parent, filename));
            }
          });
          this._watchers.push(watcher);
          watchedCount++;
        } catch {
          // Permission denied
        }
      }
    }

    this._running = true;
    return { dirsWatched: watchedCount, filesWatched: files.length };
  }

  /** Stop the filesystem watchers. */
  stop(): void {
    this._running = false;
    if (this._handler) {
      this._handler.cancelAll();
      this._handler = null;
    }
    for (const w of this._watchers) {
      try {
        w.close();
      } catch {
        // ignore
      }
    }
    this._watchers = [];
  }
}
