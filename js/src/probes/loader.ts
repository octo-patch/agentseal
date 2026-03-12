/**
 * Custom probe loader — YAML/JSON probe definitions from files and directories.
 *
 * Port of Python agentseal/probes/loader.py.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { extname, join, resolve } from "node:path";

import { generateCanary } from "./base.js";

// ═══════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

const REQUIRED_FIELDS = ["probe_id", "category", "technique", "severity", "payload"];
const PROBE_ID_RE = /^[a-zA-Z0-9_-]+$/;
const RESERVED_PREFIXES = ["ext_", "inj_", "mcp_", "rag_", "mm_"];
const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low"]);
const MAX_PROBES_PER_FILE = 500;
const MAX_FILES_PER_DIR = 10;

// ═══════════════════════════════════════════════════════════════════════
// YAML PARSER
// ═══════════════════════════════════════════════════════════════════════

let _yamlParse: ((text: string) => any) | null = null;

/** Try to load js-yaml for YAML support. Falls back to JSON-only. */
function getYamlParser(): ((text: string) => any) | null {
  if (_yamlParse !== null) return _yamlParse;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const yaml = require("js-yaml");
    _yamlParse = (text: string) => yaml.safeLoad?.(text) ?? yaml.load(text);
    return _yamlParse;
  } catch {
    return null;
  }
}

function parseFileContent(filePath: string, content: string): any {
  const ext = extname(filePath).toLowerCase();
  if (ext === ".json") return JSON.parse(content);

  // Try YAML
  const yamlParse = getYamlParser();
  if (yamlParse) return yamlParse(content);

  // Fallback: try JSON anyway (YAML is a superset of JSON)
  try {
    return JSON.parse(content);
  } catch {
    throw new Error(
      `Cannot parse ${filePath}: js-yaml is not installed. ` +
      `Install it with: npm install js-yaml`
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════════════════════════════

function validateProbe(probe: Record<string, any>, source: string): string[] {
  const errors: string[] = [];

  // Required fields
  for (const field of REQUIRED_FIELDS) {
    if (!(field in probe)) {
      errors.push(`Missing required field '${field}'`);
    }
  }
  if (errors.length > 0) return errors;

  // probe_id format
  const pid = probe.probe_id;
  if (typeof pid !== "string" || !PROBE_ID_RE.test(pid)) {
    errors.push(
      `probe_id '${pid}' must match ^[a-zA-Z0-9_-]+$ (alphanumeric, underscore, hyphen)`,
    );
  }

  // Reserved prefix check
  if (typeof pid === "string") {
    for (const prefix of RESERVED_PREFIXES) {
      if (pid.startsWith(prefix)) {
        errors.push(`probe_id '${pid}' uses reserved prefix '${prefix}'`);
        break;
      }
    }
  }

  // Severity
  const sev = probe.severity;
  if (typeof sev === "string") {
    if (!VALID_SEVERITIES.has(sev.toLowerCase())) {
      const valid = [...VALID_SEVERITIES].sort().join(", ");
      errors.push(`Invalid severity '${sev}'; must be one of: ${valid}`);
    }
  } else {
    errors.push(`Severity must be a string, got ${typeof sev}`);
  }

  // Payload type
  const payload = probe.payload;
  if (typeof payload !== "string" && !Array.isArray(payload)) {
    errors.push(`payload must be a string or list of strings, got ${typeof payload}`);
  } else if (Array.isArray(payload)) {
    for (let j = 0; j < payload.length; j++) {
      if (typeof payload[j] !== "string") {
        errors.push(`payload[${j}] must be a string, got ${typeof payload[j]}`);
      }
    }
  }

  // Category and technique
  if (typeof probe.category !== "string") {
    errors.push(`category must be a string, got ${typeof probe.category}`);
  }
  if (typeof probe.technique !== "string") {
    errors.push(`technique must be a string, got ${typeof probe.technique}`);
  }

  // Tags
  if ("tags" in probe && !Array.isArray(probe.tags)) {
    errors.push(`tags must be a list, got ${typeof probe.tags}`);
  }

  // Remediation
  if ("remediation" in probe && typeof probe.remediation !== "string") {
    errors.push(`remediation must be a string, got ${typeof probe.remediation}`);
  }

  // Type field
  const probeType = probe.type ?? "extraction";
  if (probeType !== "extraction" && probeType !== "injection") {
    errors.push(`type must be 'extraction' or 'injection', got '${probeType}'`);
  }

  // Canary position
  const canaryPos = probe.canary_position ?? "suffix";
  if (!["suffix", "inline", "prefix"].includes(canaryPos)) {
    errors.push(`canary_position must be 'suffix', 'inline', or 'prefix', got '${canaryPos}'`);
  }

  return errors;
}

// ═══════════════════════════════════════════════════════════════════════
// BUILD PROBE
// ═══════════════════════════════════════════════════════════════════════

function buildProbe(raw: Record<string, any>): Record<string, any> {
  const probeType = raw.type ?? "extraction";
  const payload = raw.payload;
  const isMultiTurn = raw.is_multi_turn ?? Array.isArray(payload);

  const probe: Record<string, any> = {
    probe_id: raw.probe_id,
    category: raw.category,
    technique: raw.technique,
    severity: raw.severity.toLowerCase(),
    payload,
    type: probeType,
    is_multi_turn: isMultiTurn,
  };

  // Canary handling
  if (probeType === "injection") {
    probe.canary = raw.canary ?? generateCanary();
    probe.canary_position = raw.canary_position ?? "suffix";
  }

  // Optional fields
  if ("tags" in raw) probe.tags = raw.tags;
  if ("remediation" in raw) probe.remediation = raw.remediation;

  return probe;
}

// ═══════════════════════════════════════════════════════════════════════
// FILE PARSING
// ═══════════════════════════════════════════════════════════════════════

function parseProbeFile(filePath: string): Array<Record<string, any>> {
  const content = readFileSync(filePath, "utf-8");
  const data = parseFileContent(filePath, content);

  if (data === null || data === undefined) return [];
  if (typeof data !== "object" || Array.isArray(data)) {
    throw new Error(`Expected a mapping at top level in ${filePath}`);
  }

  // Version check
  const version = data.version;
  if (version === undefined || version === null) {
    throw new Error(`Missing 'version' field in ${filePath}`);
  }
  if (version !== 1) {
    throw new Error(
      `Unsupported probe file version ${version} in ${filePath}; only version 1 is supported`,
    );
  }

  const probesRaw = data.probes;
  if (probesRaw === undefined || probesRaw === null) return [];
  if (!Array.isArray(probesRaw)) {
    throw new Error(`'probes' must be a list in ${filePath}`);
  }
  if (probesRaw.length > MAX_PROBES_PER_FILE) {
    throw new Error(
      `File contains ${probesRaw.length} probes, maximum is ${MAX_PROBES_PER_FILE}: ${filePath}`,
    );
  }

  const idsInFile = new Set<string>();
  const validated: Array<Record<string, any>> = [];

  for (let i = 0; i < probesRaw.length; i++) {
    const raw = probesRaw[i];
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      throw new Error(`Probe #${i + 1} is not a mapping in ${filePath}`);
    }

    const source = `${filePath}:probe[${i}]`;
    const errors = validateProbe(raw, source);
    if (errors.length > 0) {
      throw new Error(`Validation errors in ${source}:\n  ${errors.join("\n  ")}`);
    }

    const pid = raw.probe_id;
    if (idsInFile.has(pid)) {
      throw new Error(`Duplicate probe_id '${pid}' within file ${filePath}`);
    }
    idsInFile.add(pid);

    validated.push(buildProbe(raw));
  }

  return validated;
}

// ═══════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════

function isYamlFile(name: string): boolean {
  const ext = extname(name).toLowerCase();
  return ext === ".yaml" || ext === ".yml" || ext === ".json";
}

/**
 * Load custom probes from a YAML/JSON file or directory.
 *
 * @param path Path to a .yaml/.json file or directory containing them.
 * @returns List of validated probe dicts.
 */
export function loadCustomProbes(path: string): Array<Record<string, any>> {
  if (!existsSync(path)) {
    throw new Error(`Probe path does not exist: ${path}`);
  }

  const stat = statSync(path);

  if (stat.isFile()) {
    return parseProbeFile(path);
  }

  if (stat.isDirectory()) {
    const entries = readdirSync(path).filter(isYamlFile).sort();

    // Deduplicate by resolved path
    const seenPaths = new Set<string>();
    const uniqueFiles: string[] = [];
    for (const entry of entries) {
      const full = resolve(join(path, entry));
      if (!seenPaths.has(full)) {
        seenPaths.add(full);
        uniqueFiles.push(join(path, entry));
      }
    }

    if (uniqueFiles.length > MAX_FILES_PER_DIR) {
      throw new Error(
        `Directory contains ${uniqueFiles.length} YAML files, maximum is ${MAX_FILES_PER_DIR}: ${path}`,
      );
    }

    const allProbes: Array<Record<string, any>> = [];
    const allIds = new Set<string>();

    for (const yf of uniqueFiles) {
      let probes: Array<Record<string, any>>;
      try {
        probes = parseProbeFile(yf);
      } catch {
        continue; // Skip files with errors
      }

      for (const p of probes) {
        const pid = p.probe_id as string;
        if (allIds.has(pid)) {
          throw new Error(`Duplicate probe_id '${pid}' found across files in ${path}`);
        }
        allIds.add(pid);
      }

      allProbes.push(...probes);
    }

    return allProbes;
  }

  throw new Error(`Path is neither a file nor directory: ${path}`);
}

/**
 * Auto-discover probes from ~/.agentseal/probes/ and .agentseal/probes/.
 *
 * @returns Combined list of probes from both locations.
 */
export function loadAllCustomProbes(): Array<Record<string, any>> {
  const searchDirs = [
    join(homedir(), ".agentseal", "probes"),
  ];

  try {
    searchDirs.push(join(process.cwd(), ".agentseal", "probes"));
  } catch {
    // cwd may fail
  }

  const allProbes: Array<Record<string, any>> = [];
  const allIds = new Set<string>();

  for (const d of searchDirs) {
    if (!existsSync(d) || !statSync(d).isDirectory()) continue;

    const entries = readdirSync(d).filter(isYamlFile).sort();
    if (entries.length > MAX_FILES_PER_DIR) continue;

    for (const entry of entries) {
      const yf = join(d, entry);
      let probes: Array<Record<string, any>>;
      try {
        probes = parseProbeFile(yf);
      } catch {
        continue;
      }

      for (const p of probes) {
        const pid = p.probe_id as string;
        if (allIds.has(pid)) {
          throw new Error(`Duplicate probe_id '${pid}' found during auto-discovery`);
        }
        allIds.add(pid);
      }

      allProbes.push(...probes);
    }
  }

  return allProbes;
}

// Re-export for convenience
export { validateProbe, buildProbe, parseProbeFile };
