import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type {
  ShellToolsConfig,
  UnifiedPermissionConfig,
} from "./config-loader";

export const EXTENSION_ID = "pi-permission-system";

export interface CommandAnalysisConfig {
  enabled: boolean;
  provider: string;
  model: string;
  timeoutMs: number;
  maxCommandLength: number;
}

export interface PermissionSystemExtensionConfig {
  debugLog: boolean;
  permissionReviewLog: boolean;
  yoloMode: boolean;
  /** Require a confirming second press of a decision hotkey in the inline TUI dialog. Defaults to true. */
  doublePressToConfirm: boolean;
  /** Advisory LLM analysis rendered inside ask permission prompts. */
  commandAnalysis: CommandAnalysisConfig;
  /** Additional directories to auto-allow for reads as Pi infrastructure. */
  piInfrastructureReadPaths?: string[];
  /** Max length of the inline-JSON input preview shown in permission prompts. Defaults to 200. */
  toolInputPreviewMaxLength?: number;
  /** Max length of inline pattern/path summaries (grep/find/ls) in permission prompts. Defaults to 80. */
  toolTextSummaryMaxLength?: number;
  /** Non-bash tools that carry shell semantics, keyed by tool name. */
  shellTools?: ShellToolsConfig;
}

export const DEFAULT_COMMAND_ANALYSIS_CONFIG: CommandAnalysisConfig = {
  enabled: false,
  provider: "sub2api",
  model: "grok-4.5",
  timeoutMs: 30000,
  maxCommandLength: 4000,
};

export const DEFAULT_EXTENSION_CONFIG: PermissionSystemExtensionConfig = {
  debugLog: false,
  permissionReviewLog: true,
  yoloMode: false,
  doublePressToConfirm: true,
  commandAnalysis: { ...DEFAULT_COMMAND_ANALYSIS_CONFIG },
};

function resolveExtensionRoot(moduleUrl = import.meta.url): string {
  return join(dirname(fileURLToPath(moduleUrl)), "..");
}

export const EXTENSION_ROOT = resolveExtensionRoot();

const PERMISSION_POLICY_KEYS: ReadonlySet<string> = new Set([
  "defaultPolicy",
  "tools",
  "bash",
  "mcp",
  "skills",
  "special",
  "external_directory",
]);

export function detectMisplacedPermissionKeys(
  raw: Record<string, unknown>,
): string[] {
  return Object.keys(raw).filter((key) => PERMISSION_POLICY_KEYS.has(key));
}

export function normalizePermissionSystemConfig(
  raw: UnifiedPermissionConfig,
): PermissionSystemExtensionConfig {
  const result: PermissionSystemExtensionConfig = {
    debugLog: raw.debugLog === true,
    permissionReviewLog: raw.permissionReviewLog !== false,
    yoloMode: raw.yoloMode === true,
    doublePressToConfirm: raw.doublePressToConfirm !== false,
    commandAnalysis: {
      ...DEFAULT_COMMAND_ANALYSIS_CONFIG,
      ...(raw.commandAnalysis ?? {}),
      enabled: raw.commandAnalysis?.enabled === true,
    },
  };
  if (raw.piInfrastructureReadPaths !== undefined) {
    result.piInfrastructureReadPaths = raw.piInfrastructureReadPaths;
  }
  if (raw.toolInputPreviewMaxLength !== undefined) {
    result.toolInputPreviewMaxLength = raw.toolInputPreviewMaxLength;
  }
  if (raw.toolTextSummaryMaxLength !== undefined) {
    result.toolTextSummaryMaxLength = raw.toolTextSummaryMaxLength;
  }
  if (raw.shellTools !== undefined) {
    result.shellTools = raw.shellTools;
  }
  return result;
}

export function isYoloModeEnabled(
  config: PermissionSystemExtensionConfig,
): boolean {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-conversion -- typed as boolean but may be undefined at runtime (untyped callers); Boolean() guards against that
  return Boolean(config.yoloMode);
}

export function ensurePermissionSystemLogsDirectory(
  logsDir: string,
): string | undefined {
  try {
    mkdirSync(logsDir, { recursive: true });
    return undefined;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return `Failed to create permission-system log directory '${logsDir}': ${message}`;
  }
}
