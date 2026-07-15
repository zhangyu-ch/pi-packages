import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type {
  PermissionPromptDecision,
  RequestPermissionOptions,
} from "#src/authority/permission-dialog";
import type {
  PermissionPromptUi,
  PromptPreferences,
  requestPermissionDecision,
} from "#src/authority/permission-prompt-component";
import {
  analyzePermissionCommand,
  type CommandAnalysisOutcome,
  formatPermissionCommandAnalysis,
} from "#src/command-analysis";
import { buildForwardedScopeLabels } from "#src/pattern-suggest";
import {
  emitUiPromptEvent,
  type PermissionEventBus,
} from "#src/permission-events";
import { buildUiPrompt } from "#src/permission-ui-prompt";
import type { DebugReviewLogger } from "#src/session-logger";
import type { Authorizer } from "./authorizer";
import type { PromptPermissionDetails } from "./permission-prompter";

/** Dependencies required by {@link LocalUserAuthorizer}. */
export interface LocalUserAuthorizerDeps {
  /** The active session's UI surface (select/input plus the inline `custom` dialog). */
  ui: PermissionPromptUi;
  /** Full context used only for the separately configured advisory model call. */
  context: ExtensionContext;
  /** The session run mode; the dispatcher renders the inline dialog only in `"tui"`. */
  mode: ExtensionContext["mode"];
  /** Event bus used for the `permissions:ui_prompt` broadcast. */
  events: PermissionEventBus;
  /** Read live at prompt time so a settings-modal toggle takes effect on the next prompt. */
  getPromptPreferences: () => PromptPreferences;
  /** Injected for testability; production callers pass the real function. */
  requestPermissionDecision: typeof requestPermissionDecision;
  /** Writes command-analysis success/failure diagnostics. */
  logger: DebugReviewLogger;
}

/**
 * Authorizer for a session with an active UI: prompt the human here.
 *
 * Emits the `permissions:ui_prompt` broadcast (moved here from
 * `PermissionPrompter`'s `ctx.hasUI` arm) before showing the dialog, so
 * observers know a decision is imminent. This is the single emit site: a
 * forwarded ask carries its provenance on `details.forwarding`, which this
 * class renders (populated `forwarding` context + "(Subagent)" title) so the
 * broadcast stays non-degraded (#292) without a second emission path.
 */
export class LocalUserAuthorizer implements Authorizer {
  constructor(private readonly deps: LocalUserAuthorizerDeps) {}

  async authorize(
    details: PromptPermissionDetails,
  ): Promise<PermissionPromptDecision> {
    const uiPrompt = buildUiPrompt(details);
    const preferences = this.deps.getPromptPreferences();
    const outcome = await analyzePermissionCommand(
      this.deps.context,
      preferences.commandAnalysis,
      details,
    ).catch((error: unknown) => ({
      failure: {
        code: "unknown" as const,
        message: error instanceof Error ? error.message : String(error),
      },
    }));
    logCommandAnalysisOutcome(this.deps.logger, details, preferences, outcome);
    const message =
      details.message +
      formatPermissionCommandAnalysis(outcome, preferences.commandAnalysis);
    emitUiPromptEvent(this.deps.events, uiPrompt);
    return this.deps.requestPermissionDecision(
      {
        mode: this.deps.mode,
        ui: this.deps.ui,
        doublePressToConfirm: preferences.doublePressToConfirm,
      },
      details.forwarding
        ? "Permission Required (Subagent)"
        : "Permission Required",
      message,
      buildRequestOptions(details),
    );
  }
}

/**
 * A forwarded ask carrying a session-approval suggestion offers the scope
 * choice (subagent vs whole session); any other ask keeps its single
 * "for this session" option (custom label when the gate supplied one).
 */
function buildRequestOptions(
  details: PromptPermissionDetails,
): RequestPermissionOptions | undefined {
  const pattern = details.sessionApproval?.patterns[0];
  if (details.forwarding && details.sessionApproval && pattern) {
    return {
      sessionScope: buildForwardedScopeLabels(
        details.forwarding.requesterAgentName,
        details.sessionApproval.surface,
        pattern,
      ),
    };
  }
  return details.sessionLabel
    ? { sessionLabel: details.sessionLabel }
    : undefined;
}

function logCommandAnalysisOutcome(
  logger: DebugReviewLogger,
  details: PromptPermissionDetails,
  preferences: PromptPreferences,
  outcome: CommandAnalysisOutcome,
): void {
  if (!preferences.commandAnalysis.enabled) return;

  const base = {
    requestId: details.requestId,
    source: details.source,
    surface: details.surface ?? details.toolName ?? null,
    toolName: details.toolName ?? null,
    provider: preferences.commandAnalysis.provider,
    model: preferences.commandAnalysis.model,
    thinkingLevel: preferences.commandAnalysis.thinkingLevel,
    timeoutMs: preferences.commandAnalysis.timeoutMs,
    durationMs: outcome.durationMs ?? null,
  };

  if (outcome.analysis) {
    logger.debug("command_analysis.ok", {
      ...base,
      intentCategory: outcome.analysis.intentCategory,
      riskLevel: outcome.analysis.riskLevel,
      hasSafetyRisk: outcome.analysis.hasSafetyRisk,
    });
    return;
  }

  if (outcome.failure) {
    // Review log is on by default; failures stay visible without enabling debugLog.
    logger.review("command_analysis.failed", {
      ...base,
      code: outcome.failure.code,
      message: outcome.failure.message,
      details: outcome.failure.details ?? null,
    });
    logger.debug("command_analysis.failed", {
      ...base,
      code: outcome.failure.code,
      message: outcome.failure.message,
      details: outcome.failure.details ?? null,
    });
  }
}
