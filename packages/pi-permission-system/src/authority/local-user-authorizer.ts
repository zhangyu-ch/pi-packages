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
  formatPermissionCommandAnalysis,
} from "#src/command-analysis";
import { buildForwardedScopeLabels } from "#src/pattern-suggest";
import {
  emitUiPromptEvent,
  type PermissionEventBus,
} from "#src/permission-events";
import { buildUiPrompt } from "#src/permission-ui-prompt";
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
    const analysis = await analyzePermissionCommand(
      this.deps.context,
      preferences.commandAnalysis,
      details,
    ).catch(() => undefined);
    const message =
      details.message +
      formatPermissionCommandAnalysis(analysis, preferences.commandAnalysis);
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
