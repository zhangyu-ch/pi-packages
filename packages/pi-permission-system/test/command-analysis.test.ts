import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import type { PromptPermissionDetails } from "#src/authority/permission-prompter";
import {
  analyzePermissionCommand,
  formatPermissionCommandAnalysis,
} from "#src/command-analysis";
import type { CommandAnalysisConfig } from "#src/extension-config";

const disabledConfig: CommandAnalysisConfig = {
  enabled: false,
  provider: "",
  model: "",
  timeoutMs: 30000,
  maxCommandLength: 4000,
};

const enabledConfig: CommandAnalysisConfig = {
  ...disabledConfig,
  enabled: true,
  provider: "sub2api",
  model: "grok-4.5",
};

function makeDetails(): PromptPermissionDetails {
  return {
    requestId: "request-1",
    source: "tool_call",
    agentName: null,
    toolName: "bash",
    command: "rm -rf dist",
    message: "Allow bash command?",
  };
}

function makeContext(): ExtensionContext {
  return {
    cwd: "/test/project",
    modelRegistry: {
      find: vi.fn().mockReturnValue(undefined),
    },
  } as unknown as ExtensionContext;
}

describe("permission command analysis", () => {
  it("does not consult the model registry when disabled", async () => {
    const context = makeContext();

    const result = await analyzePermissionCommand(
      context,
      disabledConfig,
      makeDetails(),
    );

    expect(result).toBeUndefined();
    expect(context.modelRegistry.find).not.toHaveBeenCalled();
  });

  it("degrades safely when the configured model is unavailable", async () => {
    const result = await analyzePermissionCommand(
      makeContext(),
      enabledConfig,
      makeDetails(),
    );

    expect(result).toBeUndefined();
    expect(formatPermissionCommandAnalysis(result, enabledConfig)).toBe(
      "\n\n智能安全分析：暂时不可用，请直接审查上方原始请求。",
    );
  });

  it("formats a structured risk assessment for the ask page", () => {
    const result = formatPermissionCommandAnalysis(
      {
        intentCategory: "文件删除",
        intentSummary: "删除构建产物目录",
        hasSafetyRisk: true,
        safetyRisks: ["路径错误时可能误删其他文件", "操作不可直接撤销"],
        riskLevel: "高",
        recommendation: "确认路径后再执行",
      },
      enabledConfig,
    );

    expect(result).toBe(
      [
        "",
        "智能安全分析",
        "意图：文件删除 — 删除构建产物目录",
        "存在安全隐患：是",
        "风险等级：高",
        "具体风险：",
        "  • 路径错误时可能误删其他文件\n  • 操作不可直接撤销",
        "建议：确认路径后再执行",
      ].join("\n"),
    );
  });
});
