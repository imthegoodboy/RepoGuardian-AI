import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import manifest from "../../manifest.json" with { type: "json" };
import appMeta from "../../app.json" with { type: "json" };
import packageMeta from "../../package.json" with { type: "json" };

const root = join(__dirname, "..", "..");

describe("repoguardian-ai manifest and bundle", () => {
  it("aligns release versions, bundled tool, and Marketplace assets", () => {
    expect(appMeta.version).toBe("0.2.0");
    expect(packageMeta.version).toBe(appMeta.version);
    expect(manifest.required_executas[0].min_version).toBe("0.2.0");
    expect(appMeta.bundled_executas["repoguardian-scanner"].path).toBe("./executas/repoguardian-scanner");
    expect(appMeta.screenshots).toHaveLength(3);
    expect(appMeta.screenshots.every((url) => url.startsWith("https://raw.githubusercontent.com/"))).toBe(true);
  });

  it("declares only the host APIs used by the bundle", () => {
    expect(manifest.schema).toBe(2);
    expect(manifest.permissions).toEqual(
      expect.arrayContaining(["tools.invoke", "llm.complete", "storage.read", "storage.write", "chat.append_artifact"]),
    );
    expect(manifest.ui.host_api.llm).toEqual(["complete"]);
    expect(manifest.ui.host_api.tools).toEqual(["required:bundled:repoguardian-scanner"]);
    expect(manifest.ui.host_api.storage).toEqual(expect.arrayContaining(["get", "set", "delete", "list"]));
    expect(manifest.ui.host_api.chat).toEqual(["append_artifact"]);
    expect(manifest.ui.host_api.upload).toEqual(["inline"]);
    expect(manifest.ui.host_api.agent.session.auto).toBe(true);
    expect(manifest.ui.host_api.agent.session.fixed.client_ids).toEqual([]);
  });

  it("uses the publish-time tool-id sidecar with a dev fallback", () => {
    const app = readFileSync(join(root, "bundle", "app.js"), "utf8");
    expect(app).toContain("__ANNA_TOOL_IDS__");
    expect(app).toContain("repoguardian-scanner");
    expect(app).toContain("IS_LOCAL_ANNA_DEV");
    expect(app).toContain("tool-nikku696969-repoguardian-scanner-3tsnh6fp");
  });

  it("passes long tool timeouts to both the scanner and Anna RPC client", () => {
    const app = readFileSync(join(root, "bundle", "app.js"), "utf8");
    expect(app).toContain("RPC_TIMEOUT_PADDING_MS");
    expect(app).toContain("const payload = { tool_id: TOOL_ID, method, args, timeoutMs }");
    expect(app).toContain("state.anna.tools.invoke(payload, { timeoutMs: timeoutMs + RPC_TIMEOUT_PADDING_MS })");
  });

  it("guards Anna risk sampling behind host capabilities", () => {
    const app = readFileSync(join(root, "bundle", "app.js"), "utf8");
    expect(app).toContain("function hostSupportsAnnaRiskAnalysis()");
    expect(app).toContain("function canUseDirectAnnaLlm()");
    expect(app).toContain("enhanceRiskWithDirectAnnaLlm");
    expect(app).toContain("host_sampling: hostSampling");
    expect(app).toContain("scope === \"llm.sample\"");
    expect(app).toContain("scope === \"sampling.createMessage\"");
  });

  it("does not persist runtime GitHub tokens", () => {
    const app = readFileSync(join(root, "bundle", "app.js"), "utf8");
    expect(app).toContain("scan-github-token");
    expect(app).toContain("pr-github-token");
    expect(app).not.toMatch(/storage\.set\([^)]*github_token/s);
    expect(app).not.toMatch(/localStorage/);
  });

  it("exposes the approval-gated patch download workflow", () => {
    const html = readFileSync(join(root, "bundle", "index.html"), "utf8");
    const app = readFileSync(join(root, "bundle", "app.js"), "utf8");
    expect(html).toContain("patch-approved");
    expect(html).toContain("download-patch-btn");
    expect(app).toContain("generate_patch");
    expect(app).toContain("patch-approved");
    expect(app).toContain("URL.createObjectURL");
    expect(app).toContain("upload.inline");
  });

  it("exposes a PDF report download for the current scan", () => {
    const html = readFileSync(join(root, "bundle", "index.html"), "utf8");
    const app = readFileSync(join(root, "bundle", "app.js"), "utf8");
    expect(html).toContain("download-report-pdf-btn");
    expect(html).toContain("Download report PDF");
    expect(app).toContain("buildScanReportPdf");
    expect(app).toContain("application/pdf");
    expect(app).toContain("%PDF-1.4");
    expect(app).toContain("repoguardian-report-");
  });

  it("keeps stored scan history below Anna storage limits", () => {
    const app = readFileSync(join(root, "bundle", "app.js"), "utf8");
    expect(app).toContain("const STORAGE_VALUE_LIMIT_BYTES = 262144");
    expect(app).toContain("const STORAGE_HISTORY_TARGET_BYTES = 210000");
    expect(app).toContain("fitHistoryForStorage");
    expect(app).toContain("saveHistorySafely");
    expect(app).toContain("report_available: Boolean(scan.report_markdown)");
    expect(app).not.toContain("report_markdown: scan.report_markdown");
  });

  it("opens directly on scan setup and exposes deep bounded analysis", () => {
    const html = readFileSync(join(root, "bundle", "index.html"), "utf8");
    const app = readFileSync(join(root, "bundle", "app.js"), "utf8");
    expect(html).toMatch(/class="page is-active" id="page-scan"/);
    expect(html).toContain('id="scan-profile"');
    expect(html).toContain('id="max-bytes"');
    expect(html).toContain('id="coverage-files"');
    expect(html).toContain('id="finding-search"');
    expect(app).toContain('page: "scan"');
    expect(app).toContain("scan_profile:");
    expect(app).toContain("compactCoverageForStorage");
  });

  it("requires typed repository confirmation for real pull requests", () => {
    const html = readFileSync(join(root, "bundle", "index.html"), "utf8");
    const app = readFileSync(join(root, "bundle", "app.js"), "utf8");
    expect(html).toContain('id="pr-confirm-repo"');
    expect(app).toContain("canonicalGithubRepository");
    expect(app).toContain("to confirm the real pull request target");
  });
});
