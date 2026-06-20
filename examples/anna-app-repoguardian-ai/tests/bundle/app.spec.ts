import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import manifest from "../../manifest.json" with { type: "json" };

const root = join(__dirname, "..", "..");

describe("repoguardian-ai manifest and bundle", () => {
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
});
