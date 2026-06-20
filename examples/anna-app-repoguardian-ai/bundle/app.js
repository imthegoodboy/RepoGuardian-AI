const EXECUTA_HANDLE = "repoguardian-scanner";
const DEV_FALLBACK_TOOL_ID = "tool-nikku696969-repoguardian-scanner-3tsnh6fp";
const IS_LOCAL_ANNA_DEV =
  typeof window !== "undefined" &&
  ["localhost", "127.0.0.1", "::1"].includes(window.location.hostname);
const TOOL_ID =
  (IS_LOCAL_ANNA_DEV && DEV_FALLBACK_TOOL_ID) ||
  (typeof window !== "undefined" &&
    window.__ANNA_TOOL_IDS__ &&
    window.__ANNA_TOOL_IDS__[EXECUTA_HANDLE]) ||
  DEV_FALLBACK_TOOL_ID;

const STORAGE_HISTORY = "repoguardian:history";
const STORAGE_SETTINGS = "repoguardian:settings";
const MAX_INLINE_ARCHIVE_BYTES = 6 * 1024 * 1024;
const RPC_TIMEOUT_PADDING_MS = 10000;

const $ = (id) => document.getElementById(id);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
  anna: null,
  connected: false,
  page: "dashboard",
  scans: [],
  currentScan: null,
  patch: null,
  patchUrl: null,
  settings: {
    aiDefault: true,
    networkDefault: true,
    appendArtifact: true,
  },
  agentSession: null,
};

async function connectRuntime() {
  try {
    const mod = await import("/static/anna-apps/_sdk/latest/index.js");
    const anna = await mod.AnnaAppRuntime.connect();
    state.connected = true;
    setConnection(true, "Connected to Anna");
    window.anna = anna;
    return anna;
  } catch (err) {
    state.connected = false;
    setConnection(false, "Standalone preview");
    return createStandaloneRuntime(err);
  }
}

function createStandaloneRuntime(connectError) {
  console.warn("[repoguardian] Anna runtime unavailable:", connectError?.message || connectError);
  const memory = new Map();
  return {
    tools: {
      invoke() {
        throw new Error("Anna runtime is not connected. Start with `anna-app dev` to run scans.");
      },
    },
    storage: {
      async get({ key }) {
        return { value: memory.get(key), exists: memory.has(key) };
      },
      async set({ key, value }) {
        memory.set(key, value);
        return { ok: true };
      },
      async delete({ key }) {
        memory.delete(key);
        return { ok: true };
      },
    },
    chat: {
      async append_artifact() {
        return { artifact_id: "standalone" };
      },
    },
    window: {
      async set_title() {},
    },
    agent: {
      session: null,
    },
  };
}

function setConnection(on, text) {
  $("conn-dot")?.classList.toggle("dot-on", on);
  $("conn-dot")?.classList.toggle("dot-off", !on);
  if ($("conn-text")) $("conn-text").textContent = text;
}

function hostSupportsAnnaRiskAnalysis() {
  if (!IS_LOCAL_ANNA_DEV) return true;
  const scopes = state.anna?.capabilities?.scopes || [];
  return scopes.some(
    (scope) =>
      scope === "llm.*" ||
      scope === "llm.complete" ||
      scope === "llm.sample" ||
      scope === "sampling.createMessage" ||
      scope.startsWith("llm.") ||
      scope.startsWith("sampling."),
  );
}

async function init() {
  bindNavigation();
  bindActions();
  state.anna = await connectRuntime();
  await loadSettings();
  await loadHistory();
  applySettingsToControls();
  renderAll();
  state.anna.window?.set_title?.({ title: "RepoGuardian AI" }).catch(() => {});
}

function bindNavigation() {
  $("nav").addEventListener("click", (event) => {
    const button = event.target.closest("[data-page]");
    if (button) setPage(button.dataset.page);
  });
  document.body.addEventListener("click", (event) => {
    const button = event.target.closest("[data-jump]");
    if (button) setPage(button.dataset.jump);
  });
}

function bindActions() {
  $("quick-scan-btn").addEventListener("click", () => setPage("scan"));
  $("refresh-history-btn").addEventListener("click", async () => {
    await loadHistory();
    renderAll();
  });
  $("github-scan-btn").addEventListener("click", () => runScan("github"));
  $("archive-scan-btn").addEventListener("click", () => runScan("archive"));
  $("archive-file").addEventListener("change", () => {
    const file = $("archive-file").files?.[0];
    $("archive-name").textContent = file ? `${file.name} - ${formatBytes(file.size)}` : "No file selected";
  });
  $("severity-filter").addEventListener("change", renderFindings);
  $("category-filter").addEventListener("change", renderFindings);
  $("ask-agent-btn").addEventListener("click", askAgent);
  $("generate-patch-btn").addEventListener("click", generatePatch);
  $("download-patch-btn").addEventListener("click", downloadPatch);
  $("generate-pr-btn").addEventListener("click", generatePullRequest);
  $("clear-history-btn").addEventListener("click", clearHistory);
  $("save-settings-btn").addEventListener("click", saveSettingsFromControls);
}

function setPage(page) {
  state.page = page;
  $$(".nav-item").forEach((item) => item.classList.toggle("is-active", item.dataset.page === page));
  $$(".page").forEach((section) => section.classList.toggle("is-active", section.id === `page-${page}`));
  const labels = {
    dashboard: "Dashboard",
    scan: "New Scan",
    findings: "Findings",
    patch: "Patch",
    pr: "Pull Request",
    history: "History",
    settings: "Settings",
  };
  $("page-title").textContent = labels[page] || "RepoGuardian AI";
  state.anna?.window?.set_title?.({ title: `${labels[page] || "RepoGuardian AI"} - RepoGuardian AI` }).catch(() => {});
}

async function loadSettings() {
  try {
    const result = await state.anna.storage.get({ key: STORAGE_SETTINGS });
    if (result?.value && typeof result.value === "object") {
      state.settings = { ...state.settings, ...result.value };
    }
  } catch {
    /* storage may be unavailable in standalone preview */
  }
}

async function saveSettings() {
  await state.anna.storage.set({ key: STORAGE_SETTINGS, value: state.settings });
}

function applySettingsToControls() {
  const aiAvailable = hostSupportsAnnaRiskAnalysis();
  $("include-ai").checked = aiAvailable && !!state.settings.aiDefault;
  $("include-ai").disabled = !aiAvailable;
  $("include-ai").closest(".switch")?.classList.toggle("is-disabled", !aiAvailable);
  $("include-ai").closest(".switch")?.setAttribute(
    "title",
    aiAvailable ? "Use Anna host sampling for risk synthesis" : "Anna host sampling is not granted in this environment",
  );
  $("dependency-network").checked = !!state.settings.networkDefault;
  $("setting-ai-default").checked = !!state.settings.aiDefault;
  $("setting-network-default").checked = !!state.settings.networkDefault;
  $("setting-artifact").checked = !!state.settings.appendArtifact;
}

async function saveSettingsFromControls() {
  state.settings = {
    aiDefault: $("setting-ai-default").checked,
    networkDefault: $("setting-network-default").checked,
    appendArtifact: $("setting-artifact").checked,
  };
  await saveSettings();
  applySettingsToControls();
  $("settings-status").textContent = "Saved";
}

async function loadHistory() {
  try {
    const result = await state.anna.storage.get({ key: STORAGE_HISTORY });
    state.scans = Array.isArray(result?.value) ? result.value : [];
    state.currentScan = state.scans[0] || state.currentScan;
  } catch {
    state.scans = [];
  }
}

async function persistScan(scan) {
  const compactScan = compactScanForStorage(scan);
  state.scans = [compactScan, ...state.scans.filter((item) => item.scan_id !== scan.scan_id)].slice(0, 20);
  state.currentScan = compactScan;
  state.patch = null;
  resetPatchDownload();
  $("patch-output").textContent = "(no patch generated)";
  $("patch-status").textContent = "Review the latest scan, then approve patch generation.";
  await state.anna.storage.set({ key: STORAGE_HISTORY, value: state.scans });
}

function compactScanForStorage(scan) {
  return {
    ...scan,
    findings: (scan.findings || []).slice(0, 160),
    dependencies: (scan.dependencies || []).slice(0, 120),
    report_markdown: scan.report_markdown || "",
  };
}

async function clearHistory() {
  state.scans = [];
  state.currentScan = null;
  state.patch = null;
  resetPatchDownload();
  await state.anna.storage.delete({ key: STORAGE_HISTORY });
  renderAll();
}

async function runScan(sourceType) {
  setScanStatus("Preparing scan...");
  setBusy(true);
  try {
    const requestedAi = $("include-ai").checked;
    const hostSampling = requestedAi && hostSupportsAnnaRiskAnalysis();
    const args = {
      source_type: sourceType,
      include_ai: requestedAi,
      host_sampling: hostSampling,
      dependency_network: $("dependency-network").checked,
      max_files: Number($("max-files").value || 6000),
    };
    if (sourceType === "github") {
      args.repository_url = $("repo-url").value.trim();
      args.branch = $("repo-branch").value.trim();
      args.github_token = $("scan-github-token").value;
      if (!args.repository_url) throw new Error("Repository URL is required.");
      $("pr-repo-url").value = args.repository_url;
      $("pr-base-branch").value = args.branch;
    } else {
      const file = $("archive-file").files?.[0];
      if (!file) throw new Error("Choose a repository archive first.");
      if (file.size > MAX_INLINE_ARCHIVE_BYTES) {
        throw new Error(`Archive is ${formatBytes(file.size)}. Use a GitHub URL for archives over ${formatBytes(MAX_INLINE_ARCHIVE_BYTES)}.`);
      }
      args.archive_name = file.name;
      args.archive_b64 = await fileToBase64(file);
    }
    setScanStatus(
      requestedAi && !hostSampling
        ? "Running clone, dependency, secret, static, and deterministic risk analysis..."
        : "Running clone, dependency, secret, static, and risk analysis...",
    );
    const result = await invokeTool("scan_repository", args, 180000);
    await persistScan(result);
    if (state.settings.appendArtifact) await appendScanArtifact(result);
    setScanStatus(`Scan complete: ${result.summary.finding_count} findings in ${result.duration_ms} ms.`);
    setPage("dashboard");
    renderAll();
  } catch (err) {
    setScanStatus(formatError(err), true);
  } finally {
    setBusy(false);
    $("scan-github-token").value = "";
  }
}

async function invokeTool(method, args, timeoutMs = 65000) {
  const payload = { tool_id: TOOL_ID, method, args, timeoutMs };
  return state.anna.tools.invoke(payload, { timeoutMs: timeoutMs + RPC_TIMEOUT_PADDING_MS });
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error || new Error("Could not read file"));
    reader.onload = () => {
      const dataUrl = String(reader.result || "");
      resolve(dataUrl.split(",", 2)[1] || "");
    };
    reader.readAsDataURL(file);
  });
}

async function appendScanArtifact(scan) {
  try {
    await state.anna.chat.append_artifact({
      kind: "app_event",
      summary: `RepoGuardian AI scan: ${scan.summary.finding_count} findings, risk ${scan.summary.risk_score}/100`,
      payload: {
        app: "repoguardian-ai",
        scan_id: scan.scan_id,
        source: scan.source,
        summary: scan.summary,
      },
    });
  } catch {
    /* non-fatal: chat grant may be disabled in local harness */
  }
}

function renderAll() {
  renderDashboard();
  renderFindings();
  renderHistory();
  renderPrDefaults();
}

function renderDashboard() {
  const scan = state.currentScan;
  const summary = scan?.summary || { counts: {} };
  $("metric-risk").textContent = scan ? `${summary.risk_score}` : "--";
  $("metric-grade").textContent = scan ? `Grade ${summary.grade}` : "No scan yet";
  $("metric-critical").textContent = summary.counts?.critical || 0;
  $("metric-high").textContent = summary.counts?.high || 0;
  $("metric-secrets").textContent = (scan?.findings || []).filter((f) => f.category === "secret").length;
  $("workflow-caption").textContent = scan ? readableSource(scan.source) : "Run a scan to see live progress.";
  $("workflow-list").innerHTML = (scan?.workflow || defaultWorkflow()).map(workflowItem).join("");
  const risk = scan?.risk_analysis;
  $("risk-mode").textContent = risk ? `Mode: ${risk.mode || "unknown"}` : "Deterministic until Anna sampling is granted.";
  $("risk-copy").textContent = risk?.executive_summary || "Connect a repository or upload an archive to start.";
  $("priority-actions").innerHTML = (risk?.priority_actions || []).slice(0, 5).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  renderRecentFindings(scan);
}

function defaultWorkflow() {
  return [
    ["clone", "Clone/unpack repo"],
    ["dependency", "Dependency scan"],
    ["analyze", "AI analyzes"],
    ["finds", "Finds SQL injection, XSS, secrets, architecture, performance"],
    ["risk", "Risk analysis"],
    ["fixes", "Suggested fixes"],
    ["approval", "User approval"],
    ["patch", "Generate fix and download patch"],
    ["pr", "Generate pull request"],
  ].map(([key, label]) => ({ key, label, status: "pending" }));
}

function workflowItem(item) {
  return `<li class="workflow-item ${escapeHtml(item.status)}">
    <span>${escapeHtml(item.label)}</span>
    <strong>${escapeHtml(item.status)}</strong>
  </li>`;
}

function renderRecentFindings(scan) {
  const rows = (scan?.findings || []).slice(0, 8);
  $("findings-caption").textContent = scan ? `${scan.findings.length} total findings` : "Top issues appear here after a scan.";
  $("recent-findings").innerHTML = rows.length
    ? rows.map(findingRow).join("")
    : `<tr><td colspan="4" class="empty-cell">No scan findings yet.</td></tr>`;
}

function findingRow(finding) {
  const location = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ""}` : "n/a";
  return `<tr>
    <td><span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
    <td>${escapeHtml(finding.title)}</td>
    <td>${escapeHtml(location)}</td>
    <td>${escapeHtml(finding.recommendation)}</td>
  </tr>`;
}

function renderFindings() {
  const scan = state.currentScan;
  const severity = $("severity-filter")?.value || "all";
  const category = $("category-filter")?.value || "all";
  let findings = scan?.findings || [];
  if (severity !== "all") findings = findings.filter((item) => item.severity === severity);
  if (category !== "all") findings = findings.filter((item) => item.category === category);
  $("all-findings-caption").textContent = scan
    ? `${findings.length} shown from ${scan.findings.length} findings`
    : "Run a scan to inspect findings.";
  $("finding-list").innerHTML = findings.length
    ? findings.map(findingCard).join("")
    : `<div class="empty-state">No findings match the current filters.</div>`;
}

function findingCard(finding) {
  const location = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ""}` : "Repository level";
  return `<article class="finding-card">
    <header>
      <span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
      <strong>${escapeHtml(finding.title)}</strong>
      <small>${escapeHtml(finding.category)}</small>
    </header>
    <p>${escapeHtml(finding.impact)}</p>
    <dl>
      <dt>Location</dt><dd>${escapeHtml(location)}</dd>
      <dt>Evidence</dt><dd><code>${escapeHtml(finding.evidence || "n/a")}</code></dd>
      <dt>Fix</dt><dd>${escapeHtml(finding.recommendation)}</dd>
    </dl>
  </article>`;
}

async function askAgent() {
  const scan = state.currentScan;
  if (!scan) {
    $("agent-output").textContent = "Run a scan first.";
    return;
  }
  if (!state.anna.agent?.session) {
    $("agent-output").textContent = "Anna agent session API is not available in this preview.";
    return;
  }
  $("agent-output").textContent = "Starting agent run...\n";
  try {
    if (!state.agentSession) {
      state.agentSession = await state.anna.agent.session({
        submode: "auto",
        system_prompt: "You are RepoGuardian AI's security triage subagent. Use only the provided scan evidence.",
      });
    }
    const question = $("agent-question").value.trim() || "Explain the top release blocker and the safest fix path.";
    const context = {
      summary: scan.summary,
      source: scan.source,
      top_findings: (scan.findings || []).slice(0, 12),
      question,
    };
    const stream = state.agentSession.run({
      content: `Use this RepoGuardian scan JSON to answer concisely:\n${JSON.stringify(context)}`,
    });
    $("agent-output").textContent = "";
    for await (const frame of stream) {
      if (frame.event === "token" && frame.text) $("agent-output").textContent += frame.text;
      else if (frame.event && frame.event !== "run_meta") $("agent-output").textContent += `\n[${frame.event}]\n`;
    }
  } catch (err) {
    $("agent-output").textContent = formatError(err);
  }
}

async function generatePatch() {
  const scan = state.currentScan;
  if (!scan) {
    $("patch-status").textContent = "Run a scan before generating a patch.";
    return;
  }
  setBusy(true);
  resetPatchDownload();
  $("patch-output").textContent = "Generating patch...";
  $("patch-status").textContent = "Waiting for scanner patch generator...";
  try {
    const result = await invokeTool(
      "generate_patch",
      {
        scan_result: scan,
        approved: $("patch-approved").checked,
      },
      65000,
    );
    state.patch = result;
    $("patch-output").textContent = result.patch_text || "(empty patch)";
    $("patch-status").textContent = `Patch ready: ${result.filename} (${formatBytes(result.bytes || 0)})`;
    await setPatchDownload(result);
  } catch (err) {
    state.patch = null;
    resetPatchDownload();
    $("patch-output").textContent = formatError(err);
    $("patch-status").textContent = "Patch generation failed.";
  } finally {
    setBusy(false);
  }
}

async function setPatchDownload(patch) {
  resetPatchDownload();
  if (!patch?.patch_text) return;
  let href = "";
  if (!IS_LOCAL_ANNA_DEV && state.anna.upload?.inline) {
    try {
      const upload = await state.anna.upload.inline({
        filename: patch.filename || "repoguardian-fixes.patch",
        mime_type: "text/x-patch",
        content_b64: textToBase64(patch.patch_text),
        purpose: "user_artifact",
        metadata: { app: "repoguardian-ai", kind: "patch" },
      });
      href = upload?.download_url || "";
    } catch {
      href = "";
    }
  }
  if (!href) {
    const blob = new Blob([patch.patch_text], { type: "text/x-patch;charset=utf-8" });
    state.patchUrl = URL.createObjectURL(blob);
    href = state.patchUrl;
  }
  const link = $("download-patch-btn");
  link.href = href;
  link.download = patch.filename || "repoguardian-fixes.patch";
  link.rel = "noopener";
  link.classList.remove("is-disabled");
  link.setAttribute("aria-disabled", "false");
}

function resetPatchDownload() {
  if (state.patchUrl) {
    URL.revokeObjectURL(state.patchUrl);
    state.patchUrl = null;
  }
  const link = $("download-patch-btn");
  if (!link) return;
  link.href = "#";
  link.removeAttribute("download");
  link.classList.add("is-disabled");
  link.setAttribute("aria-disabled", "true");
}

function downloadPatch(event) {
  if (!state.patch?.patch_text || !state.patchUrl) {
    event.preventDefault();
    return;
  }
  $("patch-status").textContent = `Download ready: ${state.patch.filename || "repoguardian-fixes.patch"}`;
}

function renderPrDefaults() {
  const scan = state.currentScan;
  if (!scan) return;
  if (scan.source?.repository_url && !$("pr-repo-url").value) $("pr-repo-url").value = scan.source.repository_url;
  if (scan.source?.branch && !$("pr-base-branch").value) $("pr-base-branch").value = scan.source.branch;
}

async function generatePullRequest() {
  const scan = state.currentScan;
  if (!scan) {
    $("pr-output").textContent = "Run a scan before generating a PR.";
    return;
  }
  setBusy(true);
  $("pr-output").textContent = "Generating...";
  try {
    const result = await invokeTool(
      "create_pull_request",
      {
        repository_url: $("pr-repo-url").value.trim(),
        base_branch: $("pr-base-branch").value.trim(),
        github_token: $("pr-github-token").value,
        dry_run: $("pr-dry-run").checked,
        approved: $("pr-approved").checked,
        scan_result: scan,
      },
      180000,
    );
    $("pr-output").textContent = JSON.stringify(result, null, 2);
  } catch (err) {
    $("pr-output").textContent = formatError(err);
  } finally {
    $("pr-github-token").value = "";
    setBusy(false);
  }
}

function renderHistory() {
  $("history-list").innerHTML = state.scans.length
    ? state.scans.map(historyCard).join("")
    : `<div class="empty-state">No stored scans yet.</div>`;
}

function historyCard(scan) {
  return `<article class="history-card" data-scan="${escapeHtml(scan.scan_id)}">
    <div>
      <strong>${escapeHtml(readableSource(scan.source))}</strong>
      <span>${escapeHtml(new Date(scan.created_at).toLocaleString())}</span>
    </div>
    <div class="history-score">Risk ${scan.summary?.risk_score ?? 0}/100</div>
    <button class="btn btn-secondary" type="button" onclick="window.__repoguardianSelectScan('${escapeHtml(scan.scan_id)}')">Open</button>
  </article>`;
}

window.__repoguardianSelectScan = (scanId) => {
  const scan = state.scans.find((item) => item.scan_id === scanId);
  if (scan) {
    state.currentScan = scan;
    renderAll();
    setPage("dashboard");
  }
};

function setScanStatus(text, error = false) {
  const box = $("scan-status");
  box.textContent = text;
  box.classList.toggle("status-error", error);
}

function setBusy(on) {
  document.body.classList.toggle("is-busy", !!on);
  $$("button").forEach((button) => {
    if (button.id === "clear-history-btn") return;
    button.disabled = !!on;
  });
}

function readableSource(source = {}) {
  return source.repository || source.repository_url || source.archive_name || source.path || "No repository";
}

function formatError(err) {
  return err?.message || err?.error?.message || String(err);
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function textToBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

document.addEventListener("DOMContentLoaded", init);
