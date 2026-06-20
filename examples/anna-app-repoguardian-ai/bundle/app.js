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
const SECURITY_AGENT_SYSTEM_PROMPT = [
  "You are RepoGuardian AI's senior application security agent.",
  "Use only the provided scan evidence. Do not invent files, vulnerabilities, exploitability, or fixes.",
  "Prioritize release blockers first: exposed secrets, critical/high dependency CVEs, SQL injection, XSS, auth/data-access flaws, unsafe command execution, and severe architecture or performance risks.",
  "Give an ordered fix plan with owner-ready steps and validation commands/tests. If evidence is incomplete, state the gap and the next scan or manual check needed.",
  "Never claim a patch, pull request, or repository change exists unless the app returned it. Require explicit approval before patch or PR creation.",
].join(" ");

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
  reportUrl: null,
  reportScanKey: "",
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
    llm: {
      async complete() {
        throw new Error("Anna LLM is not connected in standalone preview.");
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

function canUseDirectAnnaLlm() {
  return typeof state.anna?.llm?.complete === "function";
}

function compactFindingForAgent(finding) {
  return {
    id: finding.id,
    severity: finding.severity,
    category: finding.category,
    title: finding.title,
    file: finding.file,
    line: finding.line,
    impact: finding.impact,
    recommendation: finding.recommendation,
    package: finding.package,
    current_version: finding.current_version,
    fixed_version: finding.fixed_version,
  };
}

function buildAgentScanContext(scan, question = "") {
  const findings = scan.findings || [];
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const topFindings = [...findings]
    .sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9))
    .slice(0, 24)
    .map(compactFindingForAgent);
  return {
    question,
    source: scan.source,
    summary: scan.summary,
    risk_analysis: scan.risk_analysis,
    top_findings: topFindings,
    top_suggestions: (scan.suggestions || []).slice(0, 12).map((item) => ({
      severity: item.severity,
      title: item.title,
      file: item.file,
      action: item.action,
      can_auto_apply: item.can_auto_apply,
    })),
    warnings: (scan.warnings || []).slice(0, 8),
    context_policy: "This is a compact scan excerpt. Treat it as authoritative evidence, and state when more code inspection is needed.",
  };
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
  $("download-report-pdf-btn").addEventListener("click", downloadReportPdf);
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
    let result = await invokeTool("scan_repository", args, 180000);
    if (requestedAi && result?.risk_analysis?.mode === "deterministic" && canUseDirectAnnaLlm()) {
      setScanStatus("Anna sampling grant unavailable; running compact Anna LLM risk synthesis...");
      result = await enhanceRiskWithDirectAnnaLlm(result);
    }
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

async function enhanceRiskWithDirectAnnaLlm(scan) {
  const context = buildAgentScanContext(scan, "Produce risk synthesis for the current scan.");
  const prompt = [
    "Review this compact RepoGuardian scan and return strict JSON only.",
    "Schema: {\"posture\":\"Low|Moderate|Elevated|High\",\"executive_summary\":\"one concise paragraph\",\"priority_actions\":[\"3-5 ordered actions\"],\"business_risk\":\"one sentence\",\"release_blocker\":true|false,\"release_blocker_reason\":\"short reason or empty\",\"validation_plan\":[\"2-4 tests or commands\"],\"confidence\":\"low|medium|high\"}.",
    "Prioritize critical/high security findings, exploitable secrets, SQL injection, XSS, dependency CVEs, unsafe command execution, and safe remediation order.",
    "Do not invent findings. Base every action on the compact scan evidence.",
    JSON.stringify(context),
  ].join("\n\n");

  try {
    const completion = await state.anna.llm.complete(
      {
        messages: [{ role: "user", content: prompt }],
        maxTokens: 1200,
        temperature: 0.2,
        systemPrompt: SECURITY_AGENT_SYSTEM_PROMPT,
      },
      { timeoutMs: 75000 },
    );
    const text = completion?.content?.text || completion?.content || "";
    const parsed = parseJsonObject(text);
    if (!parsed) return scan;
    return {
      ...scan,
      risk_analysis: {
        ...(scan.risk_analysis || {}),
        mode: "anna-llm",
        executive_summary: String(parsed.executive_summary || scan.risk_analysis?.executive_summary || ""),
        priority_actions: Array.isArray(parsed.priority_actions)
          ? parsed.priority_actions.slice(0, 5).map(String)
          : scan.risk_analysis?.priority_actions || [],
        business_risk: String(parsed.business_risk || scan.risk_analysis?.business_risk || ""),
        release_blocker: Boolean(parsed.release_blocker),
        release_blocker_reason: String(parsed.release_blocker_reason || ""),
        validation_plan: Array.isArray(parsed.validation_plan) ? parsed.validation_plan.slice(0, 4).map(String) : [],
        confidence: String(parsed.confidence || "medium"),
        llm_model: completion?.model || "anna-host",
        fallback_from: scan.risk_analysis?.mode || "deterministic",
      },
    };
  } catch (err) {
    return {
      ...scan,
      risk_analysis: {
        ...(scan.risk_analysis || {}),
        mode: scan.risk_analysis?.mode || "deterministic",
        llm_error: formatError(err),
      },
    };
  }
}

function parseJsonObject(text) {
  const raw = String(text || "").trim();
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    const start = raw.indexOf("{");
    const end = raw.lastIndexOf("}");
    if (start === -1 || end <= start) return null;
    try {
      return JSON.parse(raw.slice(start, end + 1));
    } catch {
      return null;
    }
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
  updateReportPdfDownload();
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
        system_prompt: SECURITY_AGENT_SYSTEM_PROMPT,
      });
    }
    const question = $("agent-question").value.trim() || "Explain the top release blocker and the safest fix path.";
    const context = buildAgentScanContext(scan, question);
    const stream = state.agentSession.run({
      content: [
        "Answer the user's security question from this RepoGuardian scan evidence.",
        "Format: Verdict, Evidence, Fix plan, Validation, Residual risk. Keep it concise and actionable.",
        "If the user asks for code changes, say approval is required before patch/PR generation.",
        JSON.stringify(context),
      ].join("\n\n"),
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

function updateReportPdfDownload() {
  const link = $("download-report-pdf-btn");
  if (!link) return;
  const scan = state.currentScan;
  if (!scan) {
    resetReportPdfDownload();
    return;
  }
  const key = [
    scan.scan_id || "scan",
    scan.created_at || "",
    scan.summary?.risk_score ?? "",
    (scan.findings || []).length,
    scan.risk_analysis?.mode || "",
  ].join(":");
  if (state.reportUrl && state.reportScanKey === key) {
    enableReportPdfLink(link, scan);
    return;
  }
  resetReportPdfDownload();
  const pdfBytes = buildScanReportPdf(scan);
  const blob = new Blob([pdfBytes], { type: "application/pdf" });
  state.reportUrl = URL.createObjectURL(blob);
  state.reportScanKey = key;
  enableReportPdfLink(link, scan);
}

function enableReportPdfLink(link, scan) {
  link.href = state.reportUrl || "#";
  link.download = `repoguardian-report-${safeFilename(scan.scan_id || "scan")}.pdf`;
  link.rel = "noopener";
  link.classList.remove("is-disabled");
  link.setAttribute("aria-disabled", "false");
}

function resetReportPdfDownload() {
  if (state.reportUrl) {
    URL.revokeObjectURL(state.reportUrl);
    state.reportUrl = null;
  }
  state.reportScanKey = "";
  const link = $("download-report-pdf-btn");
  if (!link) return;
  link.href = "#";
  link.removeAttribute("download");
  link.classList.add("is-disabled");
  link.setAttribute("aria-disabled", "true");
}

function downloadReportPdf(event) {
  if (!state.currentScan || !state.reportUrl) {
    event.preventDefault();
    return;
  }
}

function buildScanReportPdf(scan) {
  const pageWidth = 612;
  const pageHeight = 792;
  const margin = 48;
  const bottom = 58;
  const pages = [];
  let ops = [];
  let y = pageHeight - margin;

  const newPage = () => {
    if (ops.length) pages.push(ops.join(""));
    ops = [];
    y = pageHeight - margin;
  };

  const ensureSpace = (height) => {
    if (y - height < bottom) newPage();
  };

  const drawText = (text, x, lineY, size, font, color = [0.09, 0.13, 0.19]) => {
    const clean = cleanPdfText(text);
    ops.push(
      `${color[0]} ${color[1]} ${color[2]} rg\nBT\n/${font} ${size} Tf\n1 0 0 1 ${x.toFixed(2)} ${lineY.toFixed(2)} Tm\n(${escapePdfText(clean)}) Tj\nET\n`,
    );
  };

  const drawRule = () => {
    ensureSpace(12);
    ops.push(`0.82 0.86 0.91 RG\n0.75 w\n${margin} ${y.toFixed(2)} m ${pageWidth - margin} ${y.toFixed(2)} l S\n`);
    y -= 16;
  };

  const addText = (text, options = {}) => {
    const size = options.size || 10;
    const lineHeight = options.lineHeight || Math.ceil(size * 1.45);
    const indent = options.indent || 0;
    const maxWidth = pageWidth - margin * 2 - indent;
    const maxChars = options.maxChars || Math.max(24, Math.floor(maxWidth / (size * 0.52)));
    const lines = wrapPdfText(text, maxChars);
    for (const line of lines) {
      ensureSpace(lineHeight);
      drawText(line, margin + indent, y, size, options.font || "F1", options.color);
      y -= lineHeight;
    }
    y -= options.after ?? 2;
  };

  const addHeading = (text, size = 13) => {
    ensureSpace(28);
    y -= 6;
    addText(text, { size, font: "F2", lineHeight: Math.ceil(size * 1.35), after: 6 });
  };

  const addBullet = (text) => addText(`- ${text}`, { indent: 14, size: 9.5, lineHeight: 14, after: 1 });

  const summary = scan.summary || {};
  const counts = summary.counts || {};
  const risk = scan.risk_analysis || {};
  const findings = scan.findings || [];
  const warnings = scan.warnings || [];
  const created = scan.created_at ? new Date(scan.created_at).toLocaleString() : new Date().toLocaleString();
  const source = readableSource(scan.source);
  const secrets = findings.filter((finding) => finding.category === "secret").length;

  addText("RepoGuardian AI Security Report", { size: 18, font: "F2", lineHeight: 24, after: 2 });
  addText(`Source: ${source}`, { size: 10, font: "F2", lineHeight: 14, after: 0 });
  addText(`Scan ID: ${scan.scan_id || "n/a"} | Created: ${created}`, { size: 9, color: [0.4, 0.44, 0.5], lineHeight: 13, after: 6 });
  drawRule();

  addHeading("Executive Summary");
  addText(risk.executive_summary || "No executive summary was returned for this scan.", { size: 10, lineHeight: 15 });

  addHeading("Risk Snapshot");
  [
    `Risk score: ${summary.risk_score ?? 0}/100`,
    `Grade: ${summary.grade || "n/a"}`,
    `Total findings: ${summary.finding_count ?? findings.length}`,
    `Critical: ${counts.critical || 0} | High: ${counts.high || 0} | Medium: ${counts.medium || 0} | Low: ${counts.low || 0}`,
    `Secrets detected: ${secrets}`,
    `Risk mode: ${risk.mode || "deterministic"}`,
    `Release blocker: ${risk.release_blocker ? "yes" : "no"}${risk.release_blocker_reason ? ` - ${risk.release_blocker_reason}` : ""}`,
  ].forEach(addBullet);

  addHeading("Priority Actions");
  const actions = (risk.priority_actions || []).slice(0, 8);
  if (actions.length) actions.forEach(addBullet);
  else addBullet("Review the top findings and validate each fix with project tests.");

  addHeading("Top Findings");
  if (!findings.length) {
    addBullet("No findings were returned by the scanner.");
  } else {
    sortedFindings(findings)
      .slice(0, 30)
      .forEach((finding, index) => {
        const location = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ""}` : "Repository level";
        ensureSpace(54);
        addText(`${index + 1}. ${String(finding.severity || "info").toUpperCase()} - ${finding.title || "Untitled finding"}`, {
          size: 10,
          font: "F2",
          lineHeight: 14,
          after: 0,
        });
        addText(`Category: ${finding.category || "n/a"} | Location: ${location}`, { size: 8.8, color: [0.4, 0.44, 0.5], lineHeight: 12, after: 0 });
        if (finding.impact) addText(`Impact: ${finding.impact}`, { size: 9, lineHeight: 13, after: 0 });
        if (finding.recommendation) addText(`Fix: ${finding.recommendation}`, { size: 9, lineHeight: 13, after: 4 });
      });
  }

  if (warnings.length) {
    addHeading("Warnings");
    warnings.slice(0, 10).forEach(addBullet);
  }

  addHeading("Validation Notes");
  (risk.validation_plan || ["Run the project test suite after applying fixes.", "Re-run RepoGuardian AI to confirm release blockers are closed."])
    .slice(0, 6)
    .forEach(addBullet);
  addText("Generated by RepoGuardian AI. Secret evidence is redacted by the scanner before display or export.", {
    size: 8.5,
    color: [0.4, 0.44, 0.5],
    lineHeight: 12,
    after: 0,
  });

  if (ops.length) pages.push(ops.join(""));
  return encodePdf(pages, { pageWidth, pageHeight, margin });
}

function sortedFindings(findings) {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...findings].sort((a, b) => {
    const severityDelta = (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9);
    if (severityDelta) return severityDelta;
    return String(a.title || "").localeCompare(String(b.title || ""));
  });
}

function encodePdf(pageContents, { pageWidth, pageHeight, margin }) {
  const pages = pageContents.length ? pageContents : [""];
  const objects = {};
  const pageRefs = pages.map((_, index) => `${3 + index * 2} 0 R`).join(" ");
  objects[1] = "<< /Type /Catalog /Pages 2 0 R >>";
  objects[2] = `<< /Type /Pages /Kids [${pageRefs}] /Count ${pages.length} >>`;

  pages.forEach((content, index) => {
    const pageObject = 3 + index * 2;
    const contentObject = pageObject + 1;
    const footer = [
      `0.4 0.44 0.5 rg\nBT\n/F1 8 Tf\n1 0 0 1 ${margin.toFixed(2)} 34 Tm\n(RepoGuardian AI) Tj\nET\n`,
      `0.4 0.44 0.5 rg\nBT\n/F1 8 Tf\n1 0 0 1 ${(pageWidth - margin - 48).toFixed(2)} 34 Tm\n(Page ${index + 1} of ${pages.length}) Tj\nET\n`,
    ].join("");
    const stream = `${content}${footer}`;
    objects[pageObject] = [
      "<< /Type /Page",
      "/Parent 2 0 R",
      `/MediaBox [0 0 ${pageWidth} ${pageHeight}]`,
      "/Resources << /Font <<",
      "/F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
      "/F2 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
      ">> >>",
      `/Contents ${contentObject} 0 R >>`,
    ].join(" ");
    objects[contentObject] = `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`;
  });

  const maxObject = Math.max(...Object.keys(objects).map(Number));
  const offsets = [0];
  let pdf = "%PDF-1.4\n% RepoGuardian AI\n";
  for (let objectId = 1; objectId <= maxObject; objectId += 1) {
    offsets[objectId] = pdf.length;
    pdf += `${objectId} 0 obj\n${objects[objectId]}\nendobj\n`;
  }
  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${maxObject + 1}\n0000000000 65535 f \n`;
  for (let objectId = 1; objectId <= maxObject; objectId += 1) {
    pdf += `${String(offsets[objectId]).padStart(10, "0")} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${maxObject + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  return new TextEncoder().encode(pdf);
}

function wrapPdfText(value, maxChars) {
  const normalized = cleanPdfText(value).replace(/\s+/g, " ").trim();
  if (!normalized) return [""];
  const lines = [];
  let line = "";
  for (const word of normalized.split(" ")) {
    if (word.length > maxChars) {
      if (line) {
        lines.push(line);
        line = "";
      }
      for (let i = 0; i < word.length; i += maxChars) lines.push(word.slice(i, i + maxChars));
    } else if (!line) {
      line = word;
    } else if (`${line} ${word}`.length <= maxChars) {
      line = `${line} ${word}`;
    } else {
      lines.push(line);
      line = word;
    }
  }
  if (line) lines.push(line);
  return lines;
}

function cleanPdfText(value) {
  return String(value ?? "")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/[^\x20-\x7E]/g, "?");
}

function escapePdfText(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
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

function safeFilename(value) {
  return String(value || "scan")
    .trim()
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "scan";
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
