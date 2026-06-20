const { test, expect } = require("@playwright/test");
const fs = require("node:fs");
const path = require("node:path");

const baseUrl = process.env.REPOGUARDIAN_BASE_URL || "http://localhost:5184/";
const allowedHarnessWarnings = [
  "An iframe which has both allow-scripts and allow-same-origin for its sandbox attribute can escape its sandboxing.",
];
const allowedHarnessRequestFailures = [
  /GET http:\/\/localhost:5184\/anna-apps\/anna-app-repoguardian-ai\/dev\/index\.html\?.* net::ERR_ABORTED/,
];

function tarHeader(name, size) {
  const header = Buffer.alloc(512, 0);
  header.write(name, 0, Math.min(Buffer.byteLength(name), 100), "utf8");
  header.write("0000644\0", 100, 8, "ascii");
  header.write("0000000\0", 108, 8, "ascii");
  header.write("0000000\0", 116, 8, "ascii");
  header.write(size.toString(8).padStart(11, "0") + "\0", 124, 12, "ascii");
  header.write(Math.floor(Date.now() / 1000).toString(8).padStart(11, "0") + "\0", 136, 12, "ascii");
  header.fill(" ", 148, 156, "ascii");
  header.write("0", 156, 1, "ascii");
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8, "ascii");
  return header;
}

function writeTar(entries, outPath) {
  const parts = [];
  for (const [name, text] of entries) {
    const body = Buffer.from(text, "utf8");
    const padding = Buffer.alloc((512 - (body.length % 512)) % 512, 0);
    parts.push(tarHeader(name, body.length), body, padding);
  }
  parts.push(Buffer.alloc(1024, 0));
  fs.writeFileSync(outPath, Buffer.concat(parts));
}

function makeFixtureArchive(testInfo) {
  const archive = testInfo.outputPath("fixture-repo.tar");
  writeTar(
    [
      ["repo/package.json", JSON.stringify({ dependencies: { "left-pad": "1.1.0" } })],
      [
        "repo/app.py",
        [
      "import subprocess",
      "API_TOKEN = 'abcdefghijklmnopqrstuvwxyz1234567890TOKEN'",
      "subprocess.call('echo hello', shell=True)",
      'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
      "",
        ].join("\n"),
      ],
      ["repo/web.js", ["document.body.innerHTML = html;", "require('fs').readFileSync('large.json');", ""].join("\n")],
    ],
    archive,
  );
  return archive;
}

async function appFrame(page) {
  await expect(page.locator("iframe").first()).toBeVisible({ timeout: 15000 });
  const frameHandle = await page.locator("iframe").first().elementHandle();
  const frame = await frameHandle.contentFrame();
  if (!frame) throw new Error("App iframe not available");
  return frame;
}

async function expectCategoryVisible(frame, category) {
  await frame.locator("#category-filter").selectOption(category);
  await expect(frame.locator("#all-findings-caption")).toHaveText(/[1-9]\d* shown from \d+ findings/);
  await expect(frame.locator("#finding-list")).toContainText(category);
}

test("review-ready security workflow runs end to end through Anna harness", async ({ page }, testInfo) => {
  const logs = [];
  page.on("console", (msg) => logs.push({ type: msg.type(), text: msg.text() }));
  page.on("pageerror", (err) => logs.push({ type: "pageerror", text: err.message }));
  page.on("requestfailed", (req) => {
    logs.push({ type: "requestfailed", text: `${req.method()} ${req.url()} ${req.failure()?.errorText || ""}` });
  });

  const archive = makeFixtureArchive(testInfo);
  await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  const frame = await appFrame(page);

  await expect(frame.locator("#conn-text")).toContainText("Connected to Anna", { timeout: 15000 });
  await frame.getByRole("button", { name: /New Scan/i }).click();
  await frame.locator("#include-ai").uncheck({ force: true });
  await frame.locator("#dependency-network").uncheck({ force: true });
  await frame.locator("#archive-file").setInputFiles(archive);
  await frame.locator("#archive-scan-btn").click();

  await expect(frame.locator("#scan-status")).toContainText("Scan complete:", { timeout: 180000 });
  await expect(frame.locator("#metric-secrets")).toContainText("1");
  await expect(frame.locator("#workflow-list")).toContainText("Generate and download patch");
  await expect(frame.locator("#recent-findings")).toContainText(/secret|SQL|XSS|architecture|performance/i);
  await expect(frame.locator("#download-report-pdf-btn")).toHaveAttribute("aria-disabled", "false");
  const reportName = await frame.locator("#download-report-pdf-btn").getAttribute("download");
  expect(reportName).toMatch(/^repoguardian-report-.+\.pdf$/);
  const reportPdf = await frame.locator("#download-report-pdf-btn").evaluate(async (link) => {
    const response = await fetch(link.href);
    const bytes = new Uint8Array(await response.arrayBuffer());
    const prefix = Array.from(bytes.slice(0, 5)).map((byte) => String.fromCharCode(byte)).join("");
    const text = new TextDecoder().decode(bytes.slice(0, 3000));
    return { prefix, size: bytes.byteLength, text, bytes: Array.from(bytes) };
  });
  expect(reportPdf.prefix).toBe("%PDF-");
  expect(reportPdf.size).toBeGreaterThan(1200);
  expect(reportPdf.text).toContain("RepoGuardian AI Security Report");
  expect(reportPdf.text).toContain("Top Findings");
  fs.writeFileSync(testInfo.outputPath(reportName), Buffer.from(reportPdf.bytes));

  await frame.getByRole("button", { name: /Findings/i }).click();
  await expectCategoryVisible(frame, "secret");
  await expectCategoryVisible(frame, "injection");
  await expectCategoryVisible(frame, "xss");
  await expectCategoryVisible(frame, "architecture");
  await expectCategoryVisible(frame, "performance");
  await frame.locator("#category-filter").selectOption("all");
  await frame.locator("#severity-filter").selectOption("critical");
  await expect(frame.locator("#all-findings-caption")).toHaveText(/[1-9]\d* shown from \d+ findings/);

  await frame.getByRole("button", { name: /Patch/i }).click();
  await frame.locator("#generate-patch-btn").click();
  await expect(frame.locator("#patch-status")).toContainText("Patch generation failed.");
  await expect(frame.locator("#patch-output")).toContainText("Patch generation requires explicit user approval");
  await expect(frame.locator("#download-patch-btn")).toHaveAttribute("aria-disabled", "true");
  await frame.locator("#patch-approved").check({ force: true });
  await frame.locator("#generate-patch-btn").click();
  await expect(frame.locator("#patch-status")).toContainText("Patch ready:", { timeout: 65000 });
  await expect(frame.locator("#patch-output")).toContainText("diff --git");
  await expect(frame.locator("#patch-output")).toContainText(".github/repoguardian/security-report-");
  await expect(frame.locator("#download-patch-btn")).toHaveAttribute("aria-disabled", "false");
  const patchName = await frame.locator("#download-patch-btn").getAttribute("download");
  expect(patchName).toMatch(/^repoguardian-fixes-.+\.patch$/);
  const patchText = await frame.locator("#download-patch-btn").evaluate(async (link) => {
    const response = await fetch(link.href);
    return response.text();
  });
  fs.writeFileSync(testInfo.outputPath(patchName), patchText);
  expect(patchText).toContain("RepoGuardian AI Security Report");

  await frame.getByRole("button", { name: /Pull Request/i }).click();
  await frame.locator("#pr-repo-url").fill("https://github.com/octo/demo");
  await frame.locator("#pr-base-branch").fill("main");
  await frame.locator("#pr-github-token").fill("token-used-only-at-runtime");
  await frame.locator("#generate-pr-btn").click();
  await expect(frame.locator("#pr-output")).toContainText('"dry_run": true', { timeout: 65000 });
  await expect(frame.locator("#pr-output")).toContainText('"repository": "octo/demo"');
  await expect(frame.locator("#pr-output")).toContainText(".github/repoguardian/security-report-");
  await expect(frame.locator("#pr-github-token")).toHaveValue("");

  await frame.getByRole("button", { name: /History/i }).click();
  await expect(frame.locator("#history-list")).toContainText("fixture-repo.tar");
  await frame.getByRole("button", { name: /Settings/i }).click();
  await frame.locator("#setting-ai-default").uncheck({ force: true });
  await frame.locator("#save-settings-btn").click();
  await expect(frame.locator("#settings-status")).toContainText("Saved");

  fs.writeFileSync(testInfo.outputPath("console.json"), JSON.stringify(logs, null, 2));
  const unexpectedLogs = logs.filter((entry) => {
    if (entry.type === "warning" && allowedHarnessWarnings.includes(entry.text)) return false;
    if (entry.type === "requestfailed" && allowedHarnessRequestFailures.some((pattern) => pattern.test(entry.text))) {
      return false;
    }
    return ["error", "pageerror", "requestfailed"].includes(entry.type);
  });
  expect(unexpectedLogs).toEqual([]);
});
