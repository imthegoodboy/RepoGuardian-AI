# Anna App Developer Playbook

Last verified: 2026-06-19 with `anna-app` CLI `0.1.30`.

This is the reusable checklist for building, previewing, pushing, reviewing, and releasing Anna Apps from this workspace.

Official docs checked:

- https://staging.anna.partners/developers/overview/welcome
- https://staging.anna.partners/developers/apps/app-intro
- https://staging.anna.partners/developers/apps/app-manifest
- https://staging.anna.partners/developers/apps/app-ui-overview
- https://staging.anna.partners/developers/apps/app-ui-host-api
- https://staging.anna.partners/developers/reference/cli

## 1. Mental Model

An Anna App has two main parts:

- Listing metadata: name, slug, tagline, category, description, logos, screenshots, support/privacy URLs. In example projects this usually lives in `app.json`; the Developer Console also stores this metadata.
- Version manifest: `manifest.json`. This declares runtime behavior, bundled Executas, permissions, UI bundle, host API access, and prompt behavior for app mentions.

Typical app folder:

```text
my-anna-app/
  app.json
  manifest.json
  package.json
  bundle/
    index.html
    style.css
    app.js
    anna-tool-ids.js
    icon.svg
  executas/
    my-tool-python/
      executa.json
      pyproject.toml
      my_tool.py
  tests/
    smoke.mjs
  DEPLOY.md
```

Important lifecycle:

```text
local files
  -> validate
  -> dev preview
  -> apps push          # mutable working draft
  -> apps cut X.Y.Z     # immutable version
  -> submit-review      # DRAFT/REJECTED -> PENDING_REVIEW
  -> release X.Y.Z      # only after APPROVED or already PUBLISHED
```

`apps push` is safe to run many times while developing. `apps cut` creates a real immutable version. `apps release` goes live, but Anna only allows it after app review approval.

## 2. Hosts

Use production by default:

```powershell
$ANNA_HOST = "https://anna.partners"
```

Use staging only when you intentionally want staging:

```powershell
$ANNA_HOST = "https://staging.anna.partners"
```

Do not mix accounts accidentally. `anna-app whoami --json` shows the current host and saved accounts.

## 3. Install And Inspect CLI

Check CLI:

```powershell
anna-app --version
anna-app --help
anna-app doctor
```

Useful command help:

```powershell
anna-app dev --help
anna-app apps --help
anna-app apps push --help
anna-app apps cut --help
anna-app apps release --help
anna-app account set-handle --help
```

## 4. Logout, Login, Account

Logout one host:

```powershell
anna-app logout --host https://anna.partners
```

Logout every saved Anna account:

```powershell
anna-app logout --all
```

Login to production:

```powershell
anna-app login --host https://anna.partners --no-browser
```

The CLI prints a `user_code` and confirmation URL. Open the URL, confirm the code, then verify:

```powershell
anna-app whoami --json
```

Set or rename developer handle if needed:

```powershell
anna-app account set-handle <your-handle> --host https://anna.partners --json
```

Notes:

- Apps publish under `@handle/slug`.
- If a command says `developer handle required`, set the handle.
- If a command says `Verified developer required`, the logged-in account is not developer-enabled for that host, or you are using the wrong host.

## 5. Create A New App

Scaffold:

```powershell
cd C:\Users\parth\Desktop\CreatorOS-anna\examples
anna-app init anna-app-my-tool --slug my-tool
cd anna-app-my-tool
```

If building manually, create:

```text
app.json
manifest.json
bundle/index.html
bundle/style.css
bundle/app.js
executas/<tool-name>/
tests/smoke.mjs
```

Add a local `.gitignore`:

```gitignore
.venv/
__pycache__/
*.pyc
test-results/
.anna/
dist-anna/
node_modules/
```

## 6. Manifest Rules

`manifest.json` is strict. Unknown fields are rejected.

Core fields:

```json
{
  "schema": 2,
  "permissions": ["tools.invoke", "storage.read", "storage.write"],
  "required_executas": [
    {
      "tool_id": "bundled:my-tool",
      "min_version": "0.1.0",
      "version": "latest"
    }
  ],
  "optional_executas": [],
  "system_prompt_addendum": "Use this app for ...",
  "user_message_prefix_template": "[My App] {user_message}",
  "tags": ["productivity"],
  "ui": {
    "bundle": {
      "format": "static-spa",
      "entry": "index.html",
      "external_origins": []
    },
    "views": [
      {
        "name": "main",
        "title": "My App",
        "default": true,
        "entry": "index.html",
        "min_size": { "w": 360, "h": 560 },
        "default_size": { "w": 1120, "h": 760 },
        "resizable": true,
        "movable": true,
        "single_instance": true
      }
    ],
    "host_api": {
      "tools": ["required:bundled:my-tool"],
      "storage": ["get", "set", "delete", "list"],
      "chat": ["append_artifact"],
      "window": ["set_title"],
      "image": ["generate"],
      "files": ["upload_init", "upload_finalize", "download_url", "list", "delete"],
      "agent": {
        "session": { "auto": true },
        "tools": []
      }
    },
    "state_merge": "last_writer_wins"
  },
  "dev": {
    "seed_storage": {},
    "user_id": 1
  }
}
```

Important rules:

- `schema: 1` is no UI.
- `schema: 2` enables the UI runtime and `ui` section.
- `dev` is local-harness-only and is stripped/ignored in production.
- `user_message_prefix_template` must contain exactly one `{user_message}`.
- `required_executas` auto-install for the user when the app is installed.
- `optional_executas` are documented to the model but not auto-installed.
- `schema: 2` apps may have no Executas if they only use host APIs.
- For bundled tools, prefer `bundled:<handle>` in `required_executas` and `required:bundled:<handle>` in `ui.host_api.tools`.

Allowed top-level permissions include:

```text
ui.svg
fs.read
fs.write
tools.invoke
chat.read
chat.write_message
chat.append_artifact
artifact.create
artifact.update
artifact.delete
llm.complete
storage.read
storage.write
prefs.read
```

## 7. Host API Reality

The iframe calls Anna through the runtime SDK:

```js
const mod = await import("/static/anna-apps/_sdk/latest/index.js");
const anna = await mod.AnnaAppRuntime.connect();
```

Implemented host APIs currently include:

- `window.*`: always granted; includes `hello`, `ready`, `set_title`, `resize`, `focus`, `close`, `open_view`.
- `tools.invoke`: run declared Executas.
- `chat.append_artifact`: attach app events/cards back to the Anna chat.
- `storage.get/set/delete/list`: persistent app state in production; in-memory in basic local dev.
- `agent.session.*`: Anna-managed agent sessions when granted.
- `image.generate/edit`: host-mediated image generation/editing when granted.
- `upload.inline/negotiate/confirm`: transient host uploads when granted.
- `files.upload_init/upload_finalize/download_url/list/delete`: durable per-App object storage when the current host exposes the files API.

Stubbed or not production-ready in the Host API docs:

- `artifact.*`
- `llm.complete`
- `fs.*`
- `prefs.*`

Practical rule: use `tools.invoke` and `agent.session` for real workflows. Do not build core app behavior that depends only on direct `llm.complete`.

## 8. Executa Structure

Python Executa folder:

```text
executas/my-tool-python/
  executa.json
  pyproject.toml
  my_tool.py
  uv.lock
```

Example `executa.json`:

```json
{
  "slug": "my-tool",
  "name": "My Tool",
  "version": "0.1.0",
  "executa_type": "tool",
  "description": "Does useful work for my Anna App.",
  "tool_id": "tool-test-my-tool-12345678",
  "type": "python",
  "enabled": true,
  "distribution": {
    "active": "local",
    "profiles": {
      "local": {
        "type": "local",
        "supports_protocol": true
      }
    }
  }
}
```

Anna dev harness auto-discovers Executas under `executas/` in this order:

1. `executa.json`
2. `pyproject.toml`
3. `package.json`
4. `go.mod` with explicit `executa.json`
5. `bin/<name>`

Python default launch:

```text
uv run --project <dir> <tool_id>
```

### Binary Executa Packaging

Local source mode is for development. For real distribution, package the Executa as a platform binary so users do not need Python, `uv`, or the source tree.

Key rules:

- Package the Executa process, not the whole app UI.
- Keep `manifest.json` app dependencies on `bundled:<handle>`.
- For normal source-mode app dev, the local `executa.json` and `pyproject.toml` may use the placeholder test Tool ID that the harness whitelists.
- For production binary distribution, build artifacts with the real Anna-minted `tool_id` in binary filenames and archive entrypoints. Use an explicit build override if the source dev id stays as `tool-test-*`.
- Commit all related files before running GitHub Actions: `executa.json`, `pyproject.toml`, `uv.lock`, packaging scripts, and workflows.
- Use platform-specific builds. PyInstaller does not reliably cross-compile.

Recommended archive layout:

```text
<tool_id>-darwin-arm64.tar.gz
  bin/<tool_id>
  manifest.json
```

`manifest.json` inside the archive should point at the binary:

```json
{
  "runtime": {
    "binary": {
      "entrypoint": {
        "default": "bin/<tool_id>"
      },
      "permissions": {
        "bin/<tool_id>": "0o755"
      }
    }
  }
}
```

Common GitHub Actions runner mapping:

- `macos-14` -> `darwin-arm64`
- `macos-15-intel` -> `darwin-x86_64`
- `ubuntu-latest` -> `linux-x86_64`

After the GitHub Release exists, configure the Tool in Anna Developer Console as Binary distribution and add the platform download URLs. Then reinstall/refresh the local Agent and confirm the tool shows `Binary` and `Running`.

## 9. Local Validation

Always run:

```powershell
cd C:\Users\parth\Desktop\CreatorOS-anna\examples\anna-app-my-tool
npm test
anna-app validate --strict
```

`--strict` adds bundle host API checks and catches common mismatches between `app.js` and `manifest.json`.

For one Python file syntax check:

```powershell
python -m py_compile executas\my-tool-python\my_tool.py
```

## 10. Local Preview

Offline/no real LLM:

```powershell
anna-app dev --port 5180 --no-llm
```

Production Anna LLM/account bridge:

```powershell
anna-app dev --port 5182 --llm-account https://anna.partners
```

With real Anna persistent storage:

```powershell
anna-app dev --port 5182 --llm-account https://anna.partners --storage aps
```

With a specific app slug for dev registration:

```powershell
anna-app dev --port 5182 --llm-account https://anna.partners --llm-app-slug my-tool
```

Open:

```text
http://localhost:5180/
http://localhost:5182/
```

If the port is busy, choose another port:

```powershell
anna-app dev --port 5183 --llm-account https://anna.partners
```

## 11. Publish Lifecycle

Use production unless intentionally testing staging:

```powershell
$HOST = "https://anna.partners"
```

Preflight:

```powershell
anna-app whoami --json
anna-app validate --strict
anna-app apps list --account $HOST --json
```

Push mutable draft:

```powershell
anna-app apps push --account $HOST --json
```

Cut immutable version:

```powershell
anna-app apps cut 0.1.0 --account $HOST --json
```

Submit app for review:

```powershell
anna-app apps submit-review my-tool --account $HOST --json
```

Check status:

```powershell
anna-app apps status my-tool --account $HOST --json
anna-app apps versions my-tool --account $HOST --json
anna-app apps grants my-tool --account $HOST --json
```

Release after approval:

```powershell
anna-app apps release 0.1.0 --account $HOST --json
```

One-shot publish path:

```powershell
anna-app apps publish --bump patch --account $HOST --json
```

Auto-detect current folder:

```powershell
anna-app publish --bump patch --account $HOST --json
```

## 12. Updating An Existing App

Normal code-change flow:

```powershell
npm test
anna-app validate --strict
anna-app apps push --account https://anna.partners --json
```

When ready for a new version:

```powershell
anna-app apps cut 0.1.1 --account https://anna.partners --json
anna-app apps submit-review <slug> --account https://anna.partners --json
```

After approval:

```powershell
anna-app apps release 0.1.1 --account https://anna.partners --json
```

Update store/listing metadata:

```powershell
anna-app apps sync-meta --account https://anna.partners --json
```

Dry-run metadata change:

```powershell
anna-app apps sync-meta --dry-run --account https://anna.partners --json
```

## 13. Review And Release States

Common states:

```text
draft
pending_review
approved
published
rejected
archived
```

Rules:

- You can push while in draft.
- You submit review from draft or rejected.
- `apps release <version>` only works after Anna marks the app approved or when it is already published.
- If release says `app status is pending_review`, wait for approval.

## 14. Current CreatorOS AI Commands

For this repo's CreatorOS app:

```powershell
cd C:\Users\parth\Desktop\CreatorOS-anna\examples\anna-app-creatoros-ai

anna-app whoami --json
npm test
anna-app validate --strict
anna-app dev --port 5182 --llm-account https://anna.partners
```

Push/cut/review:

```powershell
anna-app apps push --account https://anna.partners --json
anna-app apps cut 0.1.7 --account https://anna.partners --json
anna-app apps submit-review creatoros-ai --account https://anna.partners --json
anna-app apps status creatoros-ai --account https://anna.partners --json
```

Release after approval:

```powershell
anna-app apps release 0.1.7 --account https://anna.partners --json
```

Current known production state:

```text
host: https://anna.partners
app_id: 75
slug: creatoros-ai
latest_cut_version: 0.1.7
latest_cut_version_id: 172
latest_push_revision: 8
frozen_executa_version: 0.1.0
status: pending_review
```

## 15. Secrets And Environment Variables

Never commit secrets:

- API keys
- PATs
- OAuth client secrets
- Composio keys
- Video provider keys

 
For user-provided provider keys, prefer runtime entry in the app UI or Anna-managed secret/config storage. Do not write those keys into `manifest.json`, `app.json`, source code, or docs.

If a key is pasted into chat, screenshots, terminal output, or issues, rotate it before production use.

### Composio Media Connections

For apps that connect YouTube, Instagram, TikTok, or other social channels through Composio, treat the project API key and OAuth auth configs as separate requirements.

Minimum runtime secret:

```powershell
$env:COMPOSIO_API_KEY = "<composio-project-api-key>"
```

Toolkit auth configs for channel connection links:

```powershell
$env:COMPOSIO_YOUTUBE_AUTH_CONFIG_ID = "<youtube-auth-config-id>"
$env:COMPOSIO_INSTAGRAM_AUTH_CONFIG_ID = "<instagram-auth-config-id>"
$env:COMPOSIO_TIKTOK_AUTH_CONFIG_ID = "<tiktok-auth-config-id>"
```

Expected behavior:

- `COMPOSIO_API_KEY` allows tool probing and connected-account listing.
- The auth config IDs allow the Executa to call Composio's connected-account link endpoint and return an OAuth redirect URL.
- If an auth config is missing, the app should show a setup-required state and block publishing/scheduling execution.
- Do not claim a channel is connected until Composio returns an active connected account for the current app user.

## 16. Testing Checklist

Before push:

```powershell
npm test
anna-app validate --strict
python -m py_compile executas\<tool>\*.py
```

Manual preview checklist:

- App loads in Anna dev harness.
- Main UI fits desktop and mobile widths.
- No horizontal overflow on mobile.
- All buttons have visible states.
- Loading buttons restore their settled labels after overlapping tool checks.
- `@` mention/platform selection works if relevant.
- `tools.invoke` succeeds.
- `storage.set/get` succeeds.
- `chat.append_artifact` succeeds for handoff flows.
- Optional image/video/provider flows fail safely when credentials are missing.
- No key or token is rendered back into the UI.
- Social scheduling blocks with a clear `Needs Connected Channel` state until the selected Composio connected account is active.
- Workflow shows scheduled actions before the generated calendar so upload/schedule results are visible in the first viewport.

## 17. Troubleshooting

No PAT:

```text
no PAT on disk and ANNA_APP_PAT not set
```

Fix:

```powershell
anna-app login --host https://anna.partners --no-browser
anna-app whoami --json
```

Wrong host:

```text
verified in browser but CLI still says forbidden
```

Fix: check whether the browser is on `https://anna.partners` but CLI is logged into staging.

```powershell
anna-app whoami --json
anna-app login --host https://anna.partners --no-browser
```

Developer handle missing:

```text
developer handle required before registering a dev app
```

Fix:

```powershell
anna-app account set-handle <handle> --host https://anna.partners --json
```

Developer verification missing:

```text
forbidden (403): Verified developer required
```

Fix:

- Confirm you are logged into the same host as the Developer Console.
- Visit `https://anna.partners/developer`.
- Complete developer verification for that account.
- Retry `apps push`.

Release blocked:

```text
app status is pending_review; release not permitted
```

Fix: wait for Anna review approval, then run:

```powershell
anna-app apps release <version> --account https://anna.partners --json
```

Host API permission denied:

Fix both sides:

- Add top-level `permissions` entry when required.
- Add `ui.host_api.<namespace>` method allow-list.
- Re-run `anna-app validate --strict`.

Upload falls back to `Local Ready`:

- `files.*` may report `endpoint not yet available` on a host that has not exposed Anna Files yet.
- `upload.*` may report `upload_grant not enabled`; this grant is host/admin-side, not controlled by `manifest.permissions`.
- Keep the UI fallback path: register media metadata locally, mark it `Local Ready`, and block external publishing until a connected provider account and real upload/file ref exist.

Tool id drift:

Fix:

- Use `bundled:<handle>` in `manifest.json`.
- Use `window.__ANNA_TOOL_IDS__[handle]` in `bundle/app.js`.
- Let `anna-app apps push/publish` rewrite `bundle/anna-tool-ids.js`.

Venv locked on Windows:

Fix: stop the local dev harness or any Executa process, then remove generated artifacts.

```powershell
Get-CimInstance Win32_Process |
  Where-Object { $_.CommandLine -like "*my-app*executas*" } |
  Select-Object ProcessId,Name,CommandLine

Stop-Process -Id <pid> -Force
Remove-Item .\executas\<tool>\.venv -Recurse -Force
```

Port busy:

```powershell
anna-app dev --port 5183 --llm-account https://anna.partners
```

## 18. Destructive Commands

Use these only when you really mean it.

Unpublish a published app:

```powershell
anna-app apps unpublish <slug> --account https://anna.partners --yes --confirm <slug>
```

Archive:

```powershell
anna-app apps archive <slug> --account https://anna.partners --yes --confirm <slug>
```

Unarchive:

```powershell
anna-app apps unarchive <slug> --account https://anna.partners --yes
```

Delete:

```powershell
anna-app apps delete <slug> --account https://anna.partners --yes --confirm <slug>
```

The server may refuse delete if installs exist.

## 19. Fast Start Template

Copy this for a new app:

```powershell
$HOST = "https://anna.partners"
$APP = "my-new-app"
$VERSION = "0.1.0"

cd C:\Users\parth\Desktop\CreatorOS-anna\examples
anna-app init $APP --slug $APP
cd $APP

anna-app login --host $HOST --no-browser
anna-app whoami --json
anna-app account set-handle <handle> --host $HOST --json

npm test
anna-app validate --strict
anna-app dev --port 5182 --llm-account $HOST

anna-app apps push --account $HOST --json
anna-app apps cut $VERSION --account $HOST --json
anna-app apps submit-review $APP --account $HOST --json
anna-app apps status $APP --account $HOST --json

# After review approval:
anna-app apps release $VERSION --account $HOST --json
```

## 20. Minimal Quality Bar

Before asking for review:

- App validates with `anna-app validate --strict`.
- App has a real `README.md`.
- App has a deployment note or `DEPLOY.md`.
- App has at least one smoke test.
- App does not commit `.anna`, `.venv`, `node_modules`, `test-results`, PATs, or keys.
- UI is usable at mobile width.
- Host API grants match actual SDK calls.
- Dangerous actions require explicit user approval.
- App does not claim upload/publish/generation success unless an actual external provider returned success.
