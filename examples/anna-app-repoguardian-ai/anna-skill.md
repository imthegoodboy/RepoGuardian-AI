# Anna App Build Skill — Evidence-First Executa Apps

Last verified with RepoGuardian AI `0.2.0` on 2026-08-27.

Use this as a compact release checklist for an Anna App with a bundled binary Executa. Always re-read the current official guide before publishing because Anna contracts and CLI behavior can change:

- https://forum.anna.partners/t/build-on-anna-101/228
- https://anna.partners/developers/overview/welcome
- https://anna.partners/developers/reference
- https://anna.partners/developers/reference/cli.md
- https://anna.partners/developers/reference/lifecycle.md
- https://anna.partners/developers/reference/executa-distribution.md

## Required App Contract

- `app.json` owns listing metadata and must include one aligned version, English description, real screenshot URLs, support/privacy URLs, and every bundled Executa path.
- `manifest.json` owns runtime permissions. For a UI app, use schema 2 and declare only APIs actually called.
- A bundled tool is referenced as `bundled:<handle>` in `required_executas` and as `required:bundled:<handle>` under `ui.host_api.tools`.
- Production UI code resolves the generated `bundle/anna-tool-ids.js` mapping. A real tool ID may be used only as a localhost development fallback.
- If the app declares automatic agent sessions, the saveable permission shape is:

```json
{
  "agent": {
    "session": {
      "auto": true,
      "fixed": { "client_ids": [] }
    },
    "tools": []
  }
}
```

Missing `agent.session.fixed.client_ids` can make the permission dialog say everything is granted while Save still fails.

## Binary Executa Release

1. Keep the immutable server tool ID stable in `executa.json`.
2. Set the same string as `package_name` and `executable_name` in the active binary profile. A null `package_name` can break Agent install/upgrade.
3. Build each platform on its native runner. PyInstaller is not a cross-compiler.
4. Archive layout must contain `bin/<tool-id>` plus a `manifest.json` that declares the entrypoint and executable permission.
5. Smoke-test `describe` from the packaged executable, not only the Python source.
6. Publish release assets, then record direct URL, SHA-256, byte size, entrypoint, and format for every platform.
7. Publish the Executa before cutting an app version. Check the app cut's `frozen_executas`; an app cut freezes a tool snapshot.
8. On the Anna Agent, confirm the installed tool is the expected version, Binary, and Running. Metadata alone is not runtime proof.

## Security and Data Boundaries

- Treat uploaded archives as hostile. Reject absolute/traversal paths, symlinks, hardlinks, device/FIFO entries, encrypted archives, excessive members, oversized members, and excessive expanded bytes. Extract members manually.
- Skip repository symlinks so a scan cannot escape its root.
- Redact secret evidence before it leaves the scanner. Never send raw secrets or runtime tokens to storage, logs, reports, chat artifacts, or model context.
- Send vulnerability databases exact installed versions from lockfiles. A lower bound parsed from `^`, `>=`, `~=` or another range is not an installed version and must not be queried as one.
- Static matches are heuristics. Give every finding a confidence label and ask the agent to distinguish confirmed advisories from patterns needing manual validation.
- Return explicit coverage: files/bytes inspected, per-file/file-count bounds, rule counts, exact-versus-manifest-only dependencies, skipped entries, and network failures.
- Keep dangerous actions approval-gated. For a real repository write, require explicit approval, a typed target confirmation, and a runtime token.

## Anna Storage

Anna's observed per-value JSON storage ceiling is 262,144 bytes. Keep the full current result in memory and persist compact history only. Drop large report bodies, cap arrays/text, target roughly 210 KB, and keep a smaller one-scan fallback. Persistence failure must not turn a completed scan into a failed scan.

## Test Gate

```powershell
$ANNA_HOST = "https://anna.partners"
npm test
npm run fixture:verify
anna-app validate --strict
anna-app dev --port 5184 --no-llm
npm run test:e2e
```

The e2e test must run through the real dev harness, not a standalone HTML page. For a tool app, verify UI → Anna runtime → Executa → result rendering. Test approval denial and approval success, token clearing, generated artifacts, history limits, console errors, and mobile overflow. Generate listing screenshots from the real working state.

## Publish Lifecycle

```powershell
anna-app executa publish executas/<tool> --account $ANNA_HOST --json
anna-app apps push --account $ANNA_HOST --json
anna-app apps cut <version> --account $ANNA_HOST --json
anna-app apps status <slug> --account $ANNA_HOST --json
anna-app apps submit-review <slug> --account $ANNA_HOST --json
```

`push` updates a mutable draft. `cut` creates an immutable version and freezes bundled Executas. `submit-review` requests Marketplace review. `release` is a separate public-production action; do not run it merely to test a cut.

After cutting, install the exact new version on an online Anna Agent, save its permissions, verify the bundled Executa is deployed on that selected Agent, and repeat the declared Marketplace scenarios. An App Store row, a learned tool row, and actual tool deployment are three different states.

## Recurring Failure Map

- `manifest does not declare agent.session.auto`: manifest/session permission shape is incomplete; include `auto` and `fixed.client_ids`.
- Listing says no bundled Executa while a learned tool exists: declare `bundled_executas`, `required_executas`, and host tool access consistently, republish the tool, then cut a new app version.
- `Executa ... is not deployed on the selected agent`: publish the binary profile, ensure platform URL/SHA is valid, install/update the exact app version, and inspect Agent tool status.
- `No Executa Agent is currently online`: the web app is open but no Agent for that account can run the tool.
- `RPC tools.invoke timed out`: pass a sufficiently long timeout in both the tool payload and the host invocation options; also bound the workload.
- `value JSON ... > 262144 bytes`: compact stored history and remove full reports/payloads.
- App Store shows `v—`: align `app.json`, package metadata, cut version, and listing sync; a draft push alone is not a published/cut version.
- Screenshot review fails: publish clear English screenshots from the real app state, use a stable raw URL, and ensure the main CTA appears in the first standard viewport.
- CLI shell variable failure in PowerShell: use `$ANNA_HOST`, never reserved `$Host`.

Final rule: build and test locally, publish the Executa, push/cut the app, install and retest the exact cut, then submit review. Never assume one stage performed the next.
