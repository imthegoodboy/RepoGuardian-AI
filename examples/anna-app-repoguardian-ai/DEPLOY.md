# Deploy RepoGuardian AI

Use production Anna unless intentionally testing staging.

```powershell
$ANNA_HOST = "https://anna.partners"
cd examples\anna-app-repoguardian-ai

npm test
npm run fixture:verify
anna-app validate --strict
npm run test:e2e

anna-app apps push --account $ANNA_HOST --json
anna-app apps cut 0.2.0 --account $ANNA_HOST --json
anna-app apps submit-review repoguardian-ai --account $ANNA_HOST --json
anna-app apps status repoguardian-ai --account $ANNA_HOST --json
```

After review approval:

```powershell
anna-app apps release 0.2.0 --account $ANNA_HOST --json
```

Before review, verify:

- the app loads in `anna-app dev`
- `npm run test:e2e` passes against the running local dev harness
- GitHub public repository scan succeeds
- archive scan succeeds for a small zip
- findings render on Dashboard and Findings pages
- SQL injection, XSS, secrets, architecture, and performance findings are visible in the filterable Findings page
- deep coverage reports inspected files/bytes, detector counts, exact dependency versions, and excluded entries
- Download report PDF is enabled after a scan and returns a valid PDF report
- patch generation is blocked until the user approves it, then Download patch returns a unified diff
- history survives refresh through Anna storage without exceeding the per-value JSON limit
- dry-run PR generation works without a token
- real PR creation is blocked until the user disables dry run, checks approval, types the exact `owner/repository`, and supplies a GitHub token
- no token or secret value is rendered or persisted

Binary Executa release order for `0.2.0`:

1. Commit and push scanner source plus `.github/workflows/build-repoguardian-scanner-binary.yml`.
2. Run the workflow and wait for all four platform builds.
3. Copy each release asset URL, SHA-256, and byte size into `executas/repoguardian-scanner/executa.json`.
4. Run `anna-app executa publish executas/repoguardian-scanner --account $ANNA_HOST --json`.
5. Push the app draft, cut `0.2.0`, install/test the cut, then submit review. Do not release publicly before approval.
