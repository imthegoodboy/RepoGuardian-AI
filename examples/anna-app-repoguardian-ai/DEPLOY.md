# Deploy RepoGuardian AI

Use production Anna unless intentionally testing staging.

```powershell
$HOST = "https://anna.partners"
cd examples\anna-app-repoguardian-ai

npm test
npm run fixture:verify
anna-app validate --strict
npm run test:e2e

anna-app apps push --account $HOST --json
anna-app apps cut 0.1.7 --account $HOST --json
anna-app apps submit-review repoguardian-ai --account $HOST --json
anna-app apps status repoguardian-ai --account $HOST --json
```

After review approval:

```powershell
anna-app apps release 0.1.7 --account $HOST --json
```

Before review, verify:

- the app loads in `anna-app dev`
- `npm run test:e2e` passes against the running local dev harness
- GitHub public repository scan succeeds
- archive scan succeeds for a small zip
- findings render on Dashboard and Findings pages
- SQL injection, XSS, secrets, architecture, and performance findings are visible in the filterable Findings page
- patch generation is blocked until the user approves it, then Download patch returns a unified diff
- history survives refresh through Anna storage
- dry-run PR generation works without a token
- real PR creation is blocked until the user disables dry run, checks approval, and supplies a GitHub token
- no token or secret value is rendered or persisted
