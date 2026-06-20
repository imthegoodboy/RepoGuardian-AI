#!/usr/bin/env python3
"""RepoGuardian AI scanner Executa.

The app bundle calls this process through Anna `tools.invoke`. The scanner does
not need an OpenAI/API provider key. When risk synthesis is enabled it uses
Anna Executa v2 reverse sampling (`sampling/createMessage`), so Anna owns model
selection, quota, and billing.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import difflib
import dataclasses
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - py3.11+ in this app
    tomllib = None  # type: ignore[assignment]

try:
    import executa_sdk  # noqa: F401
except ModuleNotFoundError:
    _SDK_PATH = Path(__file__).resolve().parents[4] / "sdk" / "python"
    if _SDK_PATH.is_dir():
        sys.path.insert(0, str(_SDK_PATH))

from executa_sdk import PROTOCOL_VERSION_V2, SamplingClient, SamplingError  # noqa: E402


TOOL_ID = "tool-nikku696969-repoguardian-scanner-3tsnh6fp"

MANIFEST = {
    "name": TOOL_ID,
    "display_name": "RepoGuardian Scanner",
    "version": "0.1.3",
    "description": (
        "Repository security scanner for RepoGuardian AI. Clones GitHub repos "
        "or unpacks uploaded archives, detects dependency vulnerabilities, "
        "outdated packages, secrets, and static code risks, suggests fixes, "
        "and can create a GitHub pull request with a security report."
    ),
    "author": "Anna Developer",
    "host_capabilities": ["llm.sample"],
    "tools": [
        {
            "name": "scan_repository",
            "description": (
                "Clone or unpack a repository and run dependency, secret, "
                "static-analysis, and risk-synthesis checks."
            ),
            "parameters": [
                {
                    "name": "source_type",
                    "type": "string",
                    "description": "github, archive, or local_path.",
                    "required": True,
                    "enum": ["github", "archive", "local_path"],
                },
                {
                    "name": "repository_url",
                    "type": "string",
                    "description": "GitHub URL or owner/repo. Required for source_type=github.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "branch",
                    "type": "string",
                    "description": "Branch or ref to scan.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "archive_b64",
                    "type": "string",
                    "description": "Base64 encoded zip/tar archive for source_type=archive.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "archive_name",
                    "type": "string",
                    "description": "Original archive file name.",
                    "required": False,
                    "default": "repository.zip",
                },
                {
                    "name": "local_path",
                    "type": "string",
                    "description": "Absolute local repository path for source_type=local_path.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "github_token",
                    "type": "string",
                    "description": "Runtime GitHub token for private clone. Never stored.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "include_ai",
                    "type": "boolean",
                    "description": "Use Anna reverse sampling for risk synthesis when granted.",
                    "required": False,
                    "default": True,
                },
                {
                    "name": "host_sampling",
                    "type": "boolean",
                    "description": "True only when the Anna host has granted reverse sampling for this app session.",
                    "required": False,
                    "default": False,
                },
                {
                    "name": "dependency_network",
                    "type": "boolean",
                    "description": "Query OSV/npm/PyPI/Go registries for vulnerabilities/outdated packages.",
                    "required": False,
                    "default": True,
                },
                {
                    "name": "max_files",
                    "type": "integer",
                    "description": "Maximum repository files to inspect.",
                    "required": False,
                    "default": 6000,
                },
                {
                    "name": "max_bytes",
                    "type": "integer",
                    "description": "Maximum bytes to read per text file.",
                    "required": False,
                    "default": 250000,
                },
            ],
        },
        {
            "name": "create_pull_request",
            "description": (
                "Create a dry-run PR plan, or create a real GitHub pull request "
                "after explicit approval and a runtime GitHub token."
            ),
            "parameters": [
                {
                    "name": "repository_url",
                    "type": "string",
                    "description": "GitHub URL or owner/repo where the report branch or pull request will be prepared.",
                    "required": True,
                },
                {
                    "name": "base_branch",
                    "type": "string",
                    "description": "Optional target branch. Defaults to the repository default branch.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "github_token",
                    "type": "string",
                    "description": "Runtime GitHub token. Required when dry_run=false.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "scan_result",
                    "type": "object",
                    "description": "Result returned by scan_repository.",
                    "required": True,
                },
                {
                    "name": "dry_run",
                    "type": "boolean",
                    "description": "When true, return the PR plan and file list without writing to GitHub.",
                    "required": False,
                    "default": True,
                },
                {
                    "name": "approved",
                    "type": "boolean",
                    "description": "Must be true before creating a real pull request.",
                    "required": False,
                    "default": False,
                },
                {
                    "name": "title",
                    "type": "string",
                    "description": "Optional pull request title. Defaults to a generated RepoGuardian report title.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "body",
                    "type": "string",
                    "description": "Optional pull request body. Defaults to the generated RepoGuardian report.",
                    "required": False,
                    "default": "",
                },
            ],
        },
        {
            "name": "generate_patch",
            "description": (
                "Generate a downloadable unified diff patch containing the "
                "RepoGuardian report, Dependabot configuration where applicable, "
                "and security hygiene notes. Requires explicit user approval."
            ),
            "parameters": [
                {
                    "name": "scan_result",
                    "type": "object",
                    "description": "Result returned by scan_repository.",
                    "required": True,
                },
                {
                    "name": "approved",
                    "type": "boolean",
                    "description": "Must be true before generating the downloadable patch artifact.",
                    "required": True,
                },
            ],
        },
    ],
    "runtime": {"type": "uv", "min_version": "0.1.0"},
}


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    "target",
    "bin",
    "obj",
}

TEXT_EXTS = {
    ".c",
    ".cc",
    ".cfg",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".dockerfile",
    ".env",
    ".go",
    ".gradle",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".lock",
    ".md",
    ".mjs",
    ".php",
    ".properties",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

SECRET_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    (
        "GitHub token",
        "critical",
        "Rotate the token, remove it from history, and move it to Anna or GitHub secrets.",
        re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b"),
    ),
    (
        "AWS access key",
        "critical",
        "Rotate the key in AWS IAM and replace it with workload identity or a secrets manager.",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "Private key material",
        "critical",
        "Remove the private key, rotate the credential, and store only encrypted key references.",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "Slack token",
        "high",
        "Revoke the token and move Slack credentials into a managed secret store.",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    ),
    (
        "OpenAI API key",
        "critical",
        "Revoke the key and store future model provider credentials outside source control.",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "Generic assignment secret",
        "medium",
        "Move the value to a runtime secret and commit only a documented environment variable name.",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9_./+=:-]{18,}"
        ),
    ),
]

STATIC_RULES: list[dict[str, Any]] = [
    {
        "id": "js-eval",
        "extensions": {".js", ".jsx", ".ts", ".tsx", ".mjs"},
        "pattern": re.compile(r"\beval\s*\("),
        "severity": "high",
        "title": "Dynamic eval execution",
        "impact": "Untrusted input can become executable code.",
        "recommendation": "Replace eval with a parser, schema validation, or a constrained expression evaluator.",
    },
    {
        "id": "js-sql-injection-template",
        "extensions": {".js", ".jsx", ".ts", ".tsx", ".mjs"},
        "pattern": re.compile(r"\b(?:query|execute|raw)\s*\(\s*`[^`]*\$\{", re.IGNORECASE),
        "severity": "critical",
        "category": "injection",
        "title": "Potential SQL injection via template query",
        "impact": "Interpolated SQL can let attacker-controlled input alter database queries.",
        "recommendation": "Use parameterized queries or a query builder with bound values.",
    },
    {
        "id": "js-sql-injection-concat",
        "extensions": {".js", ".jsx", ".ts", ".tsx", ".mjs"},
        "pattern": re.compile(r"\b(?:query|execute|raw)\s*\(\s*['\"][^'\"]*(SELECT|UPDATE|DELETE|INSERT)[^'\"]*['\"]\s*\+", re.IGNORECASE),
        "severity": "high",
        "category": "injection",
        "title": "Potential SQL injection via concatenated query",
        "impact": "String-concatenated SQL is hard to validate and commonly leads to injection.",
        "recommendation": "Replace string concatenation with prepared statements and parameter binding.",
    },
    {
        "id": "py-sql-injection-fstring",
        "extensions": {".py"},
        "pattern": re.compile(r"\.execute\s*\(\s*f[\"']", re.IGNORECASE),
        "severity": "critical",
        "category": "injection",
        "title": "Potential SQL injection via f-string query",
        "impact": "Interpolated SQL can let attacker-controlled input alter database queries.",
        "recommendation": "Use DB-API parameter placeholders and pass values separately.",
    },
    {
        "id": "py-sql-injection-format",
        "extensions": {".py"},
        "pattern": re.compile(r"\.execute\s*\([^)]*(?:\.format\s*\(|%\s*\(|\+\s*)", re.IGNORECASE),
        "severity": "high",
        "category": "injection",
        "title": "Potential SQL injection via dynamic query",
        "impact": "Dynamic SQL construction can bypass escaping and authorization assumptions.",
        "recommendation": "Use parameterized queries and validate any dynamic identifiers against an allow-list.",
    },
    {
        "id": "js-inner-html",
        "extensions": {".js", ".jsx", ".ts", ".tsx", ".mjs"},
        "pattern": re.compile(r"\.innerHTML\s*=", re.IGNORECASE),
        "severity": "high",
        "category": "xss",
        "title": "Potential XSS via innerHTML assignment",
        "impact": "Untrusted HTML assignment can execute attacker-controlled script in users' browsers.",
        "recommendation": "Use textContent for text or sanitize HTML with a reviewed sanitizer before assignment.",
    },
    {
        "id": "react-dangerous-html",
        "extensions": {".js", ".jsx", ".ts", ".tsx", ".mjs"},
        "pattern": re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE),
        "severity": "high",
        "category": "xss",
        "title": "Potential XSS via dangerouslySetInnerHTML",
        "impact": "Rendering raw HTML in React can execute attacker-controlled markup.",
        "recommendation": "Avoid raw HTML rendering or sanitize with an allow-list sanitizer and tests.",
    },
    {
        "id": "document-write-xss",
        "extensions": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".html"},
        "pattern": re.compile(r"\bdocument\.write\s*\(", re.IGNORECASE),
        "severity": "medium",
        "category": "xss",
        "title": "Potential XSS via document.write",
        "impact": "document.write can inject unsafe markup and makes CSP hardening harder.",
        "recommendation": "Use DOM APIs with text nodes or sanitized templates.",
    },
    {
        "id": "js-child-process-shell",
        "extensions": {".js", ".jsx", ".ts", ".tsx", ".mjs"},
        "pattern": re.compile(r"\b(exec|execSync)\s*\("),
        "severity": "high",
        "title": "Shell command execution",
        "impact": "Command strings are injection-prone when user input reaches them.",
        "recommendation": "Use execFile/spawn with an argument array and validate all inputs.",
    },
    {
        "id": "js-sync-file-io",
        "extensions": {".js", ".jsx", ".ts", ".tsx", ".mjs"},
        "pattern": re.compile(r"\b(?:readFileSync|writeFileSync|readdirSync|statSync)\s*\("),
        "severity": "medium",
        "category": "performance",
        "title": "Synchronous filesystem call",
        "impact": "Synchronous I/O blocks the event loop and can degrade request latency under load.",
        "recommendation": "Use async filesystem APIs and move expensive work out of request handlers.",
    },
    {
        "id": "js-insecure-hash",
        "extensions": {".js", ".jsx", ".ts", ".tsx", ".mjs"},
        "pattern": re.compile(r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]"),
        "severity": "medium",
        "title": "Weak hash algorithm",
        "impact": "MD5/SHA1 are collision-prone and unsuitable for security-sensitive integrity.",
        "recommendation": "Use SHA-256 or a password hashing function such as Argon2/bcrypt when storing passwords.",
    },
    {
        "id": "py-shell-true",
        "extensions": {".py"},
        "pattern": re.compile(r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True"),
        "severity": "high",
        "title": "subprocess shell=True",
        "impact": "Shell expansion can turn input into command injection.",
        "recommendation": "Pass a list of arguments with shell=False and validate untrusted input.",
    },
    {
        "id": "py-unsafe-yaml",
        "extensions": {".py"},
        "pattern": re.compile(r"yaml\.load\s*\((?![^)]*SafeLoader)"),
        "severity": "high",
        "title": "Unsafe YAML loading",
        "impact": "yaml.load may instantiate arbitrary Python objects.",
        "recommendation": "Use yaml.safe_load or yaml.load(..., Loader=yaml.SafeLoader).",
    },
    {
        "id": "py-pickle",
        "extensions": {".py"},
        "pattern": re.compile(r"\bpickle\.loads?\s*\("),
        "severity": "high",
        "title": "Unsafe pickle deserialization",
        "impact": "Pickle can execute code during deserialization.",
        "recommendation": "Use JSON or a safe schema-based format for untrusted data.",
    },
    {
        "id": "py-verify-false",
        "extensions": {".py"},
        "pattern": re.compile(r"requests\.[a-z]+\([^)]*verify\s*=\s*False"),
        "severity": "medium",
        "title": "TLS verification disabled",
        "impact": "Disabling certificate checks enables man-in-the-middle attacks.",
        "recommendation": "Remove verify=False and configure trusted CA bundles when needed.",
    },
    {
        "id": "py-requests-no-timeout",
        "extensions": {".py"},
        "pattern": re.compile(r"requests\.(?:get|post|put|patch|delete)\s*\((?![^)]*timeout\s*=)", re.IGNORECASE),
        "severity": "medium",
        "category": "performance",
        "title": "HTTP request without timeout",
        "impact": "Unbounded outbound calls can hang workers and create cascading latency.",
        "recommendation": "Set connect/read timeouts and handle timeout exceptions explicitly.",
    },
    {
        "id": "docker-root",
        "extensions": {"Dockerfile", ".dockerfile"},
        "pattern": re.compile(r"^\s*USER\s+root\s*$", re.IGNORECASE),
        "severity": "medium",
        "title": "Container runs as root",
        "impact": "A container escape or writable mount has higher blast radius.",
        "recommendation": "Create and switch to a non-root user for runtime stages.",
    },
    {
        "id": "cors-wildcard",
        "extensions": {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".java", ".yaml", ".yml", ".json"},
        "pattern": re.compile(r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*"),
        "severity": "medium",
        "title": "Wildcard CORS origin",
        "impact": "Any origin may read protected browser responses if credentials are also allowed.",
        "recommendation": "Restrict CORS origins to trusted application domains.",
    },
]

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_WEIGHT = {"critical": 20, "high": 10, "medium": 4, "low": 1, "info": 0}
MAX_INLINE_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_REMOTE_ARCHIVE_BYTES = 96 * 1024 * 1024

_stdout_lock = threading.Lock()


def _write_frame(msg: dict) -> None:
    payload = json.dumps(msg, ensure_ascii=False)
    with _stdout_lock:
        sys.stdout.write(payload + "\n")
        sys.stdout.flush()


sampling = SamplingClient(write_frame=_write_frame)
_loop = asyncio.new_event_loop()
_loop_thread = threading.Thread(target=_loop.run_forever, daemon=True)
_loop_thread.start()


@dataclasses.dataclass
class PreparedSource:
    root: Path
    tempdir: tempfile.TemporaryDirectory[str] | None
    source: dict[str, Any]

    def cleanup(self) -> None:
        if self.tempdir is not None:
            self.tempdir.cleanup()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(*parts: Any) -> str:
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def sanitize_token_text(text: str, token: str | None = None) -> str:
    if not text:
        return ""
    out = text
    if token:
        out = out.replace(token, "[redacted-token]")
    for _, _, _, pattern in SECRET_PATTERNS:
        out = pattern.sub("[redacted-secret]", out)
    return out


def redact_line(line: str) -> str:
    cleaned = line.strip()
    for _, _, _, pattern in SECRET_PATTERNS:
        cleaned = pattern.sub("[redacted-secret]", cleaned)
    if re.search(r"(?i)(token|secret|password|api[_-]?key|authorization)", cleaned):
        cleaned = re.sub(
            r"[A-Za-z0-9_+/=-]{32,}",
            lambda match: "[redacted-secret]" if entropy(match.group(0)) >= 4.0 else match.group(0),
            cleaned,
        )
    if len(cleaned) > 180:
        cleaned = cleaned[:177] + "..."
    return cleaned


def parse_github_repo(url: str) -> dict[str, str]:
    raw = (url or "").strip()
    if not raw:
        raise ValueError("repository_url is required")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", raw):
        owner, repo = raw.split("/", 1)
    elif raw.startswith("git@github.com:"):
        owner_repo = raw.removeprefix("git@github.com:").removesuffix(".git")
        owner, repo = owner_repo.split("/", 1)
    else:
        parsed = urllib.parse.urlparse(raw)
        if parsed.netloc.lower() != "github.com":
            raise ValueError("Only github.com repositories are supported for clone/PR workflows")
        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(parts) < 2:
            raise ValueError("GitHub URL must include owner and repository")
        owner, repo = parts[0], parts[1].removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", owner) or not re.fullmatch(
        r"[A-Za-z0-9_.-]{1,100}", repo
    ):
        raise ValueError("Invalid GitHub owner or repository name")
    return {
        "owner": owner,
        "repo": repo,
        "full_name": f"{owner}/{repo}",
        "https_url": f"https://github.com/{owner}/{repo}.git",
        "web_url": f"https://github.com/{owner}/{repo}",
    }


@contextlib.contextmanager
def git_auth_env(token: str | None):
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if not token:
        yield env
        return
    tempdir = tempfile.TemporaryDirectory()
    script = Path(tempdir.name) / ("askpass.bat" if os.name == "nt" else "askpass.sh")
    if os.name == "nt":
        script.write_text(
            "@echo off\r\n"
            "echo %GIT_ASKPASS_RESPONSE%\r\n",
            encoding="utf-8",
        )
    else:
        script.write_text("#!/bin/sh\nprintf '%s\\n' \"$GIT_ASKPASS_RESPONSE\"\n", encoding="utf-8")
        script.chmod(0o700)
    env["GIT_ASKPASS"] = str(script)
    env["GIT_ASKPASS_RESPONSE"] = token
    env["GIT_USERNAME"] = "x-access-token"
    try:
        yield env
    finally:
        tempdir.cleanup()


def run_cmd(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 90,
    token: str | None = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if token:
        proc.stdout = sanitize_token_text(proc.stdout, token)
        proc.stderr = sanitize_token_text(proc.stderr, token)
    return proc


def github_headers(github_token: str = "") -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "RepoGuardianAI/0.1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    return headers


def read_limited_response(resp: Any, max_bytes: int) -> bytes:
    length = resp.headers.get("Content-Length")
    if length and int(length) > max_bytes:
        raise ValueError(f"GitHub archive is larger than {max_bytes // (1024 * 1024)} MB")
    blob = resp.read(max_bytes + 1)
    if len(blob) > max_bytes:
        raise ValueError(f"GitHub archive is larger than {max_bytes // (1024 * 1024)} MB")
    return blob


def github_default_branch(repo: dict[str, str], github_token: str = "") -> str:
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo['owner']}/{repo['repo']}",
        headers=github_headers(github_token),
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return str(data.get("default_branch") or "main")


def download_github_archive(repo: dict[str, str], branch: str = "", github_token: str = "") -> PreparedSource:
    ref = branch.strip() or github_default_branch(repo, github_token)
    encoded_ref = urllib.parse.quote(ref, safe="")
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo['owner']}/{repo['repo']}/zipball/{encoded_ref}",
        headers=github_headers(github_token),
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        blob = read_limited_response(resp, MAX_REMOTE_ARCHIVE_BYTES)
    prepared = safe_extract_zip(blob, f"{repo['repo']}-{ref}.zip", max_archive_bytes=MAX_REMOTE_ARCHIVE_BYTES)
    prepared.source = {
        "type": "github",
        "repository": repo["full_name"],
        "repository_url": repo["web_url"],
        "branch": ref,
    }
    return prepared


def git_clone_repository(repository_url: str, branch: str = "", github_token: str = "") -> PreparedSource:
    repo = parse_github_repo(repository_url)
    tmp = tempfile.TemporaryDirectory(prefix="repoguardian-clone-")
    dest = Path(tmp.name) / repo["repo"]
    args = ["git", "clone", "--depth", "1"]
    if branch.strip():
        args += ["--branch", branch.strip()]
    args += [repo["https_url"], str(dest)]
    with git_auth_env(github_token or None) as env:
        # GitHub asks for username first and then password. For PAT auth over
        # HTTPS, either field can be the token for clone/push in current Git.
        env["GIT_ASKPASS_RESPONSE"] = github_token or ""
        proc = run_cmd(args, env=env, timeout=180, token=github_token or None)
    if proc.returncode != 0:
        tmp.cleanup()
        raise RuntimeError(f"git clone failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return PreparedSource(
        root=dest,
        tempdir=tmp,
        source={
            "type": "github",
            "repository": repo["full_name"],
            "repository_url": repo["web_url"],
            "branch": branch.strip() or detect_git_branch(dest),
        },
    )


def clone_repository(repository_url: str, branch: str = "", github_token: str = "") -> PreparedSource:
    repo = parse_github_repo(repository_url)
    try:
        return download_github_archive(repo, branch, github_token)
    except Exception:
        return git_clone_repository(repository_url, branch, github_token)


def detect_git_branch(path: Path) -> str:
    proc = run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=path, timeout=10)
    if proc.returncode == 0:
        return proc.stdout.strip()
    return ""


def safe_extract_zip(blob: bytes, name: str, max_archive_bytes: int = MAX_INLINE_ARCHIVE_BYTES) -> PreparedSource:
    if len(blob) > max_archive_bytes:
        raise ValueError("Archive is too large for inline scan. Use a GitHub URL for large repositories.")
    tmp = tempfile.TemporaryDirectory(prefix="repoguardian-archive-")
    archive = Path(tmp.name) / (Path(name or "repository.zip").name or "repository.zip")
    archive.write_bytes(blob)
    root = Path(tmp.name) / "repo"
    root.mkdir()
    lower = archive.name.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for member in zf.infolist():
                target = (root / member.filename).resolve()
                if not str(target).startswith(str(root.resolve())):
                    raise ValueError("Archive contains an unsafe path")
            zf.extractall(root)
    elif lower.endswith((".tar", ".tar.gz", ".tgz")):
        with tarfile.open(archive) as tf:
            for member in tf.getmembers():
                target = (root / member.name).resolve()
                if not str(target).startswith(str(root.resolve())):
                    raise ValueError("Archive contains an unsafe path")
            tf.extractall(root)
    else:
        tmp.cleanup()
        raise ValueError("Uploaded repository must be a .zip, .tar, .tar.gz, or .tgz archive")
    scan_root = collapse_single_directory(root)
    return PreparedSource(
        root=scan_root,
        tempdir=tmp,
        source={"type": "archive", "archive_name": archive.name, "branch": ""},
    )


def collapse_single_directory(root: Path) -> Path:
    entries = [p for p in root.iterdir() if p.name not in {"__MACOSX"}]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return root


def prepare_source(args: dict[str, Any]) -> PreparedSource:
    source_type = (args.get("source_type") or "").strip()
    if source_type == "github":
        return clone_repository(
            args.get("repository_url") or "",
            args.get("branch") or "",
            args.get("github_token") or "",
        )
    if source_type == "archive":
        archive_b64 = args.get("archive_b64") or ""
        if not archive_b64:
            raise ValueError("archive_b64 is required for archive scans")
        try:
            blob = base64.b64decode(archive_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("archive_b64 is not valid base64") from exc
        return safe_extract_zip(blob, args.get("archive_name") or "repository.zip")
    if source_type == "local_path":
        raw = args.get("local_path") or ""
        path = Path(raw).expanduser().resolve()
        if not path.is_dir():
            raise ValueError("local_path must point to an existing repository directory")
        return PreparedSource(
            root=path,
            tempdir=None,
            source={"type": "local_path", "path": str(path), "branch": detect_git_branch(path)},
        )
    raise ValueError("source_type must be github, archive, or local_path")


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def is_probably_text(path: Path, sample: bytes) -> bool:
    if b"\x00" in sample:
        return False
    if path.name in {"Dockerfile", "Makefile", "Gemfile", "Pipfile"}:
        return True
    suffix = path.suffix.lower()
    if suffix in TEXT_EXTS:
        return True
    with contextlib.suppress(UnicodeDecodeError):
        sample.decode("utf-8")
        return True
    return False


def iter_repo_files(root: Path, *, max_files: int, max_bytes: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    files: list[dict[str, Any]] = []
    skipped = {"dirs": 0, "binary": 0, "large": 0, "limit": 0}
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if path.is_dir():
            if should_skip(rel):
                skipped["dirs"] += 1
            continue
        if should_skip(rel):
            continue
        if len(files) >= max_files:
            skipped["limit"] += 1
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max(1024, max_bytes * 4):
            skipped["large"] += 1
            continue
        try:
            sample = path.read_bytes()[:4096]
        except OSError:
            continue
        if not is_probably_text(path, sample):
            skipped["binary"] += 1
            continue
        files.append({"path": path, "rel": rel.as_posix(), "size": size})
    return files, skipped


def read_text(path: Path, max_bytes: int) -> str:
    data = path.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def make_finding(
    *,
    category: str,
    severity: str,
    title: str,
    file: str = "",
    line: int | None = None,
    evidence: str = "",
    impact: str,
    recommendation: str,
    package: str = "",
    current_version: str = "",
    fixed_version: str = "",
    source: str = "",
) -> dict[str, Any]:
    return {
        "id": stable_id(category, severity, title, file, line, package, evidence),
        "category": category,
        "severity": severity,
        "title": title,
        "file": file,
        "line": line,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
        "package": package,
        "current_version": current_version,
        "fixed_version": fixed_version,
        "source": source,
        "confidence": "high" if severity in {"critical", "high"} else "medium",
    }


def scan_secrets(root: Path, files: list[dict[str, Any]], *, max_bytes: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in files:
        path = item["path"]
        rel = item["rel"]
        try:
            text = read_text(path, max_bytes)
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for title, severity, recommendation, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        make_finding(
                            category="secret",
                            severity=severity,
                            title=title,
                            file=rel,
                            line=line_no,
                            evidence=redact_line(line),
                            impact="Credential material in source control can be reused by attackers.",
                            recommendation=recommendation,
                        )
                    )
                    break
            if looks_like_entropy_secret(line):
                findings.append(
                    make_finding(
                        category="secret",
                        severity="medium",
                        title="High-entropy token-like value",
                        file=rel,
                        line=line_no,
                        evidence=redact_line(line),
                        impact="High-entropy values near credential words often indicate committed secrets.",
                        recommendation="Verify whether this value is a secret; rotate it and move it to managed runtime configuration if so.",
                    )
                )
    return dedupe_findings(findings)[:80]


def looks_like_entropy_secret(line: str) -> bool:
    if not re.search(r"(?i)(token|secret|password|api[_-]?key|authorization)", line):
        return False
    candidates = re.findall(r"[A-Za-z0-9_+/=-]{32,}", line)
    return any(entropy(value) >= 4.3 for value in candidates)


def scan_static(files: list[dict[str, Any]], *, max_bytes: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in files:
        path: Path = item["path"]
        rel = item["rel"]
        ext_keys = {path.suffix.lower(), path.name}
        applicable = [rule for rule in STATIC_RULES if ext_keys & set(rule["extensions"])]
        if not applicable:
            continue
        try:
            text = read_text(path, max_bytes)
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for rule in applicable:
                if rule["pattern"].search(line):
                    findings.append(
                        make_finding(
                            category=rule.get("category", "static"),
                            severity=rule["severity"],
                            title=rule["title"],
                            file=rel,
                            line=line_no,
                            evidence=redact_line(line),
                            impact=rule["impact"],
                            recommendation=rule["recommendation"],
                            source=rule["id"],
                        )
                    )
    return dedupe_findings(findings)[:120]


def scan_architecture(files: list[dict[str, Any]], root: Path, *, max_bytes: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    package_json_count = 0
    has_lockfile = False
    has_tests = False
    for item in files:
        rel = item["rel"]
        path = item["path"]
        if Path(rel).name == "package.json":
            package_json_count += 1
        if Path(rel).name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "uv.lock", "poetry.lock", "Pipfile.lock", "go.sum"}:
            has_lockfile = True
        if re.search(r"(^|/)(tests?|__tests__|spec)(/|$)", rel, re.IGNORECASE):
            has_tests = True
        if path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".java", ".php", ".rb"}:
            try:
                text = read_text(path, max_bytes)
            except OSError:
                continue
            line_count = len(text.splitlines())
            if line_count >= 900:
                findings.append(
                    make_finding(
                        category="architecture",
                        severity="medium",
                        title="Large high-risk source file",
                        file=rel,
                        evidence=f"{line_count} lines",
                        impact="Very large files often mix responsibilities, hide security checks, and make review slower.",
                        recommendation="Split the file around clear ownership boundaries and add focused tests around security-sensitive paths.",
                        source="architecture-large-file",
                    )
                )
            if re.search(r"\b(app|server)\.(?:js|ts|py)$", rel, re.IGNORECASE) and line_count >= 400:
                findings.append(
                    make_finding(
                        category="architecture",
                        severity="low",
                        title="Centralized application entrypoint",
                        file=rel,
                        evidence=f"{line_count} lines in application entrypoint",
                        impact="A crowded entrypoint can blur middleware, routing, authorization, and error handling responsibilities.",
                        recommendation="Move routes, middleware, configuration, and security checks into focused modules.",
                        source="architecture-entrypoint",
                    )
                )
    if package_json_count and not has_lockfile:
        findings.append(
            make_finding(
                category="architecture",
                severity="medium",
                title="Dependency manifest without lockfile",
                evidence="package.json present without a supported lockfile",
                impact="Builds can resolve different transitive dependency versions across environments.",
                recommendation="Commit a package lockfile and enable dependency update automation.",
                source="architecture-missing-lockfile",
            )
        )
    if files and not has_tests:
        findings.append(
            make_finding(
                category="architecture",
                severity="low",
                title="No obvious test directory",
                evidence="No tests, test, __tests__, or spec directory detected",
                impact="Security fixes are harder to validate without regression coverage.",
                recommendation="Add tests around authentication, input validation, serialization, and database access paths.",
                source="architecture-missing-tests",
            )
        )
    return dedupe_findings(findings)[:60]


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for finding in findings:
        key = finding["id"]
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    out.sort(key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0), f["category"], f.get("file") or ""))
    return out


def parse_dependencies(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    deps: list[dict[str, Any]] = []
    warnings: list[str] = []
    for package_json in root.rglob("package.json"):
        if should_skip(package_json.relative_to(root)):
            continue
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not parse {package_json.relative_to(root).as_posix()}: {exc}")
            continue
        rel = package_json.relative_to(root).as_posix()
        for scope in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, spec in (data.get(scope) or {}).items():
                version = normalize_version_spec(str(spec))
                if version:
                    deps.append(dep_item("npm", name, version, spec=str(spec), file=rel, scope=scope))

    for req in root.rglob("requirements*.txt"):
        if should_skip(req.relative_to(root)):
            continue
        rel = req.relative_to(root).as_posix()
        for raw in req.read_text(encoding="utf-8", errors="replace").splitlines():
            parsed = parse_requirement_line(raw)
            if parsed:
                name, version = parsed
                deps.append(dep_item("PyPI", name, version, spec=raw.strip(), file=rel, scope="runtime"))

    for pyproject in root.rglob("pyproject.toml"):
        if should_skip(pyproject.relative_to(root)) or tomllib is None:
            continue
        rel = pyproject.relative_to(root).as_posix()
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not parse {rel}: {exc}")
            continue
        for spec in data.get("project", {}).get("dependencies", []) or []:
            parsed = parse_requirement_line(str(spec))
            if parsed:
                name, version = parsed
                deps.append(dep_item("PyPI", name, version, spec=str(spec), file=rel, scope="runtime"))
        poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
        for name, spec in poetry.items():
            if name.lower() == "python":
                continue
            version = normalize_version_spec(str(spec))
            if version:
                deps.append(dep_item("PyPI", name, version, spec=str(spec), file=rel, scope="runtime"))

    for go_mod in root.rglob("go.mod"):
        if should_skip(go_mod.relative_to(root)):
            continue
        rel = go_mod.relative_to(root).as_posix()
        deps.extend(parse_go_mod(go_mod.read_text(encoding="utf-8", errors="replace"), rel))

    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for dep in deps:
        unique[(dep["ecosystem"], dep["name"].lower(), dep["version"])] = dep
    return list(unique.values()), warnings


def dep_item(ecosystem: str, name: str, version: str, *, spec: str, file: str, scope: str) -> dict[str, Any]:
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "spec": spec,
        "file": file,
        "scope": scope,
        "latest": "",
        "outdated": False,
    }


def normalize_version_spec(spec: str) -> str:
    raw = spec.strip()
    if not raw or raw in {"*", "latest"} or raw.startswith(("git+", "http:", "https:", "file:", "workspace:")):
        return ""
    match = re.search(r"(\d+(?:\.\d+){0,3}(?:[-+][A-Za-z0-9_.-]+)?)", raw)
    return match.group(1) if match else ""


def parse_requirement_line(raw: str) -> tuple[str, str] | None:
    line = raw.split("#", 1)[0].strip()
    if not line or line.startswith(("-r ", "--")):
        return None
    match = re.match(r"([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|>|<=|<)\s*([A-Za-z0-9_.!+-]+)", line)
    if not match:
        return None
    return match.group(1), normalize_version_spec(match.group(2))


def parse_go_mod(text: str, rel: str) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line.removeprefix("require ").strip()
        if not in_block and not raw.strip().startswith("require "):
            continue
        parts = line.split()
        if len(parts) >= 2:
            deps.append(dep_item("Go", parts[0], parts[1].removeprefix("v"), spec=line, file=rel, scope="runtime"))
    return deps


def query_dependency_network(deps: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    if not deps:
        return deps, [], warnings
    vulns = query_osv(deps, warnings)
    for dep in deps[:80]:
        with contextlib.suppress(Exception):
            latest = query_latest(dep["ecosystem"], dep["name"])
            if latest:
                dep["latest"] = latest
                dep["outdated"] = compare_versions(dep["version"], latest) < 0
    return deps, vulns, warnings


def query_osv(deps: list[dict[str, Any]], warnings: list[str]) -> list[dict[str, Any]]:
    pairs = [
        (dep, {"package": {"ecosystem": dep["ecosystem"], "name": dep["name"]}, "version": dep["version"]})
        for dep in deps[:100]
        if dep["ecosystem"] in {"npm", "PyPI", "Go"} and dep.get("version")
    ]
    if not pairs:
        return []
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps({"queries": [query for _, query in pairs]}).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "RepoGuardianAI/0.1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=18) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"OSV vulnerability lookup unavailable: {exc}")
        return []
    findings: list[dict[str, Any]] = []
    for (dep, _), result in zip(pairs, data.get("results") or []):
        for vuln in result.get("vulns") or []:
            severity = osv_severity(vuln)
            aliases = ", ".join(vuln.get("aliases") or [])
            fixed = fixed_versions(vuln)
            findings.append(
                make_finding(
                    category="dependency",
                    severity=severity,
                    title=f"{dep['name']} vulnerability: {vuln.get('id', 'OSV')}",
                    file=dep["file"],
                    evidence=(vuln.get("summary") or aliases or "OSV vulnerability")[:180],
                    impact=(vuln.get("details") or vuln.get("summary") or "Known vulnerable dependency.")[:260],
                    recommendation=(
                        f"Upgrade {dep['name']} to {fixed} or later."
                        if fixed
                        else f"Review upstream advisory and upgrade {dep['name']} to a patched version."
                    ),
                    package=dep["name"],
                    current_version=dep["version"],
                    fixed_version=fixed,
                    source=vuln.get("id", "OSV"),
                )
            )
    return findings


def osv_severity(vuln: dict[str, Any]) -> str:
    for item in vuln.get("severity") or []:
        score = str(item.get("score") or "")
        if score.upper().startswith("CVSS:"):
            numeric = re.search(r"(\d+(?:\.\d+)?)", score)
            if numeric:
                value = float(numeric.group(1))
                if value >= 9:
                    return "critical"
                if value >= 7:
                    return "high"
                if value >= 4:
                    return "medium"
    return "high"


def fixed_versions(vuln: dict[str, Any]) -> str:
    versions: list[str] = []
    for affected in vuln.get("affected") or []:
        for range_obj in affected.get("ranges") or []:
            for event in range_obj.get("events") or []:
                fixed = event.get("fixed")
                if fixed:
                    versions.append(str(fixed))
    return ", ".join(sorted(set(versions), key=version_key)[:3])


def query_latest(ecosystem: str, name: str) -> str:
    if ecosystem == "npm":
        encoded = urllib.parse.quote(name, safe="@")
        url = f"https://registry.npmjs.org/{encoded}/latest"
        field = "version"
    elif ecosystem == "PyPI":
        encoded = urllib.parse.quote(name)
        url = f"https://pypi.org/pypi/{encoded}/json"
        field = ("info", "version")
    elif ecosystem == "Go":
        encoded = urllib.parse.quote(name, safe="")
        url = f"https://proxy.golang.org/{encoded}/@latest"
        field = "Version"
    else:
        return ""
    req = urllib.request.Request(url, headers={"User-Agent": "RepoGuardianAI/0.1"})
    with urllib.request.urlopen(req, timeout=8) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if isinstance(field, tuple):
        current: Any = data
        for part in field:
            current = current.get(part, {})
        return str(current or "")
    return str(data.get(field) or "").removeprefix("v")


def version_key(value: str) -> tuple[tuple[int, Any], ...]:
    parts = re.split(r"[.\-+_]", value.removeprefix("v"))
    key: list[tuple[int, Any]] = []
    for part in parts:
        key.append((0, int(part)) if part.isdigit() else (1, part))
    return tuple(key)


def compare_versions(current: str, latest: str) -> int:
    a = version_key(current)
    b = version_key(latest)
    return (a > b) - (a < b)


def outdated_findings(deps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for dep in deps:
        if dep.get("outdated"):
            findings.append(
                make_finding(
                    category="dependency",
                    severity="low",
                    title=f"Outdated package: {dep['name']}",
                    file=dep["file"],
                    evidence=f"{dep['name']} {dep['version']} -> {dep['latest']}",
                    impact="Outdated packages increase exposure to known bugs and future advisories.",
                    recommendation=f"Review changelog and update {dep['name']} from {dep['version']} to {dep['latest']}.",
                    package=dep["name"],
                    current_version=dep["version"],
                    fixed_version=dep["latest"],
                    source="registry-latest",
                )
            )
    return findings[:80]


def repo_inventory(root: Path, files: list[dict[str, Any]]) -> dict[str, Any]:
    languages: dict[str, int] = {}
    manifests: list[str] = []
    for item in files:
        path = Path(item["rel"])
        suffix = path.suffix.lower() or path.name
        languages[suffix] = languages.get(suffix, 0) + 1
        if path.name in {"package.json", "requirements.txt", "pyproject.toml", "go.mod", "pom.xml", "Gemfile"}:
            manifests.append(item["rel"])
    top = sorted(languages.items(), key=lambda kv: kv[1], reverse=True)[:8]
    return {
        "file_count": len(files),
        "top_file_types": [{"type": key, "count": count} for key, count in top],
        "manifests": manifests[:50],
    }


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    categories: dict[str, int] = {}
    weighted = 0
    for finding in findings:
        sev = finding.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
        categories[finding["category"]] = categories.get(finding["category"], 0) + 1
        weighted += SEVERITY_WEIGHT.get(sev, 0)
    risk_score = min(100, weighted)
    grade = "A" if risk_score < 10 else "B" if risk_score < 30 else "C" if risk_score < 60 else "D"
    return {
        "risk_score": risk_score,
        "grade": grade,
        "counts": counts,
        "categories": categories,
        "finding_count": len(findings),
    }


def build_suggestions(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    suggestions: list[dict[str, Any]] = []
    for finding in findings[:50]:
        suggestion = {
            "id": "fix-" + finding["id"],
            "finding_id": finding["id"],
            "severity": finding["severity"],
            "title": finding["recommendation"],
            "file": finding.get("file") or "",
            "action": infer_fix_action(finding),
            "can_auto_apply": False,
        }
        if finding["category"] == "dependency" and finding.get("package") and finding.get("fixed_version"):
            suggestion["can_auto_apply"] = False
            suggestion["action"] = f"Upgrade {finding['package']} to {finding['fixed_version']} after test validation."
        suggestions.append(suggestion)
    return suggestions


def infer_fix_action(finding: dict[str, Any]) -> str:
    category = finding.get("category")
    if category == "secret":
        return "Rotate exposed credential, purge git history if needed, and replace committed value with runtime configuration."
    if category == "static":
        return "Patch the highlighted code path and add a regression test for unsafe input handling."
    if category == "dependency":
        return "Upgrade or remove the vulnerable dependency and run the package manager test suite."
    return finding.get("recommendation") or "Review and remediate."


def deterministic_risk(summary: dict[str, Any], findings: list[dict[str, Any]], warnings: list[str]) -> dict[str, Any]:
    top = findings[:5]
    if summary["risk_score"] >= 60:
        posture = "High risk"
    elif summary["risk_score"] >= 30:
        posture = "Elevated risk"
    elif findings:
        posture = "Moderate risk"
    else:
        posture = "Low observed risk"
    return {
        "mode": "deterministic",
        "posture": posture,
        "executive_summary": (
            f"{summary['finding_count']} findings were detected. "
            f"Critical/high issues: {summary['counts'].get('critical', 0) + summary['counts'].get('high', 0)}. "
            f"Primary categories: {', '.join(sorted(summary['categories'])) or 'none'}."
        ),
        "priority_actions": [f["recommendation"] for f in top[:4]],
        "business_risk": (
            "Secrets and high-severity dependency/static findings should be treated as release blockers."
            if top
            else "No release-blocking issues were observed by the configured scanners."
        ),
        "limitations": warnings[:5],
    }


async def ai_risk(summary: dict[str, Any], findings: list[dict[str, Any]], source: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "source": source,
        "summary": summary,
        "top_findings": [
            {
                "severity": f["severity"],
                "category": f["category"],
                "title": f["title"],
                "file": f.get("file"),
                "impact": f["impact"],
                "recommendation": f["recommendation"],
            }
            for f in findings[:15]
        ],
    }
    prompt = (
        "You are RepoGuardian AI, an autonomous application security engineer. "
        "Summarize repository risk for an engineering lead using only the scan evidence. "
        "Prioritize release blockers first: secrets, critical/high dependency CVEs, "
        "SQL injection, XSS, unsafe command execution, auth/data-access flaws, and severe "
        "architecture or performance risks. Return strict JSON with keys posture, "
        "executive_summary, priority_actions (array), business_risk, release_blocker "
        "(boolean), validation_plan (array), confidence, and limitations. Do not invent "
        "findings or claim a fix was applied.\n\n"
        + json.dumps(payload, ensure_ascii=False)
    )
    result = await sampling.create_message(
        messages=[{"role": "user", "content": {"type": "text", "text": prompt}}],
        max_tokens=1200,
        system_prompt=(
            "You are a senior application security reviewer. Be concise, "
            "evidence-bound, and practical. Separate confirmed findings from assumptions."
        ),
        response_format={"type": "json_object"},
        on_unsupported="text",
        timeout=65.0,
    )
    text = ""
    content = result.get("content") or {}
    if isinstance(content, dict):
        text = content.get("text") or ""
    try:
        data = json.loads(text)
        data["mode"] = "anna-sampling"
        data["model"] = result.get("model")
        return data
    except json.JSONDecodeError:
        return {
            "mode": "anna-sampling",
            "posture": "Review required",
            "executive_summary": text[:1200],
            "priority_actions": [],
            "business_risk": "",
            "limitations": ["Anna sampling returned non-JSON text."],
            "model": result.get("model"),
        }


def run_ai_risk(summary_obj: dict[str, Any], findings: list[dict[str, Any]], source: dict[str, Any]) -> dict[str, Any]:
    fut = asyncio.run_coroutine_threadsafe(ai_risk(summary_obj, findings, source), _loop)
    return fut.result(timeout=90.0)


def scan_repository(**args: Any) -> dict[str, Any]:
    started = time.time()
    prepared = prepare_source(args)
    warnings: list[str] = []
    try:
        max_files = max(50, min(20000, int(args.get("max_files") or 6000)))
        max_bytes = max(4096, min(1_000_000, int(args.get("max_bytes") or 250000)))
        files, skipped = iter_repo_files(prepared.root, max_files=max_files, max_bytes=max_bytes)
        inventory = repo_inventory(prepared.root, files)
        deps, dep_warnings = parse_dependencies(prepared.root)
        warnings.extend(dep_warnings)
        dep_findings: list[dict[str, Any]] = []
        if bool(args.get("dependency_network", True)):
            deps, osv_findings, network_warnings = query_dependency_network(deps)
            warnings.extend(network_warnings)
            dep_findings.extend(osv_findings)
            dep_findings.extend(outdated_findings(deps))
        else:
            warnings.append("Dependency network checks were disabled for this scan.")

        secret_findings = scan_secrets(prepared.root, files, max_bytes=max_bytes)
        static_findings = scan_static(files, max_bytes=max_bytes)
        architecture_findings = scan_architecture(files, prepared.root, max_bytes=max_bytes)
        findings = dedupe_findings(dep_findings + secret_findings + static_findings + architecture_findings)
        summary_obj = summarize(findings)
        suggestions = build_suggestions(findings)
        include_ai = bool(args.get("include_ai", True))
        host_sampling = bool(args.get("host_sampling", False))
        if include_ai and host_sampling:
            try:
                risk = run_ai_risk(summary_obj, findings, prepared.source)
            except SamplingError as exc:
                warnings.append(f"Anna risk synthesis unavailable: {exc.message}")
                risk = deterministic_risk(summary_obj, findings, warnings)
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Anna risk synthesis failed: {exc}")
                risk = deterministic_risk(summary_obj, findings, warnings)
        else:
            if include_ai and not host_sampling:
                warnings.append("Anna host sampling is not granted in this environment; deterministic risk analysis was used.")
            risk = deterministic_risk(summary_obj, findings, warnings)
        scan_id = stable_id(prepared.source, started, summary_obj, len(files))
        return {
            "scan_id": scan_id,
            "created_at": utc_now(),
            "duration_ms": int((time.time() - started) * 1000),
            "source": prepared.source,
            "workflow": [
                {"key": "clone", "label": "Clone/unpack repo", "status": "complete"},
                {"key": "dependency", "label": "Dependency scan", "status": "complete"},
                {"key": "static", "label": "Static code analysis", "status": "complete"},
                {"key": "secrets", "label": "Secret detection", "status": "complete"},
                {"key": "finds", "label": "SQL injection, XSS, architecture, performance", "status": "complete"},
                {"key": "risk", "label": "Anna risk analysis", "status": "complete" if include_ai else "skipped"},
                {"key": "fixes", "label": "Suggested fixes", "status": "complete"},
                {"key": "approval", "label": "User approval", "status": "ready"},
                {"key": "patch", "label": "Generate and download patch", "status": "ready"},
                {"key": "pr", "label": "Generate pull request", "status": "ready"},
            ],
            "inventory": inventory,
            "skipped": skipped,
            "dependencies": deps[:250],
            "summary": summary_obj,
            "risk_analysis": risk,
            "findings": findings[:250],
            "suggestions": suggestions,
            "warnings": warnings[:20],
            "report_markdown": render_report_markdown(
                {
                    "scan_id": scan_id,
                    "created_at": utc_now(),
                    "source": prepared.source,
                    "summary": summary_obj,
                    "risk_analysis": risk,
                    "findings": findings[:80],
                    "suggestions": suggestions[:80],
                    "warnings": warnings[:20],
                }
            ),
        }
    finally:
        prepared.cleanup()


def render_report_markdown(scan_result: dict[str, Any]) -> str:
    source = scan_result.get("source") or {}
    summary_obj = scan_result.get("summary") or {}
    risk = scan_result.get("risk_analysis") or {}
    findings = scan_result.get("findings") or []
    suggestions = scan_result.get("suggestions") or []
    warnings = scan_result.get("warnings") or []
    lines = [
        "# RepoGuardian AI Security Report",
        "",
        f"- Scan ID: `{scan_result.get('scan_id', '')}`",
        f"- Created: `{scan_result.get('created_at', '')}`",
        f"- Source: `{source.get('repository') or source.get('archive_name') or source.get('path') or source.get('type')}`",
        f"- Risk score: **{summary_obj.get('risk_score', 0)}/100**",
        f"- Grade: **{summary_obj.get('grade', 'n/a')}**",
        "",
        "## Risk Analysis",
        "",
        risk.get("executive_summary") or "No risk summary was generated.",
        "",
        "## Findings",
        "",
    ]
    if findings:
        lines.extend(["| Severity | Category | Finding | Location | Recommendation |", "|---|---|---|---|---|"])
        for finding in findings[:80]:
            location = finding.get("file") or ""
            if finding.get("line"):
                location += f":{finding['line']}"
            lines.append(
                "| {severity} | {category} | {title} | {location} | {recommendation} |".format(
                    severity=finding.get("severity", ""),
                    category=finding.get("category", ""),
                    title=escape_md(finding.get("title", "")),
                    location=escape_md(location or "n/a"),
                    recommendation=escape_md(finding.get("recommendation", "")),
                )
            )
    else:
        lines.append("No findings were detected by the configured scanners.")
    lines.extend(["", "## Suggested Fixes", ""])
    if suggestions:
        for item in suggestions[:40]:
            lines.append(f"- {item.get('title', '')}")
    else:
        lines.append("- No fixes required from this scan.")
    if warnings:
        lines.extend(["", "## Scanner Notes", ""])
        for warning in warnings:
            lines.append(f"- {escape_md(str(warning))}")
    lines.extend(
        [
            "",
            "---",
            "Generated by RepoGuardian AI. Review changes and run the repository test suite before merging.",
            "",
        ]
    )
    return "\n".join(lines)


def escape_md(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def build_pr_files(scan_result: dict[str, Any]) -> dict[str, str]:
    scan_id = scan_result.get("scan_id") or stable_id(time.time())
    report = scan_result.get("report_markdown") or render_report_markdown(scan_result)
    files = {f".github/repoguardian/security-report-{scan_id}.md": report}
    manifests = ((scan_result.get("inventory") or {}).get("manifests") or [])
    ecosystems = []
    if any(path.endswith("package.json") for path in manifests):
        ecosystems.append(("npm", "/", "weekly"))
    if any(path.endswith(("requirements.txt", "pyproject.toml")) for path in manifests):
        ecosystems.append(("pip", "/", "weekly"))
    if any(path.endswith("go.mod") for path in manifests):
        ecosystems.append(("gomod", "/", "weekly"))
    if ecosystems:
        files[".github/dependabot.yml"] = render_dependabot(ecosystems)
    files[".gitignore"] = "# RepoGuardian AI secret hygiene\n.env\n.env.local\n.env.*.local\n*.pem\n*.key\n"
    return files


def generate_patch(scan_result: dict[str, Any], approved: bool) -> dict[str, Any]:
    if not approved:
        raise ValueError("Patch generation requires explicit user approval")
    files = build_pr_files(scan_result)
    patch_text = render_unified_patch(files)
    scan_id = scan_result.get("scan_id") or stable_id(time.time())
    return {
        "filename": f"repoguardian-fixes-{scan_id}.patch",
        "patch_text": patch_text,
        "bytes": len(patch_text.encode("utf-8")),
        "files": [{"path": path, "bytes": len(content.encode("utf-8"))} for path, content in files.items()],
        "summary": [
            "Adds a RepoGuardian security report with prioritized findings and fix guidance.",
            "Adds dependency update automation when supported manifests were detected.",
            "Adds secret hygiene ignore patterns as a reviewable baseline.",
            "Source-code vulnerabilities are intentionally left as explicit fix recommendations unless they are safe mechanical changes.",
        ],
    }


def render_unified_patch(files: dict[str, str]) -> str:
    chunks: list[str] = []
    for path, content in files.items():
        new_lines = content.splitlines(keepends=True)
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        diff = difflib.unified_diff(
            [],
            new_lines,
            fromfile="/dev/null",
            tofile=f"b/{path}",
            lineterm="",
        )
        chunks.append(f"diff --git a/{path} b/{path}\nnew file mode 100644\n" + "\n".join(diff) + "\n")
    return "\n".join(chunks)


def render_dependabot(ecosystems: list[tuple[str, str, str]]) -> str:
    lines = ["version: 2", "updates:"]
    for ecosystem, directory, interval in ecosystems:
        lines.extend(
            [
                f"  - package-ecosystem: \"{ecosystem}\"",
                f"    directory: \"{directory}\"",
                "    schedule:",
                f"      interval: \"{interval}\"",
                "    open-pull-requests-limit: 5",
            ]
        )
    return "\n".join(lines) + "\n"


def create_pull_request(
    repository_url: str,
    scan_result: dict[str, Any],
    base_branch: str = "",
    github_token: str = "",
    dry_run: bool = True,
    approved: bool = False,
    title: str = "",
    body: str = "",
) -> dict[str, Any]:
    repo = parse_github_repo(repository_url)
    files = build_pr_files(scan_result)
    branch = f"repoguardian/security-audit-{scan_result.get('scan_id', stable_id(time.time()))[:10]}"
    pr_title = title.strip() or f"RepoGuardian AI security report for {repo['full_name']}"
    pr_body = body.strip() or build_pr_body(scan_result)
    if dry_run:
        return {
            "dry_run": True,
            "repository": repo["full_name"],
            "base_branch": base_branch or "(default branch)",
            "branch": branch,
            "title": pr_title,
            "body": pr_body,
            "files": [{"path": path, "bytes": len(content.encode("utf-8"))} for path, content in files.items()],
        }
    if not approved:
        raise ValueError("Real PR creation requires approved=true")
    if not github_token:
        raise ValueError("Real PR creation requires a runtime GitHub token")
    tmp = tempfile.TemporaryDirectory(prefix="repoguardian-pr-")
    try:
        root = Path(tmp.name) / repo["repo"]
        with git_auth_env(github_token) as env:
            env["GIT_ASKPASS_RESPONSE"] = github_token
            clone = run_cmd(["git", "clone", repo["https_url"], str(root)], env=env, timeout=180, token=github_token)
            if clone.returncode != 0:
                raise RuntimeError(f"git clone failed: {clone.stderr.strip() or clone.stdout.strip()}")
            if base_branch.strip():
                checkout_base = run_cmd(["git", "checkout", base_branch.strip()], cwd=root, env=env, timeout=60, token=github_token)
                if checkout_base.returncode != 0:
                    raise RuntimeError(f"git checkout base failed: {checkout_base.stderr.strip()}")
            create = run_cmd(["git", "checkout", "-b", branch], cwd=root, env=env, timeout=30, token=github_token)
            if create.returncode != 0:
                raise RuntimeError(f"git checkout branch failed: {create.stderr.strip()}")
            for rel, content in files.items():
                target = root / rel
                if rel == ".gitignore" and target.exists():
                    existing = target.read_text(encoding="utf-8", errors="replace")
                    additions = [line for line in content.splitlines() if line and line not in existing]
                    if additions:
                        target.write_text(existing.rstrip() + "\n\n# RepoGuardian AI secret hygiene\n" + "\n".join(additions) + "\n", encoding="utf-8")
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            run_cmd(["git", "config", "user.name", "RepoGuardian AI"], cwd=root, env=env, timeout=10)
            run_cmd(["git", "config", "user.email", "repoguardian-ai@anna.local"], cwd=root, env=env, timeout=10)
            add = run_cmd(["git", "add", "."], cwd=root, env=env, timeout=30, token=github_token)
            if add.returncode != 0:
                raise RuntimeError(f"git add failed: {add.stderr.strip()}")
            diff = run_cmd(["git", "diff", "--cached", "--quiet"], cwd=root, env=env, timeout=30)
            if diff.returncode == 0:
                raise RuntimeError("No PR file changes were generated")
            commit = run_cmd(
                ["git", "commit", "-m", "Add RepoGuardian AI security report"],
                cwd=root,
                env=env,
                timeout=60,
                token=github_token,
            )
            if commit.returncode != 0:
                raise RuntimeError(f"git commit failed: {commit.stderr.strip()}")
            push = run_cmd(["git", "push", "origin", branch], cwd=root, env=env, timeout=180, token=github_token)
            if push.returncode != 0:
                raise RuntimeError(f"git push failed: {push.stderr.strip() or push.stdout.strip()}")
        pr = github_create_pr(repo, github_token, pr_title, branch, base_branch, pr_body)
        return {
            "dry_run": False,
            "repository": repo["full_name"],
            "branch": branch,
            "title": pr_title,
            "url": pr.get("html_url"),
            "number": pr.get("number"),
            "files": [{"path": path, "bytes": len(content.encode("utf-8"))} for path, content in files.items()],
        }
    finally:
        tmp.cleanup()


def build_pr_body(scan_result: dict[str, Any]) -> str:
    summary_obj = scan_result.get("summary") or {}
    risk = scan_result.get("risk_analysis") or {}
    return textwrap.dedent(
        f"""
        RepoGuardian AI generated this security report from scan `{scan_result.get('scan_id', '')}`.

        - Risk score: {summary_obj.get('risk_score', 0)}/100
        - Grade: {summary_obj.get('grade', 'n/a')}
        - Findings: {summary_obj.get('finding_count', 0)}

        {risk.get('executive_summary', '')}

        Review the generated report, apply the suggested fixes, and run the repository test suite before merging.
        """
    ).strip()


def github_create_pr(
    repo: dict[str, str],
    token: str,
    title: str,
    head_branch: str,
    base_branch: str,
    body: str,
) -> dict[str, Any]:
    payload = {
        "title": title,
        "head": head_branch,
        "base": base_branch or default_branch(repo, token),
        "body": body,
        "maintainer_can_modify": True,
    }
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo['owner']}/{repo['repo']}/pulls",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "RepoGuardianAI/0.1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        data = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub PR API failed ({exc.code}): {sanitize_token_text(data, token)}") from exc


def default_branch(repo: dict[str, str], token: str) -> str:
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo['owner']}/{repo['repo']}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "RepoGuardianAI/0.1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("default_branch") or "main"


def _make_response(req_id, *, result=None, error=None) -> dict[str, Any]:
    out: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    return out


def _tool_success(data: dict[str, Any]) -> dict[str, Any]:
    return {"success": True, "data": data}


def _tool_failure(message: str) -> dict[str, Any]:
    return {"success": False, "error": message}


def _handle_initialize(req_id, params: dict[str, Any]) -> dict[str, Any]:
    proto = (params or {}).get("protocolVersion") or "1.1"
    if proto != PROTOCOL_VERSION_V2:
        sampling.disable(
            f"host did not negotiate v2 (offered protocolVersion={proto!r}); sampling risk synthesis requires Executa protocol 2.0"
        )
    return _make_response(
        req_id,
        result={
            "protocolVersion": proto if proto in ("1.1", "2.0") else "2.0",
            "serverInfo": {"name": MANIFEST["display_name"], "version": MANIFEST["version"]},
            "client_capabilities": {"sampling": {}} if proto == PROTOCOL_VERSION_V2 else {},
            "capabilities": {},
        },
    )


def _handle_invoke(req_id, params: dict[str, Any]) -> dict[str, Any]:
    tool = params.get("tool")
    args = params.get("arguments") or {}
    try:
        if tool == "scan_repository":
            data = scan_repository(**args)
        elif tool == "create_pull_request":
            data = create_pull_request(**args)
        elif tool == "generate_patch":
            data = generate_patch(**args)
        else:
            return _make_response(req_id, result=_tool_failure(f"unknown method: {tool}"))
    except (TypeError, ValueError) as exc:
        return _make_response(req_id, result=_tool_failure(f"Invalid params: {exc}"))
    except SamplingError as exc:
        return _make_response(req_id, result=_tool_failure(f"Sampling failed: {exc.message}"))
    except Exception as exc:  # noqa: BLE001
        return _make_response(req_id, result=_tool_failure(f"Tool execution failed: {exc}"))
    return _make_response(req_id, result=_tool_success(data))


def _handle_message(line: str) -> None:
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        _write_frame(_make_response(None, error={"code": -32700, "message": "Parse error"}))
        return
    if "method" not in msg:
        if not sampling.dispatch_response(msg):
            print(f"unmatched response id={msg.get('id')!r}", file=sys.stderr)
        return
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}
    if method == "initialize":
        resp = _handle_initialize(req_id, params)
    elif method == "describe":
        resp = _make_response(req_id, result=MANIFEST)
    elif method == "health":
        resp = _make_response(req_id, result={"status": "healthy", "timestamp": utc_now(), "version": MANIFEST["version"]})
    elif method == "invoke":
        resp = _handle_invoke(req_id, params)
    elif method == "shutdown":
        resp = _make_response(req_id, result={"ok": True})
    else:
        resp = _make_response(req_id, error={"code": -32601, "message": f"Method not found: {method}"})
    if req_id is not None:
        _write_frame(resp)


def main() -> None:
    print("repoguardian-scanner plugin started", file=sys.stderr)
    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="repoguardian")
    try:
        for raw in sys.stdin:
            line = raw.strip()
            if line:
                pool.submit(_handle_message, line)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        _loop.call_soon_threadsafe(_loop.stop)


if __name__ == "__main__":
    main()
