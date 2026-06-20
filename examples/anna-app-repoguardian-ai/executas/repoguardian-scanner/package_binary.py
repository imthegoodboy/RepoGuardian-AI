#!/usr/bin/env python3
"""Build a platform-specific Anna binary archive for RepoGuardian Scanner."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import queue
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
EXECUTA_JSON = ROOT / "executa.json"
ENTRY_FILE = ROOT / "repoguardian_scanner.py"
OUT_DIR = ROOT / "dist-anna"


def load_metadata() -> dict[str, str]:
    data = json.loads(EXECUTA_JSON.read_text(encoding="utf-8"))
    return {
        "tool_id": os.environ.get("TOOL_ID") or data["tool_id"],
        "version": str(data.get("version") or "0.0.0"),
        "display_name": str(data.get("name") or data["tool_id"]),
        "description": str(data.get("description") or ""),
    }


def platform_key() -> str:
    forced = os.environ.get("PLATFORM")
    if forced:
        return forced

    system = platform.system().lower()
    machine = platform.machine().lower()
    aliases = {
        "amd64": "x86_64",
        "x64": "x86_64",
    }
    machine = aliases.get(machine, machine)
    if system in {"darwin", "windows"} and machine == "aarch64":
        machine = "arm64"
    return f"{system}-{machine}"


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def clean(platform_name: str) -> None:
    shutil.rmtree(ROOT / "build", ignore_errors=True)
    shutil.rmtree(ROOT / "dist", ignore_errors=True)
    shutil.rmtree(OUT_DIR / f"staging-{platform_name}", ignore_errors=True)


def build_binary(tool_id: str) -> Path:
    if not ENTRY_FILE.exists():
        raise SystemExit(f"missing entry file: {ENTRY_FILE}")

    if shutil.which("uv"):
        cmd = [
            "uv",
            "run",
            "--with",
            "pyinstaller",
            "python",
            "-m",
            "PyInstaller",
        ]
    else:
        cmd = [sys.executable, "-m", "PyInstaller"]

    run(
        cmd
        + [
            "--onefile",
            "--clean",
            "--noupx",
            "--name",
            tool_id,
            str(ENTRY_FILE.name),
        ]
    )

    exe = ROOT / "dist" / (tool_id + (".exe" if platform.system().lower() == "windows" else ""))
    if not exe.exists():
        raise SystemExit(f"PyInstaller did not produce {exe}")
    return exe


def write_manifest(stage: Path, metadata: dict[str, str], entrypoint: str) -> None:
    manifest = {
        "name": metadata["tool_id"],
        "display_name": metadata["display_name"],
        "version": metadata["version"],
        "description": metadata["description"],
        "runtime": {
            "binary": {
                "entrypoint": {"default": entrypoint},
                "permissions": {entrypoint: "0o755"},
            }
        },
    }
    (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def stage_binary(binary: Path, platform_name: str, metadata: dict[str, str]) -> tuple[Path, str]:
    stage = OUT_DIR / f"staging-{platform_name}"
    bin_dir = stage / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    suffix = ".exe" if platform_name.startswith("windows-") else ""
    entrypoint = f"bin/{metadata['tool_id']}{suffix}"
    staged_binary = stage / entrypoint
    shutil.copy2(binary, staged_binary)
    staged_binary.chmod(staged_binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    write_manifest(stage, metadata, entrypoint)
    return stage, entrypoint


def make_archive(stage: Path, platform_name: str, tool_id: str) -> tuple[Path, str]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if platform_name.startswith("windows-"):
        archive = OUT_DIR / f"{tool_id}-{platform_name}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    zf.write(path, path.relative_to(stage).as_posix())
        fmt = "zip"
    else:
        archive = OUT_DIR / f"{tool_id}-{platform_name}.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            for path in sorted(stage.rglob("*")):
                tf.add(path, arcname=path.relative_to(stage).as_posix())
        fmt = "tar.gz"
    return archive, fmt


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def smoke_test(executable: Path) -> None:
    proc = subprocess.Popen(
        [str(executable)],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    assert proc.stdin is not None and proc.stdout is not None
    lines: queue.Queue[str] = queue.Queue()

    def read_stdout() -> None:
        lines.put(proc.stdout.readline())

    reader = threading.Thread(target=read_stdout, daemon=True)
    reader.start()
    proc.stdin.write('{"jsonrpc":"2.0","method":"describe","id":1}\n')
    proc.stdin.flush()
    reader.join(timeout=20)
    if lines.empty():
        proc.kill()
        _, stderr = proc.communicate(timeout=5)
        raise SystemExit(f"smoke test timed out waiting for describe response\n{stderr}")

    raw = lines.get().strip()
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    response = json.loads(raw)
    result = response.get("result") or {}
    if response.get("error") or not result.get("tools"):
        raise SystemExit(f"smoke test failed: {raw}")
    print("Smoke test passed:", result.get("name") or result.get("display_name"))


def main() -> None:
    do_smoke = "--smoke" in sys.argv
    metadata = load_metadata()
    platform_name = platform_key()

    print(f"Tool ID:  {metadata['tool_id']}")
    print(f"Version:  {metadata['version']}")
    print(f"Platform: {platform_name}")

    clean(platform_name)
    binary = build_binary(metadata["tool_id"])
    stage, entrypoint = stage_binary(binary, platform_name, metadata)
    if do_smoke:
        smoke_test(stage / entrypoint)

    archive, fmt = make_archive(stage, platform_name, metadata["tool_id"])
    digest = sha256(archive)
    size = archive.stat().st_size
    sha_path = archive.with_name(archive.name + ".sha256")
    sha_path.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")

    print()
    print(f"Built archive: {archive}")
    print(f"SHA-256: {digest}")
    print(f"Size: {size} bytes")
    print()
    print(
        json.dumps(
            {
                platform_name: {
                    "url": f"https://github.com/imthegoodboy/RepoGuardian-AI/releases/download/repoguardian-scanner-v{metadata['version']}/{archive.name}",
                    "sha256": digest,
                    "size": size,
                    "entrypoint": entrypoint,
                    "format": fmt,
                }
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
