#!/usr/bin/env python3
"""file_upload_via_executa_plugin.py — Executa that demonstrates the
**host/uploadFile** reverse-RPC (inline / negotiate / confirm) end to end.

See https://anna.partners/developers/reference/executa-host-upload

Why this demo sources bytes *locally* instead of from the iframe
---------------------------------------------------------------------
``host/uploadFile`` persists a binary blob that the **Executa already
holds** — an image it generated, a screenshot, an intermediate PDF — to
short-lived host storage (~30 min TTL) without the plugin holding any R2
credentials. The bytes flow **plugin → R2 directly** (negotiate mode), so
they never traverse the JSON-RPC stdio channel.

An earlier version of this demo base64-encoded the file in the browser and
shipped it through ``anna.tools.invoke`` into the Executa. That makes the
bytes cross stdio **twice** (in via the invoke request, and — for inline
mode — back out via the reverse-RPC request), which caps the practical
file size at the stdio line limit and defeats the whole point of
``negotiate``. A browser-picked ``File`` can only reach a subprocess over
that stdio channel, so to demonstrate large-file ``host/uploadFile`` the
bytes must originate **inside the Executa**.

This Executa therefore exposes two tools:

- ``make_sample``      — write a scratch file of N bytes to the local
                         filesystem and return its absolute path. Lets the
                         UI conjure preset-size payloads that cross the
                         8 MiB inline cap and the per-file upload quota,
                         without committing large binaries to the repo.
- ``host_upload_path`` — read a **local file path** and persist it via
                         ``host/uploadFile``: ``inline`` (base64 round-trip)
                         for ≤ 8 MiB, otherwise ``negotiate`` (presigned R2
                         PUT, bytes stream straight to R2) + ``confirm``.
                         Returns a short-lived download URL.

Run it::

    anna-app dev               # signed-in account; mints app_session_token

``host/uploadFile`` needs a real account (so the host can mint an
``upload_token``) but — unlike the APS ``files/*`` flow — does **not**
require ``--storage aps``. The host enforces the user's ``upload_grant``:
by default 16 files / 20 MiB per file / 80 MiB total per invoke. A payload
above the per-file cap is rejected with ``UPLOAD_TOO_LARGE`` (-32204)
*before* any R2 round-trip — the demo surfaces that verbatim.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

# Fallback for fresh checkouts: locate the in-repo SDK when not pip-installed.
try:
    import executa_sdk  # noqa: F401
except ModuleNotFoundError:
    _SDK_PATH = Path(__file__).resolve().parents[4] / "sdk" / "python"
    if _SDK_PATH.is_dir():
        sys.path.insert(0, str(_SDK_PATH))

from executa_sdk import (  # noqa: E402
    PROTOCOL_VERSION_V2,
    HostUploadClient,
    UploadError,
    make_response_router,
)

# host/uploadFile inline-mode payload cap (mirrors SDK MAX_INLINE_BYTES).
# Files at or below this go through `inline`; larger ones use `negotiate`.
_INLINE_CAP_BYTES = 8 * 1024 * 1024

# Scratch dir for `make_sample`-generated payloads. Reused across calls;
# a deterministic per-size filename means repeated clicks overwrite rather
# than accumulate.
_SAMPLE_DIR = Path(tempfile.gettempdir()) / "anna-host-upload-demo"

# ─── Manifest ─────────────────────────────────────────────────────────

MANIFEST = {
    "display_name": "Host Upload via Executa",
    "version": "0.2.0",
    "description": (
        "Demonstrates the host/uploadFile reverse-RPC (inline / negotiate / "
        "confirm) by reading a local file and persisting it to short-lived "
        "host storage. Bytes go plugin → R2 directly, never through stdio."
    ),
    "author": "Anna Developer",
    # `host.upload` — required for the transient host/uploadFile flow. Without
    #                it the host refuses with UPLOAD_NOT_GRANTED (-32201); the
    #                user must also have `upload_grant` enabled on their
    #                UserExecuta.custom_config.
    "host_capabilities": ["host.upload"],
    "tools": [
        {
            "name": "make_sample",
            "description": (
                "Write a scratch file of `size_bytes` bytes to the local "
                "filesystem and return its absolute path. Use it to produce "
                "preset-size payloads for host_upload_path without shipping "
                "large binaries."
            ),
            # Executa protocol uses `parameters: [{name, type, required, ...}]`
            # (see docs/protocol-spec.md), NOT MCP-style `input_schema`. The
            # host's ToolDefinition.from_dict only reads `parameters`.
            "parameters": [
                {
                    "name": "size_bytes",
                    "type": "integer",
                    "description": "Number of bytes to write, e.g. 12582912 for 12 MiB.",
                    "required": True,
                },
                {
                    "name": "filename",
                    "type": "string",
                    "description": "Optional logical name; defaults to sample-<size>.bin.",
                    "required": False,
                    "default": "",
                },
            ],
        },
        {
            "name": "host_upload_path",
            "description": (
                "Read a LOCAL file path and persist it TRANSIENTLY via "
                "host/uploadFile (~30 min TTL). Picks inline (≤8 MiB) or "
                "negotiate+confirm automatically and returns a short-lived "
                "download URL. Use for invoke-scoped artefacts, not durable "
                "storage."
            ),
            "parameters": [
                {
                    "name": "path",
                    "type": "string",
                    "description": "Absolute path to a local file the Executa can read.",
                    "required": True,
                },
                {
                    "name": "filename",
                    "type": "string",
                    "description": "Logical filename for the object; defaults to the path's basename.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "mime_type",
                    "type": "string",
                    "description": "MIME type, e.g. 'image/png'. Defaults to application/octet-stream.",
                    "required": False,
                    "default": "application/octet-stream",
                },
                {
                    "name": "purpose",
                    "type": "string",
                    "description": "Upload purpose allowlist value.",
                    "required": False,
                    "default": "user_artifact",
                    "enum": ["image_input", "image_reference", "user_artifact"],
                },
            ],
        },
    ],
    "runtime": {"type": "uv", "min_version": "0.1.0"},
}

# ─── Reverse-RPC client ───────────────────────────────────────────────

_stdout_lock = threading.Lock()


def _write_frame(msg: dict) -> None:
    payload = json.dumps(msg, ensure_ascii=False)
    with _stdout_lock:
        sys.stdout.write(payload + "\n")
        sys.stdout.flush()


_host_upload = HostUploadClient(write_frame=_write_frame)
_route_response = make_response_router(_host_upload)


# ─── Tool implementations ─────────────────────────────────────────────


async def _make_sample(size_bytes: int, filename: str) -> dict:
    try:
        size = int(size_bytes)
    except (TypeError, ValueError) as e:
        raise ValueError(f"size_bytes must be an integer: {e}") from e
    if size < 0:
        raise ValueError("size_bytes must be >= 0")

    _SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    # Never let a caller-supplied name escape the scratch dir.
    safe = os.path.basename((filename or "").strip()) or f"sample-{size}.bin"
    path = _SAMPLE_DIR / safe

    # Stream zero-bytes in 1 MiB chunks so a large sample never balloons
    # memory. Content is irrelevant for the upload demo.
    chunk = b"\0" * (1024 * 1024)
    written = 0
    with open(path, "wb") as f:
        while written < size:
            n = min(len(chunk), size - written)
            f.write(chunk[:n])
            written += n

    return {"ok": True, "path": str(path), "filename": safe, "size_bytes": size}


async def _host_upload_path(
    path: str, filename: str, mime_type: str, purpose: str
) -> dict:
    """Persist a local file via host/uploadFile.

    Picks the cheapest mode automatically: ``inline`` (one round-trip) for
    payloads up to 8 MiB, otherwise ``negotiate`` (presigned PUT, bytes
    stream straight to R2) + ``confirm``. Both return a short-lived
    download URL — store the ``r2_key``, not the URL, since URLs TTL out
    (~30 min).
    """
    p = Path(path).expanduser()
    if not p.is_file():
        raise ValueError(f"local file not found: {path}")

    size = p.stat().st_size
    name = (filename or "").strip() or p.name
    mime = mime_type or "application/octet-stream"
    purpose = purpose or "user_artifact"

    if size <= _INLINE_CAP_BYTES:
        # Mode 1 — inline: base64 round-trip, simplest path. Bytes ride the
        # reverse-RPC request, so this is only sane for small payloads.
        res = await _host_upload.upload_inline(
            filename=name,
            mime_type=mime,
            content=p.read_bytes(),
            purpose=purpose,
        )
        mode = "inline"
    else:
        # Mode 2 — negotiate + PUT + confirm: the host signs an R2 PUT URL,
        # the plugin streams the file straight to R2 (NOT through stdio),
        # then confirm registers the object. This is the large-file path.
        info = await _host_upload.negotiate(
            filename=name,
            mime_type=mime,
            size_bytes=size,
            purpose=purpose,
        )
        headers = dict(info.get("headers") or {})
        # urllib only sets Content-Length automatically for bytes bodies;
        # for a streamed file object we must set it ourselves.
        headers["Content-Length"] = str(size)
        with open(p, "rb") as f:
            req = urllib.request.Request(
                info["put_url"], data=f, method="PUT", headers=headers
            )
            with urllib.request.urlopen(req, timeout=300) as resp:  # noqa: S310 - presigned URL
                put_status = resp.status
        if put_status not in (200, 201):
            raise RuntimeError(f"host upload PUT failed: HTTP {put_status}")
        res = await _host_upload.confirm(r2_key=info["r2_key"])
        mode = "negotiate+confirm"

    return {
        "ok": True,
        "mode": mode,
        "filename": name,
        "size_bytes": res.get("size_bytes", size),
        "mime_type": mime,
        "download_url": res.get("download_url"),
        "r2_key": res.get("r2_key"),
        "expires_at": res.get("expires_at"),
    }


# ─── JSON-RPC dispatch ────────────────────────────────────────────────


def _ok(req_id: Any, result: dict) -> None:
    _write_frame({"jsonrpc": "2.0", "id": req_id, "result": result})


def _err(req_id: Any, code: int, message: str, data: dict | None = None) -> None:
    err: dict = {"code": code, "message": message}
    if data:
        err["data"] = data
    _write_frame({"jsonrpc": "2.0", "id": req_id, "error": err})


_loop = asyncio.new_event_loop()
_loop_thread = threading.Thread(target=_loop.run_forever, daemon=True)
_loop_thread.start()


def _handle_invoke(req_id: Any, params: dict) -> None:
    tool = params.get("tool")
    args = params.get("arguments") or {}
    if tool == "make_sample":
        coro = _make_sample(args.get("size_bytes", 0), str(args.get("filename", "")))
    elif tool == "host_upload_path":
        coro = _host_upload_path(
            str(args.get("path", "")),
            str(args.get("filename", "")),
            str(args.get("mime_type", "application/octet-stream")),
            str(args.get("purpose", "user_artifact")),
        )
    else:
        _err(req_id, -32601, f"Unknown tool: {tool}")
        return

    fut = asyncio.run_coroutine_threadsafe(coro, _loop)
    try:
        data = fut.result(timeout=300.0)
    except UploadError as e:
        # host/uploadFile surfaces UPLOAD_* codes (e.g. UPLOAD_TOO_LARGE
        # -32204 when size_bytes exceeds the per-file grant). Pass the
        # reason through verbatim so the LLM/UI sees it.
        _err(req_id, e.code, e.message, e.data)
        return
    except ValueError as e:
        _err(req_id, -32602, str(e))
        return
    except Exception as e:  # noqa: BLE001
        _err(req_id, -32603, f"Tool execution failed: {e}")
        return
    # InvokeResult.from_dict on the host expects {success, data}; never
    # return the bare tool dict (it would be read as success=False).
    _ok(req_id, {"success": True, "tool": tool, "data": data})


def _handle_initialize(req_id: Any, params: dict) -> None:
    proto = (params or {}).get("protocolVersion") or PROTOCOL_VERSION_V2
    is_v2 = proto == PROTOCOL_VERSION_V2
    if not is_v2:
        # host/uploadFile is v2-only; disable so calls fail fast with a clear
        # reason instead of hanging on a never-answered reverse-RPC.
        _host_upload.disable(
            f"host did not negotiate v2 (offered protocolVersion={proto!r}); "
            "host/uploadFile requires Executa protocol 2.0"
        )
    _ok(
        req_id,
        {
            "protocolVersion": proto if proto in ("1.1", "2.0") else "2.0",
            "serverInfo": {"name": MANIFEST["display_name"], "version": MANIFEST["version"]},
            # Advertise the transient host/uploadFile capability. The host
            # gates uploads on this negotiation + the manifest's `host.upload`.
            "client_capabilities": {"upload": {}} if is_v2 else {},
        },
    )


def _handle_message(line: str) -> None:
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        return
    # Reverse-RPC replies from the host resolve our pending upload futures.
    if "method" not in msg:
        if not _route_response(msg):
            print(f"⚠️  unmatched response id={msg.get('id')!r}", file=sys.stderr)
        return

    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    if method == "initialize":
        _handle_initialize(req_id, params)
    elif method == "describe":
        # `result` MUST be the bare manifest — matrix's ToolManifest.from_dict
        # reads result["name"] directly.
        _ok(req_id, MANIFEST)
    elif method == "health":
        _ok(req_id, {"status": "healthy", "version": MANIFEST["version"]})
    elif method == "invoke":
        _handle_invoke(req_id, params)
    elif method == "shutdown":
        _ok(req_id, {"ok": True})
    elif req_id is not None:
        _err(req_id, -32601, f"Method not found: {method}")


def main() -> None:
    print("🔌 host-upload-via-executa plugin started", file=sys.stderr)
    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="invoke")
    try:
        for raw in sys.stdin:
            line = raw.strip()
            if not line:
                continue
            pool.submit(_handle_message, line)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        _loop.call_soon_threadsafe(_loop.stop)


if __name__ == "__main__":
    main()
