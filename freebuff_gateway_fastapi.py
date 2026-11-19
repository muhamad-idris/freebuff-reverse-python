#!/usr/bin/env python3
"""
freebuff_gateway_fastapi.py
===========================

FastAPI gateway yang memakai `freebuff_requests.py` sebagai library dasar,
supaya endpoint Freebuff bisa diakses agen/klien lain lewat HTTP (API mirip
OpenAI: GET /v1/models, POST /v1/chat/completions termasuk streaming SSE).

Satu sesi free mode dipakai ulang untuk semua request (state dipersist):
  1. GET  /api/v1/freebuff/models          (cache, refresh bila basi/409)
  2. GET  /api/v1/freebuff/session          heartbeat (perpanjang sesi)
  3. POST /api/v1/freebuff/session/admission (takeover bila slot dipakai)
  4. POST /api/agents/validate              (definisi base3-free-catalog -> handle)
  5. GET  /api/v1/freebuff/session          heartbeat lagi
  6. POST /api/v1/agent-runs START          -> runId (sekali per sesi)
  7. POST /api/v1/chat/completions          (stream / non-stream)
  8. GET  /api/v1/project-profile
  9. POST /api/v1/agent-runs FINISH         (hanya saat reset/shutdown opsional)

Identitas sesi (trace_session_id, client_id, run_id) stabil; llm_step_number
naik tiap request. `--session-id <id>` memilih slot sesi tertentu.

Akses (kredensial): diambil dari ~/.config/manicode/credentials.json + keychain
(lihat Credentials.load). Jika env FREEBUFF_GATEWAY_TOKEN diisi, semua endpoint
wajib membawa `Authorization: Bearer <FREEBUFF_GATEWAY_TOKEN>`.

Jalankan:
    FREEBUFF_GATEWAY_TOKEN=rahasia uvicorn freebuff_gateway_fastapi:app \
        --host 127.0.0.1 --port 8000
    # atau: python3 freebuff_gateway_fastapi.py
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Mapping, Sequence

import httpx
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

import freebuff_requests as f

# ---------------------------------------------------------------------------
# Konfigurasi
# ---------------------------------------------------------------------------
CATALOG_TTL_S = float(os.environ.get("FREEBUFF_CATALOG_TTL", "300"))
GATEWAY_TOKEN = os.environ.get("FREEBUFF_GATEWAY_TOKEN") or ""
UPSTREAM_TIMEOUT = float(os.environ.get("FREEBUFF_TIMEOUT", "180"))
DEFAULT_MODEL = "recommended"   # key katalog / "recommended" / handle fbm1.*
# Sesi (instanceId + admission) disimpan ke disk supaya restart tidak membuka
# sesi baru dan jatah sesi free mode tidak habis.
SESSION_ID = os.environ.get("FREEBUFF_SESSION_ID") or ""


def state_path_for(session_id: str | None = None) -> Path:
    """Lokasi state sesi: env FREEBUFF_SESSION_STATE > per-id > default."""
    override = os.environ.get("FREEBUFF_SESSION_STATE")
    if override:
        return Path(override)
    base = Path.home() / ".config" / "manicode"
    if session_id:
        safe = re.sub(r"[^A-Za-z0-9._-]", "-", session_id)[:64]
        return base / "gateway-sessions" / f"{safe}.json"
    return base / "gateway-session.json"


STATE_PATH = state_path_for(SESSION_ID)
HB_MIN_INTERVAL_S = float(os.environ.get("FREEBUFF_HB_INTERVAL", "45"))
ADMISSION_MARGIN_MS = 120_000  # perpanjang sesi bila sisa < 2 menit
FINISH_ON_SHUTDOWN = os.environ.get("FREEBUFF_FINISH_ON_SHUTDOWN", "0") == "1"


def load_state() -> dict[str, Any]:
    try:
        with STATE_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_state(data: dict[str, Any]) -> None:
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE_PATH.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, separators=(",", ":"))
        os.chmod(tmp, 0o600)
        tmp.replace(STATE_PATH)
    except Exception:
        pass


class GatewayError(Exception):
    """Error yang bisa dipetakan ke HTTP status tertentu."""

    def __init__(self, status: int, error_code: str, message: str):
        self.status = status
        self.error_code = error_code
        self.message = message
        super().__init__(message)


# ---------------------------------------------------------------------------
# Sesi Freebuff (cache catalog + admission + run lifecycle)
# ---------------------------------------------------------------------------

class FreebuffSession:
    """Memegang state sesi (catalog, instance, admission) dan menjalankan run."""

    def __init__(self, session_id: str | None = None) -> None:
        self.session_id = session_id if session_id is not None else SESSION_ID
        self.creds = f.Credentials.load()
        self.store = f.DeviceKeyStore()
        self.lock = asyncio.Lock()
        self.client = httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT)
        self.slot = asyncio.Semaphore(1)
        # tool_call_id -> nama tool CLI (untuk menerjemahkan pesan role:"tool")
        self.tool_names: dict[str, str] = {}
        self.catalog: dict[str, Any] | None = None
        self.catalog_at = 0.0
        self.ref: f.CatalogRef | None = None
        state = load_state()
        self.instance: str | None = state.get("instanceId") or None
        admission = state.get("admission")
        self.admission: dict[str, Any] | None = admission if isinstance(admission, dict) else None
        self._validate_at = 0.0
        self._hb_at = 0.0
        # identitas yang stabil selama satu sesi (capture: sama untuk semua step)
        sess = state.get("session") if isinstance(state.get("session"), dict) else {}
        self.trace_session_id: str = sess.get("traceSessionId") or ""
        self.client_id: str = sess.get("clientId") or ""
        self.run_id: str = sess.get("runId") or ""
        self.step_number: int = int(sess.get("stepNumber") or 0)
        self.steps: list[dict[str, Any]] = list(sess.get("steps") or [])
        self.repo_snapshot_json: str = sess.get("repoSnapshot") or ""

    # -- send helper (mengirim PreparedRequest via httpx, mengikuti tanda tangan) --
    async def _send(
        self,
        prepared: f.PreparedRequest,
        *,
        stream: bool = False,
    ):
        if stream:
            return await self.client.stream("POST", prepared.url, headers=prepared.headers, content=prepared.body)
        resp = await self.client.request(prepared.method, prepared.url, headers=prepared.headers, content=prepared.body)
        try:
            payload = resp.json() if resp.content else None
        except Exception:
            payload = resp.text
        return resp, payload

    # 1. katalog
    async def ensure_catalog(self, force: bool = False) -> dict[str, Any]:
        if self.catalog and not force and (time.time() - self.catalog_at) < CATALOG_TTL_S:
            return self.catalog
        prepared = f.build_catalog_request(self.creds.token, self.store)
        resp, payload = await self._send(prepared)
        if resp.status_code >= 400 or not isinstance(payload, dict) or not payload.get("rows"):
            raise GatewayError(502, "catalog_fetch_failed", f"HTTP {resp.status_code}: {str(payload)[:200]}")
        self.catalog = payload
        self.catalog_at = time.time()
        self.ref = f.CatalogRef.from_catalog(payload)
        self._validate_at = 0.0  # katalog baru -> perlu validate ulang
        return payload

    def resolve_model(self, model: str | None) -> str:
        """Ubah model klien (key m-…, 'recommended', atau handle) -> handle fbm1.*."""
        catalog = self.catalog or {}
        key = model or DEFAULT_MODEL
        if key == "recommended":
            key = catalog.get("recommendedKey") or "m-61c26317cc"
        if key.startswith(f.CATALOG_PREFIX):
            return key
        handle = f.catalog_handle(catalog, key)
        if handle:
            return handle
        # coba cocokkan lewat displayName / key
        for row in catalog.get("rows", []):
            if row.get("key") == key or row.get("displayName") == key:
                return row.get("handle", key)
        if not key.startswith("m-"):
            raise GatewayError(400, "unknown_model", f"model tidak dikenal: {key}")
        return key

    # 3. sesi (reuse admission, heartbeat murah, admission hanya bila perlu)
    def _admission_fresh(self) -> bool:
        if not self.admission:
            return False
        expires_at = self.admission.get("expiresAt")
        if not expires_at:
            return True
        return f.parse_iso_ms(expires_at) > f.now_ms() + ADMISSION_MARGIN_MS

    def _persist(self) -> None:
        save_state({
            "session": {
                "traceSessionId": self.trace_session_id,
                "clientId": self.client_id,
                "runId": self.run_id,
                "stepNumber": self.step_number,
                "steps": self.steps[-40:],
                "repoSnapshot": self.repo_snapshot_json,
            },
            "instanceId": self.instance,
            "savedAt": f.now_ms(),
            "admission": {
                key: (self.admission or {}).get(key)
                for key in ("status", "instanceId", "model", "accessTier", "admittedAt", "expiresAt")
            } if self.admission else None,
        })

    def ensure_identity(self) -> None:
        """Buat identitas sesi bila belum ada (dipakai seluruh request di sesi ini).

        Bila `--session-id` diberikan, trace_session_id & client_id dihitung
        deterministik dari id tersebut: menjalankan ulang dengan id yang sama
        menghasilkan identitas (dan state sesi) yang sama pula.
        """
        changed = False
        if self.session_id:
            ns = uuid.uuid5(uuid.NAMESPACE_URL, "freebuff-gateway/session")
            if not self.trace_session_id:
                self.trace_session_id = str(uuid.uuid5(ns, self.session_id))
                changed = True
            if not self.client_id:
                digest = hashlib.sha256(f"client:{self.session_id}".encode()).hexdigest()
                alphabet = "bcdfghjklmnpqrstvwxyz0123456789"
                self.client_id = "".join(alphabet[int(c, 16) % len(alphabet)] for c in digest[:12])[:11]
                changed = True
        else:
            if not self.trace_session_id:
                self.trace_session_id = str(uuid.uuid4())
                changed = True
            if not self.client_id:
                self.client_id = "".join(ch for ch in f.nanoid(12) if ch.isalnum())[:11].lower().ljust(11, "0")
                changed = True
        if not self.repo_snapshot_json:
            self.repo_snapshot_json = json.dumps(f.repo_snapshot(), separators=(",", ":"))
            changed = True
        if changed:
            self._persist()

    def rotate_run(self) -> None:
        """Sesi baru -> run baru (trace/client tetap, karena percakapan berlanjut)."""
        self.run_id = ""
        self.step_number = 0
        self.steps = []
        self._persist()

    def _session_params(self, takeover: str | None = None) -> "f.SessionParams":
        return f.SessionParams(
            token=self.creds.token,
            instance_id=self.instance or f.new_instance_id(),
            model=self._base_model_key(),
            catalog=self.ref,
            catalog_data=self.catalog,
            user_id=self.creds.user_id,
            takeover_instance_id=takeover,
        )

    async def _heartbeat(self) -> dict[str, Any]:
        """GET /session: perpanjang sesi tanpa admission baru (murah)."""
        resp, payload = await self._send(f.build_session_request("GET", self._session_params(), self.store))
        self._hb_at = time.time()
        return payload if isinstance(payload, dict) else {}

    async def ensure_session(self, force: bool = False) -> dict[str, Any]:
        async with self.lock:
            await self.ensure_catalog()

            if not force and self._admission_fresh():
                # Sesi masih hidup: cukup heartbeat sesekali, tanpa admission baru.
                if (time.time() - self._hb_at) > HB_MIN_INTERVAL_S:
                    state = await self._heartbeat()
                    status = state.get("status")
                    own = state.get("instanceId")
                    if status == "active" and (own is None or own == self.admission.get("instanceId")):
                        # simpan payload heartbeat terbaru (freebucks, expiresAt, dll)
                        self.admission = {**state, "instanceId": own or self.admission.get("instanceId")}
                        self._persist()
                    elif status in ("none", "ended", "superseded", "expired"):
                        self.admission = None
                    else:
                        self.admission = None
                if self.admission:
                    print(f"[session] reuse {self.admission.get('instanceId')}", flush=True)
                    await self._validate_agents()
                    return self.admission

            if not self.instance:
                self.instance = f.new_instance_id()

            previous_run = self.run_id
            resp, payload = await self._send(f.build_session_request("POST", self._session_params(), self.store))
            state = payload if isinstance(payload, dict) else {}
            if state.get("status") != "active" and state.get("currentInstanceId"):
                # slot dipakai instance lain -> takeover
                resp, payload = await self._send(
                    f.build_session_request("POST", self._session_params(state["currentInstanceId"]), self.store)
                )
                state = payload if isinstance(payload, dict) else {}
            if state.get("status") != "active":
                self.admission = None
                status = str(state.get("status") or "unknown")
                retry_at = (
                    state.get("nextExpiryAt")
                    or (state.get("desktopSessionCounts") or {}).get("nextExpiryAt")
                    or ""
                )
                if status in ("purchase_claim_released", "ip_capped", "rate_limited"):
                    raise GatewayError(
                        429,
                        status,
                        "jatah sesi free mode sedang habis/dipakai"
                        + (f"; coba lagi setelah {retry_at}" if retry_at else "")
                        + f" (status: {status})",
                    )
                raise GatewayError(409, "admission_failed", _explain(resp.status_code, json.dumps(state)[:400]))
            self.admission = state
            self.instance = state.get("instanceId") or self.instance
            self._hb_at = time.time()
            print(f"[session] admit baru {self.instance}", flush=True)
            if previous_run:
                # run sesi lama dibiarkan (server yang menutup); FINISH di sini
                # berisiko melepas klaim sesi yang baru didapat.
                print(f"[session] run lama {previous_run[:8]} dilepas, mulai run baru", flush=True)
                self.rotate_run()
            self._persist()
            await self._validate_agents()
            return state

    async def recover_session(self) -> None:
        """Untuk 428/409/410: heartbeat dulu, admission baru hanya bila perlu."""
        alive = False
        async with self.lock:
            if self.admission:
                state = await self._heartbeat()
                status = state.get("status")
                own = state.get("instanceId")
                if status == "active" and (own is None or own == self.admission.get("instanceId")):
                    self.admission = {**state, "instanceId": own or self.admission.get("instanceId")}
                    self._persist()
                    alive = True
                else:
                    self.admission = None
        self._validate_at = 0.0
        if not alive:
            await self.ensure_session(force=True)
            return
        await self._validate_agents(force=True)

    async def reset_session(self) -> None:
        """Paksa sesi baru: tutup run lama, lalu buang admission + identitas."""
        try:
            await self.finish_run(status="completed")
        except Exception:
            pass
        self.run_id = ""
        self.step_number = 0
        self.steps = []
        self.trace_session_id = ""
        self.client_id = ""
        self.repo_snapshot_json = ""
        async with self.lock:
            self.admission = None
            self.instance = f.new_instance_id()
            self._hb_at = 0.0
            self._validate_at = 0.0
            self._persist()

    def _base_model_key(self) -> str:
        return (self.catalog or {}).get("recommendedKey") or "m-61c26317cc"

    # 4. validate agent
    async def _validate_agents(self, force: bool = False) -> None:
        if self._validate_at and not force and (time.time() - self._validate_at) < CATALOG_TTL_S:
            return
        prepared = f.build_free_agent_validate_request(self.creds.token, self.catalog, model_key=self._base_model_key())
        resp, payload = await self._send(prepared)
        if resp.status_code >= 400:
            raise GatewayError(502, "agents_validate_failed", f"HTTP {resp.status_code}: {str(payload)[:200]}")
        self._validate_at = time.time()

    # 6. run START
    async def start_run(self, *, ensure_session: bool = True) -> str:
        """POST /api/v1/agent-runs START -> runId (pastikan sesi dulu bila diminta)."""
        if ensure_session:
            await self.ensure_session()
        self.ensure_identity()
        if self.run_id:
            return self.run_id  # satu run untuk seluruh percakapan (seperti CLI)
        prepared = f.build_agent_run_start(self.creds.token, agent_id=f.FREE_AGENT_ID, user_id=self.creds.user_id)
        resp, payload = await self._send(prepared)
        run_id = payload.get("runId") if isinstance(payload, dict) else None
        if not run_id:
            raise GatewayError(502, "run_start_failed", f"HTTP {resp.status_code}: {str(payload)[:200]}")
        self.run_id = run_id
        self._persist()
        return run_id

    # 9. step & FINISH
    def record_step(self, status: str = "completed", run_id: str | None = None) -> None:
        """Catat satu langkah LLM (dikirim lewat FINISH di akhir sesi)."""
        self.steps.append(f.build_agent_step(
            step_number=self.step_number,
            credits=0,
            child_run_ids=(),
            message_id=str(uuid.uuid4()),
            status=status,
            start_time=datetime.now(timezone.utc).isoformat(),
        ))
        self.steps = self.steps[-40:]
        self._persist()

    async def finish_run(
        self,
        run_id: str | None = None,
        status: str = "completed",
        total_steps: int | None = None,
    ) -> None:
        """POST agent-runs FINISH untuk run sesi (dipanggil saat sesi berakhir)."""
        target = run_id or self.run_id
        if not target:
            return
        prepared = f.build_agent_run_finish(
            self.creds.token,
            run_id=target,
            status=status,
            total_steps=total_steps if total_steps is not None else max(len(self.steps), 1),
            steps=self.steps,
            user_id=self.creds.user_id,
        )
        await self._send(prepared)

    # 7. chat (streaming / non-streaming)
    def _build_chat(
        self,
        *,
        run_id: str,
        model_handle: str,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]] | None,
        tool_choice: Any,
        stream: bool,
        prompt: str,
    ):
        self.ensure_identity()
        extras = {
            **f.instance_metadata(self.instance or ""),
            **f.input_profile_metadata(f.InputProfile.from_prompt(prompt)),
            "trace_session_id": self.trace_session_id,
            "repo_snapshot": self.repo_snapshot_json,
            "compaction_version": "summary-v1",
            "compaction_root_model": model_handle,
            "compaction_root_version": "summary-v1",
            "compaction_root_run_id": run_id,
            "compaction_request_id": str(uuid.uuid4()),
            "compaction_request_group": "other",
            "llm_step_number": str(max(self.step_number, 1)),
        }
        return f.build_chat_request(
            token=self.creds.token,
            store=self.store,
            model=model_handle,
            messages=messages,
            tools=tools,
            tool_choice=tool_choice,
            run_id=run_id,
            client_id=self.client_id,
            user_id=self.creds.user_id,
            catalog=self.ref,
            codebuff_metadata_extra=extras,
            stream=stream,
        )

    async def chat(
        self,
        *,
        messages: Sequence[Mapping[str, Any]],
        model: str | None = None,
        stream: bool = False,
        cli2c: Mapping[str, tuple[str, Mapping[str, Any]]] | None = None,
    ):
        """Jalankan satu giliran: slot -> run START -> chat.

        `messages` sudah dalam format codebuff. Slot (semaphore) dipegang sampai
        stream selesai supaya tidak ada dua chat bersamaan (satu slot free mode).
        """
        turn = _Turn(self, messages, model or DEFAULT_MODEL, cli2c or {})
        await self.slot.acquire()
        handed_off = False
        try:
            await turn.prepare()
            if stream:
                handed_off = True
                return _ChatStream(turn)
            return await _non_stream(turn)
        finally:
            if not handed_off:
                self.slot.release()

    async def aclose(self) -> None:
        # FINISH di akhir bisa membuat server melepas klaim sesi (slot jadi
        # terkunci sampai jendela berikutnya), jadi default-nya tidak dikirim.
        if FINISH_ON_SHUTDOWN:
            try:
                await self.finish_run(status="completed")
            except Exception:
                pass
        await self.client.aclose()


# ---------------------------------------------------------------------------
# Terjemahan tool: klien <-> CLI
# ---------------------------------------------------------------------------
# Upstream menolak (403 third_party_client_warning) bila daftar `tools` bukan
# milik CLI resmi. Jadi ke upstream SELALU kirim `f.default_tools()`, lalu
# nama/argumen tool diterjemahkan dua arah.

TOOL_ALIASES: dict[str, tuple[str, ...]] = {
    "read_files": ("read", "read_file", "view_file", "view"),
    "write_file": ("write", "write_file", "create_file", "write_to_file"),
    "str_replace": ("edit", "str_replace", "apply_patch", "replace_in_file", "edit_file"),
    "run_terminal_command": ("bash", "shell", "run_command", "execute", "terminal"),
    "code_search": ("grep", "code_search", "search_code", "ripgrep"),
    "glob": ("glob", "find_files", "file_search", "glob_files"),
    "list_directory": ("ls", "list_dir", "list_files", "list_directory"),
    "write_todos": ("todowrite", "todo_write", "write_todos", "update_todos"),
    "web_search": ("web_search", "websearch", "search_web"),
    "read_url": ("webfetch", "fetch_url", "read_url"),
    "ask_user": ("question", "ask_user", "ask_followup_question"),
}


def tool_maps(client_tools: Sequence[Mapping[str, Any]]):
    """(client_name -> cli_name, cli_name -> (client_name, schema_props))."""
    c2c: dict[str, str] = {}
    cli2c: dict[str, tuple[str, dict[str, Any]]] = {}
    for tool in client_tools or []:
        fn = tool.get("function") if isinstance(tool, Mapping) else None
        fn = fn or (tool if isinstance(tool, Mapping) else {})
        name = fn.get("name") or (tool.get("name") if isinstance(tool, Mapping) else None)
        if not name:
            continue
        props = ((fn.get("parameters") or {}).get("properties") or {})
        for cli_name, aliases in TOOL_ALIASES.items():
            if name == cli_name or name in aliases:
                c2c[name] = cli_name
                cli2c.setdefault(cli_name, (name, props))
                break
        else:
            c2c[name] = name
            cli2c.setdefault(name, (name, props))
    return c2c, cli2c


def _json_args(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            parsed = json.loads(value) if value.strip() else {}
        except Exception:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return dict(value) if isinstance(value, Mapping) else {}


def _pick_key(props: Mapping[str, Any], *names: str) -> str | None:
    for name in names:
        if name in props:
            return name
    return None


def args_to_client(cli_name: str, client_name: str, props: Mapping[str, Any] | None, args: Any) -> dict[str, Any]:
    """Ubah argumen tool CLI -> argumen tool klien (menyesuaikan skema klien)."""
    a = _json_args(args)
    if client_name == cli_name:
        return a
    props = props or {}

    def key(*names: str) -> str | None:
        return _pick_key(props, *names)

    if cli_name == "read_files":
        paths = a.get("paths") or []
        if not paths:
            return a
        return {(key("path", "filePath", "file_path", "file", "filename") or "path"): paths[0]}

    if cli_name == "str_replace":
        reps = a.get("replacements") or [{}]
        first = _json_args(reps[0] if reps else {})
        out: dict[str, Any] = {}
        pk = key("path", "filePath", "file_path", "file", "filename") or "path"
        out[pk] = a.get("path")
        old_key = key("oldString", "old_string", "oldText", "search") or "oldString"
        new_key = key("newString", "new_string", "newText", "replace") or "newString"
        out[old_key] = first.get("old_string", first.get("oldString", ""))
        out[new_key] = first.get("new_string", first.get("newString", ""))
        return out

    if cli_name == "write_file":
        return {
            (key("path", "filePath", "file_path", "file", "filename") or "path"): a.get("path"),
            (key("content", "text", "file_text", "newContent") or "content"): a.get("content", ""),
        }

    if cli_name == "run_terminal_command":
        out = {(key("command", "cmd", "script") or "command"): a.get("command", "")}
        wd = key("workdir", "cwd", "dir", "directory")
        if wd and a.get("cwd"):
            out[wd] = a["cwd"]
        return out

    if cli_name == "code_search":
        out = {(key("pattern", "query", "regex") or "pattern"): a.get("pattern", "")}
        p = key("path", "cwd", "dir")
        if p and a.get("cwd"):
            out[p] = a["cwd"]
        return out

    if cli_name == "glob":
        out = {(key("pattern", "query", "glob") or "pattern"): a.get("pattern", "")}
        p = key("path", "cwd", "dir")
        if p and a.get("cwd"):
            out[p] = a["cwd"]
        return out

    if cli_name == "list_directory":
        return {(key("path", "dir", "directory") or "path"): a.get("path", ".")}

    if cli_name == "web_search":
        return {(key("query", "q", "search") or "query"): a.get("query", "")}

    if cli_name == "read_url":
        return {(key("url", "uri") or "url"): a.get("url", "")}

    return a


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks = []
        for part in content:
            if isinstance(part, str):
                chunks.append(part)
            elif isinstance(part, Mapping):
                if part.get("type") in ("text", "input_text") and part.get("text"):
                    chunks.append(str(part["text"]))
        return "\n".join(chunks)
    if content is None:
        return ""
    return str(content)


def _translate_messages(
    messages: Sequence[Mapping[str, Any]],
    c2c: Mapping[str, str],
    own_system: str | None = None,
    tool_names: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """OpenAI messages -> format wire codebuff (OpenAI klasik).

    Upstream hanya menerima part `text`, `image_url`, `file`; tool call dikirim
    sebagai `assistant.tool_calls` dan hasilnya sebagai `role:"tool"` biasa.
    Semua pesan `system` digabung jadi SATU system prompt (Buffy dulu) supaya
    deteksi "CLI resmi" upstream tetap lolos.
    """
    tool_names = tool_names if tool_names is not None else {}
    client_systems = [own_system] if own_system else []
    out: list[dict[str, Any]] = []

    for message in messages:
        role = message.get("role")
        if role in ("system", "developer"):
            text = _text_of(message.get("content"))
            if text:
                client_systems.append(text)
            continue

        if role == "tool":
            call_id = message.get("tool_call_id") or ""
            tool_names.setdefault(call_id, message.get("name") or "")
            out.append({
                "role": "tool",
                "tool_call_id": call_id,
                "content": _text_of(message.get("content")),
            })
            continue

        parts: list[dict[str, Any]] = []
        raw = message.get("content")
        if isinstance(raw, list):
            for part in raw:
                if isinstance(part, Mapping) and part.get("type") == "image_url":
                    parts.append({"type": "image_url", "image_url": part.get("image_url") or {}})
                elif page_text := (_text_of(part)):
                    parts.append({"type": "text", "text": page_text})
        else:
            text = _text_of(raw)
            if text:
                parts.append({"type": "text", "text": text})

        entry: dict[str, Any] = {"role": role or "user"}
        if parts:
            entry["content"] = parts
        else:
            entry["content"] = ""

        calls = message.get("tool_calls") or []
        if calls:
            translated = []
            for call in calls:
                fn = call.get("function") or {}
                client_name = fn.get("name") or ""
                cli_name = c2c.get(client_name, client_name)
                call_id = call.get("id") or f"call_{uuid.uuid4().hex[:24]}"
                tool_names[call_id] = cli_name
                translated.append({
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": cli_name,
                        "arguments": json.dumps(_json_args(fn.get("arguments")), ensure_ascii=False),
                    },
                })
            entry["tool_calls"] = translated
        out.append(entry)

    system_text = f.default_system_prompt()
    if client_systems:
        system_text = system_text + "\n\n" + "\n\n".join(client_systems)
    return [{"role": "system", "content": system_text}, *out]


def _translate_tool_calls(
    raw_calls: Sequence[Mapping[str, Any]],
    cli2c: Mapping[str, tuple[str, Mapping[str, Any]]],
    tool_names: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    out = []
    for call in raw_calls:
        fn = call.get("function") or {}
        cli_name = fn.get("name") or ""
        client_name, props = cli2c.get(cli_name, (cli_name, {}))
        args = args_to_client(cli_name, client_name, props, fn.get("arguments"))
        call_id = call.get("id") or f"call_{uuid.uuid4().hex[:24]}"
        if tool_names is not None:
            tool_names[call_id] = cli_name
        out.append({
            "id": call_id,
            "type": "function",
            "function": {"name": client_name, "arguments": json.dumps(args, ensure_ascii=False)},
        })
    return out


class _Turn:
    """Satu giliran chat: siapkan (admission+run+body) dan bisa diulang sekali.

    Upstream bisa menjawab 428 `waiting_room_required` ("Your free session has
    ended. Send your message again to start a new one.") walau admission kita
    masih terlihat aktif; kasus itu butuh admission baru + run baru.
    """

    RETRY_STATUS = (409, 410, 428)

    def __init__(
        self,
        session: "FreebuffSession",
        messages: Sequence[Mapping[str, Any]],
        model_label: str,
        cli2c: Mapping[str, tuple[str, Mapping[str, Any]]],
    ):
        self.session = session
        self.messages = messages
        self.model_label = model_label
        self.cli2c = cli2c
        self.run_id = ""
        self.prepared: f.PreparedRequest | None = None
        self.retried = False

    async def prepare(self) -> None:
        await self.session.ensure_session()
        self.session.step_number += 1
        self.session._persist()
        async with self.session.lock:
            self.run_id = await self.session.start_run(ensure_session=False)
            handle = self.session.resolve_model(self.model_label)
            self.prepared = self.session._build_chat(
                run_id=self.run_id,
                model_handle=handle,
                messages=self.messages,
                tools=f.default_tools(),
                tool_choice="auto",
                stream=True,
                prompt=f._last_user_text(self.messages),
            )

    async def retry(self) -> bool:
        """Sekali saja: pulihkan sesi (heartbeat dulu) lalu run + body baru."""
        if self.retried:
            return False
        self.retried = True
        await self.session.recover_session()
        self.session.step_number += 1
        self.session._persist()
        async with self.session.lock:
            self.run_id = await self.session.start_run(ensure_session=False)
            handle = self.session.resolve_model(self.model_label)
            self.prepared = self.session._build_chat(
                run_id=self.run_id,
                model_handle=handle,
                messages=self.messages,
                tools=f.default_tools(),
                tool_choice="auto",
                stream=True,
                prompt=f._last_user_text(self.messages),
            )
        return True


async def _non_stream(turn: _Turn) -> dict[str, Any]:
    session, prepared = turn.session, turn.prepared
    assert prepared is not None
    try:
        resp = await session.client.request(
            prepared.method, prepared.url, headers=prepared.headers, content=prepared.body
        )
        if resp.status_code in _Turn.RETRY_STATUS and await turn.retry():
            prepared = turn.prepared
            assert prepared is not None
            resp = await session.client.request(
                prepared.method, prepared.url, headers=prepared.headers, content=prepared.body
            )
    except httpx.HTTPError as exc:
        session.record_step("failed")
        raise GatewayError(502, "upstream_error", str(exc)) from exc
    if resp.status_code != 200:
        session.record_step("failed")
        await _maybe_retry(session)
        raise GatewayError(resp.status_code, "chat_failed", _explain(resp.status_code, resp.text))
    text, raw_calls, usage = _consume_sse(resp.text)
    tool_calls = _translate_tool_calls(raw_calls, turn.cli2c, session.tool_names)
    session.record_step("completed")
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": turn.model_label,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text or None, "tool_calls": tool_calls or None},
                "finish_reason": "stop" if not tool_calls else "tool_calls",
            }
        ],
        "usage": usage,
    }


def _explain(status: int, body: str) -> str:
    """Pesan error yang berguna untuk klien."""
    hint = ""
    if "third_party_client_warning" in body:
        hint = " (upstream menganggap request ini bukan dari CLI resmi: jangan kirim tools kustom)"
    elif "free_mode_cli_required" in body:
        hint = " (system prompt CLI tidak terkirim; jangan set system= atau hapus system prompt sendiri)"
    elif "purchase_capacity" in body or "waiting_room" in body:
        hint = " (slot free mode sedang dipakai instance lain)"
    elif "rate_limited" in body or "freebucks" in body:
        hint = " (jatah freebucks sesi ini habis: pakai model non-premium / tunggu jendela berikutnya)"
    elif "ip_capped" in body:
        hint = " (terlalu banyak sesi Freebuff dari IP/jaringan ini: tunggu sesi lain selesai)"
    elif "purchase_claim_released" in body:
        hint = " (klaim sesi free mode dilepas; tunggu nextExpiryAt sebelum mencoba lagi)"
    elif "superseded" in body:
        hint = " (sesi diambil alih instance lain; POST /freebuff/session/reset lalu coba lagi)"
    return body[:400] + hint


class _ChatStream:
    """Streaming: kirim SSE upstream ke klien, jalankan FINISH setelah selesai."""

    def __init__(self, turn: _Turn):
        self.turn = turn

    async def __call__(self) -> AsyncIterator[str]:
        try:
            async for chunk in self._run():
                yield chunk
        finally:
            self.turn.session.slot.release()

    async def _run(self) -> AsyncIterator[str]:
        session = self.turn.session
        try:
            resp = await self._open()
            if resp.status_code in _Turn.RETRY_STATUS:
                await resp.aclose()
                if await self.turn.retry():
                    resp = await self._open()
            if resp.status_code != 200:
                body = (await resp.aread()).decode(errors="replace")[:400]
                await resp.aclose()
                session.record_step("failed")
                await _maybe_retry(session)
                yield _sse_error(resp.status_code, _explain(resp.status_code, body))
                yield "data: [DONE]\n\n"
                return
            try:
                async for chunk in _sse_chunks(session, resp, self.turn.cli2c, self.turn.model_label):
                    yield chunk
            finally:
                await resp.aclose()
            session.record_step("completed")
        except httpx.HTTPError as exc:
            session.record_step("failed")
            yield _sse_error(502, str(exc))

    async def _open(self):
        prepared = self.turn.prepared
        assert prepared is not None
        request = self.turn.session.client.build_request(
            prepared.method, prepared.url, headers=prepared.headers, content=prepared.body
        )
        return await self.turn.session.client.send(request, stream=True)


def _sse_error(status: int, detail: str) -> str:
    return f"data: {json.dumps({'error': {'message': detail, 'type': 'upstream_error', 'code': status}})}\n\n"


async def _sse_chunks(
    session: "FreebuffSession",
    resp,
    cli2c: Mapping[str, tuple[str, Mapping[str, Any]]],
    model_label: str,
) -> AsyncIterator[str]:
    """Teruskan event SSE upstream; tool-call dikumpulkan lalu diterjemahkan."""
    stream_id = f"chatcmpl-{uuid.uuid4().hex}"
    created = int(time.time())
    buffered_calls: list[dict[str, Any]] = []
    emitted_finish = False

    def chunk(delta: dict[str, Any], finish: str | None = None) -> str:
        event = {
            "id": stream_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model_label,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
        }
        return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

    async for line in resp.aiter_lines():
        if not line or not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload == "[DONE]":
            continue
        try:
            event = json.loads(payload)
        except Exception:
            continue
        if event.get("error"):
            yield _sse_error(event.get("status") or 502, str(event["error"])[:300])
            continue
        choices = event.get("choices") or []
        if not choices:
            continue
        choice = choices[0]
        delta = choice.get("delta") or {}
        finish = choice.get("finish_reason")

        raw_calls = delta.get("tool_calls") or []
        if raw_calls:
            for call in raw_calls:
                index = call.get("index", 0)
                while len(buffered_calls) <= index:
                    buffered_calls.append({"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
                slot = buffered_calls[index]
                fn = call.get("function") or {}
                slot["id"] = slot["id"] or (call.get("id") or "")
                slot["function"]["name"] += fn.get("name") or ""
                slot["function"]["arguments"] += fn.get("arguments") or ""
            continue

        text = delta.get("content")
        if text:
            yield chunk({"role": "assistant", "content": text} if not buffered_calls else {"content": text})
        if finish == "stop" and not buffered_calls:
            yield chunk({}, "stop")
            emitted_finish = True
            continue
        if finish and buffered_calls and not emitted_finish:
            translated = _translate_tool_calls(buffered_calls, cli2c, session.tool_names)
            yield chunk({"tool_calls": translated}, "tool_calls")
            emitted_finish = True

    if buffered_calls and not emitted_finish:
        translated = _translate_tool_calls(buffered_calls, cli2c, session.tool_names)
        yield chunk({"tool_calls": translated}, "tool_calls")
    yield "data: [DONE]\n\n"


def _consume_sse(text: str) -> tuple[str, list[dict], dict]:
    text_out: list[str] = []
    tool_calls: list[dict] = []
    usage: dict = {}
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload in ("[DONE]", ""):
            continue
        try:
            event = json.loads(payload)
        except Exception:
            continue
        if event.get("usage"):
            usage = event["usage"]
        if not event.get("choices"):
            continue
        delta = event["choices"][0].get("delta") or {}
        if delta.get("content"):
            text_out.append(delta["content"])
        for tc in delta.get("tool_calls") or []:
            index = tc.get("index", 0)
            while len(tool_calls) <= index:
                tool_calls.append({"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
            slot = tool_calls[index]
            fn = tc.get("function") or {}
            slot["id"] = slot["id"] or (tc.get("id") or "")
            slot["function"]["name"] += fn.get("name") or ""
            slot["function"]["arguments"] += fn.get("arguments") or ""
    return "".join(text_out), tool_calls, usage


async def _maybe_retry(session: "FreebuffSession") -> None:
    """Segarkan katalog & validasi agen, TAPI pertahankan admission.

    Admission (sesi) itu jatah terbatas; membuangnya berarti request berikutnya
    membuka sesi baru. Cukup heartbeat yang memutuskan sesi masih hidup.
    """
    session.catalog_at = 0.0
    session._validate_at = 0.0


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

def configure(session_id: str | None = None, state: str | None = None) -> "FreebuffSession":
    """Siapkan gateway dengan slot sesi tertentu (`--session-id`)."""
    global STATE_PATH, SESSION_ID, gateway
    if state:
        os.environ["FREEBUFF_SESSION_STATE"] = state
        STATE_PATH = Path(state)
    if session_id:
        os.environ["FREEBUFF_SESSION_ID"] = session_id
        SESSION_ID = session_id
        STATE_PATH = state_path_for(session_id)
    gateway = FreebuffSession(session_id=session_id)
    return gateway


gateway = FreebuffSession()


@asynccontextmanager
async def lifespan(app: FastAPI):
    gateway.ensure_identity()  # identitas ditentukan (deterministik) sejak awal
    await gateway.ensure_catalog(force=True)
    yield
    await gateway.aclose()


app = FastAPI(title="Freebuff Gateway", version="0.2.36", lifespan=lifespan)


def _check_token(request: Request) -> None:
    if not GATEWAY_TOKEN:
        return
    auth = request.headers.get("authorization") or ""
    if auth != f"Bearer {GATEWAY_TOKEN}":
        raise HTTPException(status_code=401, detail="unauthorized")


# pydantic model OpenAI-compatible
class ChatMessage(BaseModel):
    role: str
    content: str | list | None = None
    tool_calls: Any = None
    tool_call_id: str | None = None
    name: str | None = None


class ChatRequest(BaseModel):
    model: str | None = None
    messages: list[ChatMessage]
    tools: list[dict[str, Any]] | None = None
    tool_choice: Any = "auto"
    stream: bool = False
    temperature: float | None = None
    max_tokens: int | None = None
    system: str | None = None
    user: str | None = None


@app.get("/healthz")
async def healthz(request: Request):
    _check_token(request)
    return {
        "ok": True,
        "version": f.CLI_VERSION,
        "account": gateway.creds.email,
        "sessionId": gateway.session_id or None,
    }


@app.get("/v1/models")
async def list_models():
    catalog = await gateway.ensure_catalog()
    rows = f.catalog_rows(catalog)
    models = [
        {
            "id": row.get("key"),
            "object": "model",
            "created": int((catalog.get("issuedAt") or 0) / 1000),
            "owned_by": "freebuff",
            "display_name": row.get("displayName"),
            "handle": row.get("handle"),
            "premium": row.get("premium", False),
            "access": row.get("access", "open"),
            "context_window": row.get("contextWindow"),
            "efforts": row.get("efforts"),
        }
        for row in rows
    ]
    return {
        "object": "list",
        "data": models,
        "recommended": catalog.get("recommendedKey"),
        "fetchId": catalog.get("fetchId"),
        "version": catalog.get("version"),
    }


@app.post("/v1/chat/completions")
async def chat_completions(body: ChatRequest, request: Request):
    _check_token(request)
    client_tools = [t for t in (body.tools or []) if isinstance(t, dict)]
    c2c, cli2c = tool_maps(client_tools)
    messages = _translate_messages(
        [m.model_dump() for m in body.messages],
        c2c,
        own_system=body.system,
        tool_names=gateway.tool_names,
    )
    try:
        result = await gateway.chat(
            messages=messages,
            model=body.model,
            stream=body.stream,
            cli2c=cli2c,
        )
    except GatewayError as exc:
        raise HTTPException(status_code=exc.status, detail={"error": exc.error_code, "message": exc.message}) from exc
    if body.stream:
        return StreamingResponse(result(), media_type="text/event-stream")
    return JSONResponse(result)


@app.get("/freebuff/catalog", dependencies=[Depends(_check_token)])
async def get_catalog():
    return await gateway.ensure_catalog()


@app.get("/freebuff/session", dependencies=[Depends(_check_token)])
async def get_session():
    try:
        state = await gateway.ensure_session()
    except GatewayError as exc:
        raise HTTPException(status_code=exc.status, detail={"error": exc.error_code, "message": exc.message}) from exc
    return {
        **state,
        "sessionId": gateway.session_id or None,
        "instanceId": gateway.instance,
        "reused": bool(load_state().get("admission")),
        "statePath": str(STATE_PATH),
    }


@app.post("/freebuff/session/reset", dependencies=[Depends(_check_token)])
async def reset_session():
    await gateway.reset_session()
    return {"ok": True, "instanceId": gateway.instance}


@app.get("/freebuff/streak", dependencies=[Depends(_check_token)])
async def get_streak():
    prepared = f.build_streak_request(gateway.creds.token)
    resp = await gateway.client.get(prepared.url, headers=prepared.headers)
    return resp.json()


@app.get("/freebuff/me", dependencies=[Depends(_check_token)])
async def get_me():
    prepared = f.build_me_request(gateway.creds.token, ("id", "email", "name"))
    resp = await gateway.client.get(prepared.url, headers=prepared.headers)
    return resp.json()


@app.get("/freebuff/fingerprint", dependencies=[Depends(_check_token)])
async def get_fingerprint():
    return {"fingerprintId": f.current_fingerprint_id(), "payload": f.fingerprint_payload()}


# ---- login via API (agar agen lain bisa login) ----
@app.post("/freebuff/login/start", dependencies=[Depends(_check_token)])
async def login_start():
    prepared = f.build_login_code_request()
    resp = await gateway.client.post(prepared.url, headers=prepared.headers, content=prepared.body)
    return resp.json()


class LoginPollRequest(BaseModel):
    fingerprintId: str
    fingerprintHash: str
    expiresAt: int


@app.get("/freebuff/login/status", dependencies=[Depends(_check_token)])
async def login_status(fp: str = "", fph: str = "", expiresAt: int = 0):
    prepared = f.build_login_status_request(fp, fph, expiresAt)
    resp = await gateway.client.get(prepared.url, headers=prepared.headers)
    if resp.status_code == 200:
        data = resp.json()
        user = data.get("user")
        if user:
            f.save_credentials(user)
            return {"ok": True, "user": user}
    return resp.json()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="freebuff-gateway",
        description="Gateway FastAPI Freebuff (API mirip OpenAI).",
    )
    parser.add_argument(
        "--session-id",
        default=os.environ.get("FREEBUFF_SESSION_ID", ""),
        help="Slot sesi yang ditentukan (server gateway memakai/pencipta state "
             "untuk id ini; state disimpan per id di "
             "~/.config/manicode/gateway-sessions/<id>.json). "
             "trace_session_id & client_id dihitung deterministik dari id ini.",
    )
    parser.add_argument("--state", help="Path file state sesi (override FREEBUFF_SESSION_STATE).")
    parser.add_argument("--host", default=os.environ.get("FREEBUFF_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("FREEBUFF_PORT", "8000")))
    parser.add_argument("--token", default=os.environ.get("FREEBUFF_GATEWAY_TOKEN", ""), help="Bearer token akses.")
    parser.add_argument(
        "--list-sessions",
        action="store_true",
        help="Cetak slot sesi yang tersimpan lalu keluar.",
    )
    args = parser.parse_args()

    if args.list_sessions:
        base = Path.home() / ".config" / "manicode" / "gateway-sessions"
        files = sorted(base.glob("*.json")) if base.is_dir() else []
        print(f"{'sesi':24} {'file':6} {'instance':42} status")
        print("-" * 90)
        for path in files:
            try:
                imported = json.loads(path.read_text())
            except Exception:
                imported = {}
            adm = imported.get("admission") or {}
            print(
                f"{path.stem:24} {path.stat().st_size:6} {str(adm.get('instanceId')) or '_':42} "
                f"{adm.get('status') or '-':8} exp {adm.get('expiresAt') or '-':25}"
            )
        print(f"({len(files)} slot terpakai, dir {base})")
        raise SystemExit(0)

    if args.token:
        os.environ["FREEBUFF_GATEWAY_TOKEN"] = args.token
    if args.session_id or args.state:
        configure(session_id=args.session_id, state=args.state)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")