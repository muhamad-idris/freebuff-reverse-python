#!/usr/bin/env python3
"""
freebuff_requests.py
====================

Rekonstruksi Python dari SEMUA pembuat request (headers + payload) milik
Freebuff CLI 0.2.36.

Sumber kebenaran (artifact, bukan tebakan):
  * Binary Bun-compiled: ~/.config/manicode/freebuff  (138 MB, offset 94_535_710
    .. 101_288_000 = 6,7 MB bundle JS yang TIDAK terenkripsi)
    -> hasil ekstraksi: ./bundle.js / ./bundle.pretty.js
  * Wrapper npm: ~/.nvm/versions/node/v26.13.0/lib/node_modules/freebuff/
    {index.js,launcher.js,http.js}  (hanya downloader binary, tidak membuat request API)
  * Reqable live capture 2026-11-18 (record 1..29)

Pemetaan fungsi JS -> fungsi Python (nama simbol minified di bundle.pretty.js):

  qPA()        -> device_canonical_string()
  T2L()        -> DeviceKeyStore.sign_headers()
  ERH.class    -> DeviceKeyStore
  fRH()        -> _b64url()
  cpA()        -> _sha256_hex()
  X2L()/bpA()  -> DeviceKeyStore.generate()/_import_private()
  ltL()/$RH()  -> build_client_env()          (header x-freebuff-env)
  Fv()         -> client_env_header()
  jpA()        -> timezone_header()           (header x-fb-timezone)
  stL()        -> InputProfile.to_header()    (freebuff_input_profile)
  RpA()        -> instance_metadata()         (freebuff_instance_id / multi_session / surface)
  KpA()        -> input_profile_metadata()
  HxA()        -> build_session_request()     (POST admission / GET heartbeat)
  ApL()        -> build_catalog_request()     (GET /api/v1/freebuff/models)
  b5H()        -> build_codebuff_metadata()
  ZHH()/W5H()  -> build_chat_request()        (POST /api/v1/chat/completions)
  tuA()        -> build_agent_run_start()
  QuA()        -> build_agent_run_finish()
  Zw()         -> build_agents_validate_request()
  FqH()/ZAH()  -> build_logs_request() + ApiClient
  hY()         -> build_ads_request()         (/api/v1/ads , /api/ads)
  vA$()        -> build_profile_survey_request()
  tA$()        -> build_sponsored_survey_request()
  z2A()        -> build_project_profile_request()
  PostHog node -> build_posthog_batch()

Temuan penting soal "yang kelihatan terenkripsi":
  1. Tidak ada enkripsi body sama sekali. Body chat = JSON biasa (55 KB karena
     system prompt + 16 tool schema), dan model dikirim sebagai *handle* opaque
     "fbm1.<base64url>" yang berasal dari katalog bertanda-tangan.
  2. Yang membuat request "sulit dipalsukan" adalah tanda tangan Ed25519:
     x-freebuff-device-sig atas string kanonik
     "freebuff-device-v1\\nMETHOD\\nPATH\\nTS_MS\\nSHA256HEX(BODY)\\nFETCH_ID"
     dengan kunci privat PKCS#8 di ~/.config/manicode/device-key.json
     (registrasi lewat POST /api/v1/freebuff/device-keys).
  3. Header x-freebuff-env / freebuff_input_profile / clientContext ikut ditandatangani
     (karena masuk hash body untuk chat) -> ini "sidik jari" klien.

CATATAN CHAT (terbukti empiris 18-19 Nov 2026):
  403 "third_party_client_warning" + strike muncul karena urutan request tidak
  lengkap (tanpa GET /session heartbeat dan tanpa POST /api/agents/validate).
  Setelah urutan 9 langkah dijalankan penuh (lihat run_freebuff_session()),
  chat dijawab 200 tanpa strike. Syarat tambahan: slot sesi free mode hanya
  satu (slotLimit 1); bila dipegang instance lain, admission menjawab
  409 purchase_capacity dan perlu takeover lewat x-freebuff-takeover-instance-id.

Pemakaian:
    python3 freebuff_requests.py fingerprint      # fingerprintId + payload (wsL)
    python3 freebuff_requests.py login            # POST auth/cli/code -> polling
    python3 freebuff_requests.py logout           # POST auth/cli/logout + hapus lokal
    python3 freebuff_requests.py plan             # 9 langkah wajib free mode
    python3 freebuff_requests.py run --prompt "halo" [--confirm]
    python3 freebuff_requests.py environ          # cetak sidik jari env
    python3 freebuff_requests.py selftest         # 18 cek vs capture Reqable
    python3 freebuff_requests.py verify           # tanda tangan Ed25519
    python3 freebuff_requests.py build session|chat|ads|surveys|logs|posthog|...
    python3 freebuff_requests.py send catalog|streak|me|session
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import platform
import re
import secrets
import socket
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import quote, urlencode

try:  # Ed25519 (dipakai binary: WebCrypto "Ed25519", pkcs8/raw)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "butuh paket 'cryptography' (pip install cryptography)"
    ) from exc


# ---------------------------------------------------------------------------
# 0. Konstanta yang dibaca langsung dari bundle (nama simbol aslinya di komentar)
# ---------------------------------------------------------------------------

CLI_VERSION = "0.2.36"                       # package.json / x-freebuff-client-version

# FI.NEXT_PUBLIC_CODEBUFF_APP_URL (bundle offset 16236)
DEFAULT_API_HOST = "https://www.codebuff.com"
# FI.NEXT_PUBLIC_FREEBUFF_APP_URL
DEFAULT_FREEBUFF_HOST = "https://freebuff.com"

# oBA() : override host hanya boleh https (atau http localhost) + domain codebuff/freebuff
APP_URL_ENV_VARS = ("NEXT_PUBLIC_CODEBUFF_APP_URL", "CODEBUFF_APP_URL")
ALLOW_CUSTOM_HOST_ENV = "CODEBUFF_ALLOW_CUSTOM_APP_URL"     # f5H
ALLOWED_HOSTS = ("codebuff.com", "freebuff.com")            # Ms$
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")             # Es$

# Nama header (semua dari bundle)
H_AUTH = "Authorization"
H_USER_AGENT = "User-Agent"
H_CLIENT_VERSION = "x-freebuff-client-version"       # Q_H
H_CLIENT = "x-freebuff-client"                       # UpA
H_CLIENT_ENV = "x-freebuff-env"                      # DpA
H_TIMEZONE = "x-fb-timezone"
H_ACTING_USER = "x-freebuff-acting-user-id"          # xG
H_INSTANCE = "x-freebuff-instance-id"                # L$A
H_MODEL = "x-freebuff-model"                          # _$A
H_SPEND_LIMIT = "x-freebuff-wallet-spend-limit"       # f$A
H_MULTI_SESSION = "x-freebuff-multi-session"          # U$A
H_PURCHASE_CONTINUITY = "x-freebuff-purchase-continuity"  # PpA
H_DESKTOP_ATTEMPT = "x-freebuff-desktop-attempt-id"   # JpA
H_HEARTBEAT = "x-freebuff-heartbeat"                  # J$A
H_INCLUDE_RATE_LIMITS = "x-freebuff-include-unused-rate-limits"  # E$A
H_COMPACT = "x-freebuff-compact-session"              # M$A
H_TAKEOVER = "x-freebuff-takeover-instance-id"        # P$A
H_SSE_GZIP = "x-freebuff-sse-gzip-recovery"           # auA
H_CATALOG_PROTOCOL = "x-freebuff-catalog-protocol"    # Vs
H_CATALOG_FETCH = "x-freebuff-catalog-fetch"          # xs
H_DEVICE_KEY = "x-freebuff-device-key"                # QPA
H_DEVICE_TS = "x-freebuff-device-ts"                  # CPA
H_DEVICE_SIG = "x-freebuff-device-sig"                # FPA

CATALOG_PROTOCOL = "1"                                # ps
CLIENT_KIND = "cli"

# Agent yang dipakai free mode (bundle: tV = "base3-free-catalog", HkA(row)).
# Capture Reqable #21 juga mengirim agentId ini, BUKAN "base2".
FREE_AGENT_ID = "base3-free-catalog"                                   # lVL (header x-freebuff-client)
HG_MODE = "session"                                   # f$A value

# Path endpoint
P_AUTH_CODE = "/api/auth/cli/code"
P_AUTH_STATUS = "/api/auth/cli/status"
P_AUTH_LOGOUT = "/api/auth/cli/logout"
KEYCHAIN_SERVICE = "freebuff-cli"
P_DEVICE_KEYS = "/api/v1/freebuff/device-keys"        # tPA
P_CATALOG = "/api/v1/freebuff/models"                 # uPA
P_SESSION = "/api/v1/freebuff/session"
P_ADMISSION = "/api/v1/freebuff/session/admission"    # I$A
P_CHAT = "/api/v1/chat/completions"
P_AGENT_RUNS = "/api/v1/agent-runs"
P_AGENTS_VALIDATE = "/api/agents/validate"
P_PROJECT_PROFILE = "/api/v1/project-profile"         # W2A
P_LOGS = "/api/logs"
P_ADS = "/api/v1/ads"
P_ADS_POLICY = "/api/v1/ads/policy"
P_STREAK = "/api/v1/freebuff/streak"
P_ME = "/api/v1/me"
P_USAGE = "/api/v1/usage"
P_FEEDBACK = "/api/v1/feedback"
P_PROFILE_SURVEY = "/api/profile-survey"              # OwL
P_SPONSORED_SURVEY = "/api/sponsored-survey"          # u1H
P_ADS_FREEBUFF = "/api/ads"                           # freebuff.com (server-side ads)

# User-Agent
UA_AI_SDK = (
    "ai-sdk/openai-compatible/0.0.0-test/codebuff "
    "ai-sdk/provider-utils/3.0.25 runtime/browser"
)  # binary: `ai-sdk/openai-compatible/${Op}/codebuff`; suffix ditambahkan ai-sdk
UA_CLI = f"Freebuff-CLI/{CLI_VERSION}"                       # _E()
UA_BROWSER = {                                              # EY() / JKA
    "linux": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
    "darwin": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
    "win32": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
}

# PostHog (NEXT_PUBLIC_POSTHOG_API_KEY / HOST_URL)
POSTHOG_HOST = "https://us.i.posthog.com"
POSTHOG_KEY = "phc_tug7g8yc10qNestK14QV8WyKwjfEl6vwzIbJkBdqeHS"
POSTHOG_LIB_VERSION = "5.11.0"

DEVICE_KEY_VERSION = 1
DEVICE_CANON_PREFIX = "freebuff-device-v1"            # qPA()


# ---------------------------------------------------------------------------
# 1. Path & state lokal (~/.config/manicode)
# ---------------------------------------------------------------------------

def config_dir() -> Path:
    """kD() -> ~/.config/manicode (Bun: $XDG_CONFIG_HOME/manicode)."""
    override = os.environ.get("CODEBUFF_CONFIG_DIR") or os.environ.get("MANICODE_DIR")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "manicode"


def device_key_path() -> Path:
    return config_dir() / "device-key.json"           # u2L()


def credentials_path() -> Path:
    return config_dir() / "credentials.json"


def settings_path() -> Path:
    return config_dir() / "settings.json"


def analytics_id_path() -> Path:
    return config_dir() / "analytics-id.json"


@dataclass
class Credentials:
    """credentials.json -> {"default": {id,name,email,fingerprintId,fingerprintHash,authToken,...}}"""

    token: str
    user_id: str | None = None
    email: str | None = None
    name: str | None = None
    fingerprint_id: str | None = None
    fingerprint_hash: str | None = None
    profile: str = "default"

    @classmethod
    def load(cls, profile: str = "default") -> "Credentials":
        raw = json.loads(credentials_path().read_text())
        entry = raw.get(profile) or raw.get("default") or {}
        token = (
            entry.get("authToken")
            or entry.get("auth_token")
            or os.environ.get("CODEBUFF_API_KEY")
            or keychain_token()
        )
        if not token:
            raise SystemExit(
                f"tidak ada authToken di {credentials_path()} (profile={profile}); "
                "set CODEBUFF_API_KEY atau pastikan keychain (secret-tool) berisi "
                "service=freebuff-cli"
            )
        return cls(
            token=token,
            user_id=entry.get("id"),
            email=entry.get("email"),
            name=entry.get("name"),
            fingerprint_id=entry.get("fingerprintId"),
            fingerprint_hash=entry.get("fingerprintHash"),
            profile=profile,
        )


def keychain_token(path: Path | None = None) -> str | None:
    """oFA()/eAH(): token disimpan Bun.secrets (service 'freebuff-cli').

    Bun.secrets di Linux memakai libsecret -> dibaca lewat `secret-tool lookup`
    (schema com.oven-sh.bun.Secret, attribute.account = path credentials.json).
    """
    import shutil
    import subprocess

    if not shutil.which("secret-tool"):
        return None
    account = str(path or credentials_path())
    try:
        result = subprocess.run(
            ["secret-tool", "lookup", "service", "freebuff-cli", "account", account],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return None
    token = result.stdout.strip()
    return token or None


def load_settings() -> dict[str, Any]:
    try:
        return json.loads(settings_path().read_text())
    except Exception:
        return {}


def load_analytics_id() -> str | None:
    try:
        return json.loads(analytics_id_path().read_text()).get("anonymousId")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 2. Utilitas encoding (fRH / cpA / P2L)
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    """fRH(): base64url tanpa padding."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(text: str) -> bytes:
    """U2L(): balikan dari _b64url."""
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _sha256_hex(data: bytes | str | None) -> str:
    """cpA(): sha256 hex dari body (None/undefined -> sha256 dari kosong)."""
    if data is None:
        data = b""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def json_bytes(payload: Any) -> bytes:
    """Serialisasi persis seperti JSON.stringify di Bun (tanpa spasi, UTF-8)."""
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()


def now_ms() -> int:
    return int(time.time() * 1000)


def parse_iso_ms(value: str | int | None) -> int:
    """Timestamp epoch-millis dari ISO 8601 (akhiran Z / +00:00) atau angka ms."""
    if isinstance(value, (int, float)):
        return int(value)
    if not isinstance(value, str):
        return 0
    text = value.strip()
    try:
        text = text.replace("Z", "+00:00")
        return int(datetime.fromisoformat(text).timestamp() * 1000)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return 0


def _last_user_text(messages: Sequence[Mapping[str, Any]]) -> str:
    """Teks gabungan dari pesan user terakhir (untuk input profile)."""
    chunks: list[str] = []
    for message in reversed(list(messages)):
        if message.get("role") not in ("user", "assistant"):
            continue
        content = message.get("content")
        if isinstance(content, str):
            chunks.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and part.get("text"):
                    chunks.append(str(part["text"]))
        if chunks:
            return "\n".join(chunks)
    return ""



def nanoid(n: int = 11) -> str:
    """Client id gaya 'kblov2nfncf' (alfabet URL-safe)."""
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-"
    return "".join(secrets.choice(alphabet) for _ in range(n))


# ---------------------------------------------------------------------------
# 3. Deteksi host API (OM() / oBA() / LxA())
# ---------------------------------------------------------------------------

def _host_allowed(url: str) -> bool:
    if os.environ.get(ALLOW_CUSTOM_HOST_ENV) == "1":
        return True
    try:
        parsed = re.sub(r"/+$", "", url)
        m = re.match(r"^(https?)://([^/:]+)", parsed)
        if not m:
            return False
        scheme, host = m.group(1), m.group(2).lower()
        if scheme != "https" and host not in LOCAL_HOSTS:
            return False
        return any(host == h or host.endswith("." + h) for h in ALLOWED_HOSTS) or host in LOCAL_HOSTS
    except Exception:
        return False


def api_host() -> str:
    """OM(): NEXT_PUBLIC_CODEBUFF_APP_URL/CODEBUFF_APP_URL yang tervalidasi, else default."""
    for var in APP_URL_ENV_VARS:
        value = os.environ.get(var)
        if value is None or value.strip() == "":
            continue
        if _host_allowed(value):
            return value.rstrip("/")
    return DEFAULT_API_HOST


def freebuff_host() -> str:
    """vJ(): NEXT_PUBLIC_FREEBUFF_APP_URL."""
    return (os.environ.get("NEXT_PUBLIC_FREEBUFF_APP_URL") or DEFAULT_FREEBUFF_HOST).rstrip("/")


# ---------------------------------------------------------------------------
# 4. Sidik jari lingkungan: x-freebuff-env (ltL / $RH / Fv)
# ---------------------------------------------------------------------------

_UTC_ZONES = {
    "UTC", "UCT", "GMT", "GMT0", "Greenwich", "Universal", "Zulu",
    "Etc/UTC", "Etc/UCT", "Etc/GMT", "Etc/GMT0", "Etc/GMT+0", "Etc/GMT-0",
    "Etc/Greenwich", "Etc/Universal", "Etc/Zulu",
}
_TZ_RE = re.compile(r"^[A-Za-z]+(?:/[A-Za-z0-9_+-]+){1,2}$")   # itL
_REMOTE_ENV_KEYS = (                                           # _2L()
    "SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "CODESPACES",
    "REMOTE_CONTAINERS", "GITPOD_WORKSPACE_ID", "container",
)

_TERM_PROGRAMS = {                # OtL
    "apple_terminal": "apple_terminal", "iterm.app": "iterm", "iterm2": "iterm",
    "vscode": "vscode", "ghostty": "ghostty", "wezterm": "wezterm",
    "warpterminal": "warp", "hyper": "hyper", "tmux": "tmux", "zed": "zed",
    "tabby": "tabby", "rio": "rio", "mintty": "mintty",
    "jetbrains-jediterm": "jetbrains", "kitty": "kitty", "alacritty": "alacritty",
}
_SHELLS = {                       # WtL
    "sh", "bash", "zsh", "fish", "dash", "ksh", "mksh", "tcsh", "csh",
    "nu", "elvish", "xonsh", "pwsh", "powershell", "cmd", "login",
}
_MUXES = {"tmux", "screen", "zellij", "byobu", "abduco"}          # ztL
_TERMINALS = {                    # mtL
    "terminal", "iterm2", "ghostty", "wezterm", "wezterm-gui", "alacritty",
    "kitty", "warp", "stable", "hyper", "tabby", "konsole", "gnome-terminal",
    "gnome-terminal-server", "gnome-terminal-", "xfce4-terminal",
    "mate-terminal", "lxterminal", "tilix", "terminator", "xterm", "urxvt",
    "rxvt", "st", "foot", "rio", "mintty", "windowsterminal", "openconsole",
    "conhost", "contour", "blackbox", "ptyxis", "ptyxis-agent",
}
_EDITORS = {                      # htL
    "code", "code-insiders", "cursor", "windsurf", "zed", "idea", "pycharm",
    "webstorm", "goland", "clion", "rider", "phpstorm", "rubymine", "datagrip",
    "fleet", "nvim", "vim", "emacs", "helix", "hx", "sublime_text",
}
_LOOPBACK_RE = re.compile(r"^(localhost|127(?:\.\d{1,3}){3}|\[?::1\]?|0\.0\.0\.0)$", re.I)
_ETC_GMT_RE = re.compile(r"^Etc/GMT[+-]\d{1,2}$")                 # L2L


def _classify_process(name: str | None) -> str:
    """TpA(): shell / mux / sshd / node / python / bun / terminal / editor / other."""
    if not name:
        return "unknown"
    value = name.strip()
    if "/" in value:
        value = value.rsplit("/", 1)[1]
    value = re.sub(r"^-+", "", value)
    value = re.sub(r"\.exe$", "", value, flags=re.I).lower()
    if not value:
        return "unknown"
    if value in _SHELLS:
        return "shell"
    if value in _MUXES or value.startswith("tmux"):
        return "mux"
    if value == "sshd" or value.startswith("sshd-"):
        return "sshd"
    if value in ("node", "nodejs"):
        return "node"
    if re.match(r"^python[0-9.]*$", value) or value in ("pypy", "pypy3"):
        return "python"
    if value == "bun":
        return "bun"
    if value in _TERMINALS:
        return "terminal"
    if value in _EDITORS:
        return "editor"
    if re.match(r"^(code|cursor|windsurf|zed|electron)( helper|$)", value):
        return "editor"
    return "other"


def _proc_stat(pid: int) -> tuple[int | None, str | None]:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except Exception:
        return None, None
    lparen, rparen = raw.find("("), raw.rfind(")")
    if lparen < 0 or rparen <= lparen:
        return None, None
    name = raw[lparen + 1:rparen]
    rest = raw[rparen + 2:].split(" ")
    try:
        return int(rest[1]), name
    except Exception:
        return None, name


def process_chain() -> dict[str, Any]:
    """NtL(): {launcher, parent, grandparent} dari /proc."""
    ppid = os.getppid()
    launcher_pid = os.environ.get("CODEBUFF_LAUNCHER_PID")
    launcher = bool(launcher_pid) and launcher_pid == str(ppid)
    pid = ppid
    if launcher:
        pid, _ = _proc_stat(ppid)
    if not pid:
        return {"launcher": launcher, "parent": "unknown", "grandparent": "unknown"}
    parent_ppid, parent_name = _proc_stat(pid)
    gp_name = None
    if parent_ppid:
        _, gp_name = _proc_stat(parent_ppid)
    return {
        "launcher": launcher,
        "parent": _classify_process(parent_name),
        "grandparent": _classify_process(gp_name),
    }


def _classify_term_program(value: str | None) -> str:
    if not value:
        return "none"
    return _TERM_PROGRAMS.get(value.strip().lower(), "other")


def _classify_proxy(env: Mapping[str, str]) -> str:
    """ctL(): none / loopback / remote."""
    kinds = []
    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        raw = env.get(key)
        if not raw or not raw.strip():
            kinds.append("none")
            continue
        url = raw if "://" in raw else f"http://{raw}"
        try:
            host = re.sub(r"^https?://", "", url).split("/")[0].split("@")[-1].split(":")[0]
            kinds.append("loopback" if _LOOPBACK_RE.match(host) else "remote")
        except Exception:
            kinds.append("remote")
    if "loopback" in kinds:
        return "loopback"
    if "remote" in kinds:
        return "remote"
    return "none"


def _classify_cloud(env: Mapping[str, str]) -> str:
    """btL(): codespaces / gitpod / cloudshell / coder / none."""
    if (env.get("CODESPACES") or "").strip().lower() == "true":
        return "codespaces"
    if (env.get("GITPOD_WORKSPACE_ID") or "").strip():
        return "gitpod"
    if (env.get("CLOUD_SHELL") or "").strip().lower() == "true":
        return "cloudshell"
    if (env.get("CODER") or "").strip().lower() == "true":
        return "coder"
    return "none"


def _sanitize_zone(zone: str | None) -> str | None:
    """ARH(): hanya 'Area/Location' yang wajar, maks 64 char."""
    if not zone:
        return None
    value = zone.strip()
    idx = value.rfind("zoneinfo/")
    if idx >= 0:
        value = value[idx + 9:]
    if _TZ_RE.match(value) and len(value) <= 64:
        return value
    return None


def system_timezone() -> str | None:
    """ktL(): Intl.DateTimeFormat().resolvedOptions().timeZone -> /etc/localtime -> /etc/timezone."""
    try:
        link = os.path.realpath("/etc/localtime")
        zone = _sanitize_zone(link)
        if zone:
            return zone
    except Exception:
        pass
    try:
        return _sanitize_zone(Path("/etc/timezone").read_text().strip())
    except Exception:
        pass
    return _sanitize_zone(os.environ.get("TZ"))


def tz_header_zone(zone: str | None = None) -> str | None:
    """f2L(): timezone untuk header x-fb-timezone, None -> header tidak dikirim."""
    zone = zone if zone is not None else system_timezone()
    if not zone or zone == "Etc/Unknown":
        return None
    env = os.environ
    if zone in _UTC_ZONES:
        tz_set = "TZ" in env
        tz_value = (env.get("TZ") or "").strip().lstrip(":")
        if tz_set and tz_value not in _UTC_ZONES:
            return None
        if any(env.get(k) for k in _REMOTE_ENV_KEYS):
            return None
    if platform.system() == "Windows" and _ETC_GMT_RE.match(zone):
        return None
    return zone


def _flag(cond: Any) -> str:
    return "1" if cond else "0"


@dataclass
class ClientEnv:
    """Input untuk ltL(): semua sinyal yang membentuk x-freebuff-env."""

    stdin_is_tty: bool = False
    stdout_is_tty: bool = False
    columns: int = 0
    rows: int = 0
    osc: str = "na"                  # "1" / "0" / "na"
    launcher: bool = False
    parent: str = "unknown"
    grandparent: str = "unknown"
    zone: str | None = None
    timezone_env_set: bool | None = None

    @classmethod
    def detect(cls) -> "ClientEnv":
        chain = process_chain()
        columns = os.get_terminal_size().columns if sys.stdout.isatty() else 0
        rows = os.get_terminal_size().lines if sys.stdout.isatty() else 0
        env = os.environ
        return cls(
            stdin_is_tty=sys.stdin.isatty(),
            stdout_is_tty=sys.stdout.isatty(),
            columns=min(9999, max(0, int(columns or 0))),
            rows=min(9999, max(0, int(rows or 0))),
            osc=env.get("FREEBUFF_OSC", "na"),
            launcher=bool(chain["launcher"]),
            parent=chain["parent"],
            grandparent=chain["grandparent"],
            zone=system_timezone(),
        )

    def to_header(self) -> str:
        """ltL(): string 'v1;in=..;out=..;...' (urutan key HARUS sama)."""
        env = os.environ
        zone = tz_header_zone(self.zone)
        tz_set = bool((env.get("TZ") or "").strip())
        ci = env.get("CI") in ("true", "1") or env.get("GITHUB_ACTIONS") == "true"
        parts: list[tuple[str, str]] = [
            ("in", _flag(self.stdin_is_tty)),
            ("out", _flag(self.stdout_is_tty)),
            ("tp", _classify_term_program(env.get("TERM_PROGRAM"))),
            ("term", _flag(env.get("TERM"))),
            ("ct", _flag(env.get("COLORTERM"))),
            ("sz", f"{self.columns}x{self.rows}"),
            ("ci", _flag(ci)),
            ("ssh", _flag(env.get("SSH_TTY") or env.get("SSH_CONNECTION"))),
            ("l", _flag(self.launcher)),
            ("p", self.parent),
            ("g", self.grandparent),
            ("osc", self.osc),
            ("tzo", _flag(tz_set)),
            ("px", _classify_proxy(env)),
            ("tls", "0" if (env.get("NODE_TLS_REJECT_UNAUTHORIZED") or "").strip() == "0" else "1"),
            ("ca", _flag((env.get("NODE_EXTRA_CA_CERTS") or "").strip())),
            ("cde", _classify_cloud(env)),
        ]
        if tz_set and zone:
            parts.append(("stz", zone))
        return "v1;" + ";".join(f"{k}={v}" for k, v in parts)


def client_env_header(env: ClientEnv | None = None) -> dict[str, str]:
    """Fv(): {x-freebuff-env: ...} atau {} bila fitur dimatikan (CA=false)."""
    if os.environ.get("FREEBUFF_NO_CLIENT_ENV") == "1":
        return {}
    return {H_CLIENT_ENV: (env or ClientEnv.detect()).to_header()}


def timezone_header(zone: str | None = None) -> dict[str, str]:
    """jpA(): {x-fb-timezone: <zone>} atau {}."""
    value = tz_header_zone(zone)
    return {H_TIMEZONE: value} if value else {}


# ---------------------------------------------------------------------------
# 5. Profil input pengguna: freebuff_input_profile (F_H / stL / gpA / KpA)
# ---------------------------------------------------------------------------

@dataclass
class InputProfile:
    """F_H: profil keystroke pada prompt terakhir (dipakai anti-bot)."""

    typed_chars: int = 0
    keypress_events: int = 0
    multi_char_keypress_events: int = 0
    pasted_chars: int = 0
    paste_events: int = 0
    compose_ms: int | None = None
    max_typed_chars_per_second: int = 0

    @classmethod
    def from_prompt(cls, prompt: str, *, gap_ms: int | None = None, pasted: bool = False) -> "InputProfile":
        """Tebakan wajar: satu keypress per karakter (atau satu paste)."""
        n = len(prompt)
        if pasted:
            return cls(pasted_chars=n, paste_events=1, compose_ms=gap_ms)
        # simulasi mengetik: ~4 char/detik
        gap = gap_ms if gap_ms is not None else 0
        return cls(
            typed_chars=n,
            keypress_events=n,
            multi_char_keypress_events=0,
            pasted_chars=0,
            paste_events=0,
            compose_ms=gap if gap > 0 else max(0, int(n * 120)),
            max_typed_chars_per_second=4 if n else 0,
        )

    def to_header(self) -> str:
        """stL(): 'v1;tc=..;ke=..;...' hanya key yang tidak null."""
        items: list[tuple[str, int | None]] = [
            ("tc", self.typed_chars),
            ("ke", self.keypress_events),
            ("mc", self.multi_char_keypress_events),
            ("pc", self.pasted_chars),
            ("pe", self.paste_events),
            ("ms", self.compose_ms),
            ("cps", self.max_typed_chars_per_second),
        ]
        return "v1;" + ";".join(f"{k}={min(10_000_000, max(0, int(v)))}" for k, v in items if v is not None)


def input_profile_metadata(
    profile: InputProfile | None,
    env: ClientEnv | None = None,
) -> dict[str, str]:
    """KpA(): potongan codebuff_metadata.

    PENTING: kunci di metadata bernama `freebuff_client_env`, BUKAN header
    `x-freebuff-env` (capture #58); semua nilainya string.
    """
    meta: dict[str, str] = {"freebuff_client_env": (env or ClientEnv.detect()).to_header()}
    if profile is not None:
        meta["freebuff_input_profile"] = profile.to_header()
    return meta


def instance_metadata(instance_id: str) -> dict[str, str]:
    """RpA(): freebuff_instance_id + (bila instance UUID) multi_session & surface."""
    meta = {"freebuff_instance_id": instance_id}
    if instance_uuid(instance_id):
        meta["freebuff_multi_session"] = "1"
        meta["surface"] = "cli"
    return meta


INSTANCE_PREFIX = "cli:"          # XpA


def new_instance_id() -> str:
    """S_H(): 'cli:<uuid v4>'."""
    return f"{INSTANCE_PREFIX}{uuid.uuid4()}"


def instance_uuid(instance_id: str | None) -> str | None:
    """Y9(): ambil UUID dari 'cli:<uuid>'."""
    if not instance_id or not instance_id.startswith(INSTANCE_PREFIX):
        return None
    value = instance_id[len(INSTANCE_PREFIX):]
    return value or None


# ---------------------------------------------------------------------------
# 6. Device key Ed25519: generasi, registrasi, penandatanganan (ERH / T2L / qPA)
# ---------------------------------------------------------------------------

def device_canonical_string(
    method: str,
    path: str,
    timestamp_ms: int,
    body: bytes | str | None,
    fetch_id: str | None = None,
) -> str:
    """qPA(): string kanonik yang ditandatangani.

    Urutan PERSIS:
        freebuff-device-v1
        <METHOD upper>
        <path tanpa query>
        <ts_ms>
        <sha256hex(body)>
        <fetchId atau string kosong>
    """
    return "\n".join(
        [
            DEVICE_CANON_PREFIX,
            method.upper(),
            path,
            str(timestamp_ms),
            _sha256_hex(body),
            fetch_id or "",
        ]
    )


@dataclass
class DeviceKeyRecord:
    """Bentuk device-key.json (ipA())."""

    public_key: str                                  # base64url(raw 32 byte)
    private_key: str                                 # base64url(PKCS#8 DER)
    registrations: dict[str, str] = field(default_factory=dict)   # scope -> keyId
    version: int = DEVICE_KEY_VERSION

    def to_json(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "publicKey": self.public_key,
            "privateKey": self.private_key,
            "registrations": dict(self.registrations),
        }

    def private_object(self) -> Ed25519PrivateKey:
        """bpA(): importKey("pkcs8", ...)."""
        return serialization.load_der_private_key(
            _b64url_decode(self.private_key), password=None
        )


class DeviceKeyStore:
    """ERH: penyimpanan kunci + registrasi per (host, akun/token) + signing."""

    REGISTER_TIMEOUT_MS = 10_000
    SPIN_TIMEOUT_MS = 3_000
    RETRY_REGISTER_MS = 300_000
    RETRY_UNSUPPORTED_MS = 3_600_000

    def __init__(self, path: Path | None = None, client: str = CLIENT_KIND, log=None):
        self.path = path or device_key_path()
        self.client = client
        self._log = log or (lambda msg: None)
        self.record: DeviceKeyRecord | None = None
        self._retry_after: dict[str, float] = {}

    # --- penyimpanan -----------------------------------------------------
    def load(self) -> DeviceKeyRecord | None:
        try:
            raw = json.loads(self.path.read_text())
        except FileNotFoundError:
            return None
        except Exception:
            return None
        if raw.get("version") != DEVICE_KEY_VERSION:
            return None
        pub, priv = raw.get("publicKey"), raw.get("privateKey")
        if not isinstance(pub, str) or not isinstance(priv, str):
            return None
        regs = raw.get("registrations")
        clean = {
            k: v for k, v in (regs or {}).items() if isinstance(v, str) and v
        } if isinstance(regs, dict) else {}
        return DeviceKeyRecord(public_key=pub, private_key=priv, registrations=clean)

    def save(self, record: DeviceKeyRecord) -> None:
        """t2L().save(): mkdir 0o700, tulis tmp 0o600, chmod, rename."""
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(record.to_json()))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    def ensure(self) -> DeviceKeyRecord:
        """ensureKey(): pakai yang ada, kalau tidak ada buat baru."""
        if self.record is not None:
            return self.record
        record = self.load()
        if record is None:
            record = self.generate()
            self.save(record)
        self.record = record
        return record

    @staticmethod
    def generate() -> DeviceKeyRecord:
        """X2L(): generateKey(Ed25519, extractable) -> raw pub + pkcs8 priv, b64url."""
        private = Ed25519PrivateKey.generate()
        raw_pub = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pkcs8 = private.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return DeviceKeyRecord(public_key=_b64url(raw_pub), private_key=_b64url(pkcs8))

    # --- scope & registrasi ---------------------------------------------
    @staticmethod
    def scope_for(api_origin: str, token: str, account_id: str | None = None) -> str:
        """scopeFor(): '<origin> user:<id>' atau '<origin> token:<sha256[:32]>'."""
        origin = api_origin.rstrip("/")
        if account_id:
            return f"{origin} user:{account_id}"
        return f"{origin} token:{_sha256_hex(token)[:32]}"

    def key_id_for(self, record: DeviceKeyRecord, scope: str) -> str | None:
        return record.registrations.get(scope)

    def register(
        self,
        record: DeviceKeyRecord,
        scope: str,
        *,
        token: str,
        api_origin: str,
        session=None,
    ) -> str | None:
        """register(): POST /api/v1/freebuff/device-keys {publicKey, client}."""
        import urllib.error
        import urllib.request

        url = f"{api_origin.rstrip('/')}{P_DEVICE_KEYS}"
        body = json_bytes({"publicKey": record.public_key, "client": self.client})
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "content-type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.REGISTER_TIMEOUT_MS / 1000) as resp:
                payload = json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            delay = self.RETRY_UNSUPPORTED_MS if exc.code in (404, 405) else self.RETRY_REGISTER_MS
            self._retry_after[scope] = time.time() * 1000 + delay
            self._log(f"device key registration failed (HTTP {exc.code})")
            return None
        except Exception as exc:
            self._retry_after[scope] = time.time() * 1000 + self.RETRY_REGISTER_MS
            self._log(f"device key registration failed ({exc})")
            return None
        key_id = payload.get("keyId") if isinstance(payload, dict) else None
        if not isinstance(key_id, str) or not key_id:
            self._retry_after[scope] = time.time() * 1000 + self.RETRY_REGISTER_MS
            self._log("device key registration returned no keyId")
            return None
        record.registrations[scope] = key_id
        self.save(record)
        return key_id

    def headers(
        self,
        *,
        token: str,
        api_origin: str,
        method: str,
        url: str,
        body: bytes | str | None = None,
        fetch_id: str | None = None,
        account_id: str | None = None,
        register: bool = True,
        timestamp_ms: int | None = None,
    ) -> dict[str, str]:
        """headers(): hasil siap-tempel {x-freebuff-device-key, -ts, -sig}."""
        try:
            record = self.ensure() if register else (self.record or self.load())
            if record is None:
                return {}
            scope = self.scope_for(api_origin, token, account_id)
            key_id = self.key_id_for(record, scope)
            if key_id is None:
                if not register:
                    return {}
                key_id = self.register(record, scope, token=token, api_origin=api_origin)
                if key_id is None:
                    return {}
            return self.sign_headers(
                record,
                key_id=key_id,
                method=method,
                url=url,
                body=body,
                fetch_id=fetch_id,
                timestamp_ms=timestamp_ms,
            )
        except Exception as exc:  # signing failed -> header kosong (binary juga begitu)
            self._log(f"signing failed: {exc}")
            return {}

    def sign_headers(
        self,
        record: DeviceKeyRecord,
        *,
        key_id: str,
        method: str,
        url: str,
        body: bytes | str | None = None,
        fetch_id: str | None = None,
        timestamp_ms: int | None = None,
    ) -> dict[str, str]:
        """T2L(): path = URL pathname saja; sig = base64url(Ed25519(kanon))."""
        ts = timestamp_ms if timestamp_ms is not None else now_ms()
        path = url.split("://", 1)[-1]
        path = "/" + path.split("/", 1)[1] if "/" in path else "/"
        path = path.split("?")[0].split("#")[0]
        canon = device_canonical_string(method, path, ts, body, fetch_id)
        signature = record.private_object().sign(canon.encode())
        return {
            H_DEVICE_KEY: key_id,
            H_DEVICE_TS: str(ts),
            H_DEVICE_SIG: _b64url(signature),
        }

    @staticmethod
    def verify(record: DeviceKeyRecord, canon: str, signature_b64url: str) -> bool:
        try:
            public = Ed25519PublicKey.from_public_bytes(_b64url_decode(record.public_key))
            public.verify(_b64url_decode(signature_b64url), canon.encode())
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# 7. Katalog model (respond bertanda tangan) + resolver handle fbm1.*
# ---------------------------------------------------------------------------

CATALOG_PREFIX = "fbm1."          # RN$


def is_catalog_handle(value: str | None) -> bool:
    """EQH(): apakah nilai ini handle katalog (fbm1.*)."""
    return bool(value) and value.startswith(CATALOG_PREFIX)


def legacy_model_digest(model_id: str) -> str:
    """MQH(): FNV-1a 32-bit ganda atas 'freebuff-legacy-model:<id>'."""
    text = f"freebuff-legacy-model:{model_id}"
    a, b = 2166136261, 1523705862
    for ch in text:
        code = ord(ch)
        a = (a ^ code) * 16777619 & 0xFFFFFFFF
        b = (b ^ code) * 1540483477 & 0xFFFFFFFF
    return f"{a:08x}{b:08x}"


def catalog_rows(catalog: Mapping[str, Any] | None, now: int | None = None) -> list[dict[str, Any]]:
    """Ha(): baris yang sudah dibuka (opensAt <= sekarang)."""
    if not catalog:
        return []
    issued = catalog.get("issuedAt") or (now or now_ms())
    return [
        row for row in catalog.get("rows", [])
        if row.get("opensAt") is None or row.get("opensAt") <= issued
    ]


def catalog_handle(catalog: Mapping[str, Any] | None, model_key: str) -> str | None:
    """HpA(): model key (m-xxxxxxxxxx) -> handle fbm1.* untuk body/header."""
    for row in catalog_rows(catalog):
        if row.get("key") == model_key:
            return row.get("handle")
    return None


def resolve_model(catalog: Mapping[str, Any] | None, model_key: str) -> str:
    """Logika header x-freebuff-model & body 'model': handle bila ada."""
    return catalog_handle(catalog, model_key) or model_key


def catalog_row(catalog: Mapping[str, Any] | None, model_key: str) -> dict[str, Any] | None:
    if not catalog:
        return None
    for row in catalog.get("rows", []):
        if row.get("key") == model_key:
            return row
        if row.get("handle") == model_key:
            return row
    return None


def model_id_by_legacy_digest(catalog: Mapping[str, Any] | None, model_id: str) -> dict[str, Any] | None:
    """UQH(): cari baris lewat legacyDigests (kompatibilitas model id lama)."""
    digest = legacy_model_digest(model_id)
    for row in (catalog or {}).get("rows", []):
        if digest in (row.get("legacyDigests") or []):
            return row
    return None


# ---------------------------------------------------------------------------
# 8. Header set per kelompok request
# ---------------------------------------------------------------------------

def base_headers(
    token: str | None,
    *,
    user_id: str | None = None,
    with_content_type: bool = False,
    with_timezone: bool = False,
    with_client_env: bool = False,
    client_env: ClientEnv | None = None,
    include_client_version: bool = True,
    user_agent: str = UA_CLI,
) -> dict[str, str]:
    """Header dasar yang dipakai hampir semua endpoint."""
    headers: dict[str, str] = {}
    if token:
        headers[H_AUTH] = f"Bearer {token}"
    if with_content_type:
        headers["Content-Type"] = "application/json"
    headers[H_USER_AGENT] = user_agent
    if user_id:
        headers[H_ACTING_USER] = user_id
    if with_timezone:
        headers.update(timezone_header())
    if with_client_env:
        headers.update(client_env_header(client_env))
    if include_client_version:
        headers[H_CLIENT_VERSION] = CLI_VERSION
    return headers


@dataclass
class CatalogRef:
    """Potongan katalog yang dipakai untuk header + tanda tangan."""

    fetch_id: str | None = None
    protocol: str = CATALOG_PROTOCOL

    @classmethod
    def from_catalog(cls, catalog: Mapping[str, Any] | None) -> "CatalogRef":
        if not catalog:
            return cls()
        return cls(fetch_id=catalog.get("fetchId"), protocol=CATALOG_PROTOCOL)


def catalog_headers(ref: CatalogRef | None) -> dict[str, str]:
    """Vs/ps/xs: protokol + fetchId (fetchId ikut ditandatangani)."""
    if ref is None:
        return {}
    headers = {H_CATALOG_PROTOCOL: ref.protocol}
    if ref.fetch_id:
        headers[H_CATALOG_FETCH] = ref.fetch_id
    return headers


def device_sig_headers(
    store: DeviceKeyStore,
    token: str,
    *,
    method: str,
    url: str,
    body: bytes | str | None = None,
    fetch_id: str | None = None,
    account_id: str | None = None,
    register: bool = True,
    timestamp_ms: int | None = None,
) -> dict[str, str]:
    """vy()/spA(): header tanda tangan device (opsional, gagal -> {})."""
    return store.headers(
        token=token,
        api_origin=api_host(),
        method=method,
        url=url,
        body=body,
        fetch_id=fetch_id,
        account_id=account_id,
        register=register,
        timestamp_ms=timestamp_ms,
    )


# ---------------------------------------------------------------------------
# 9. Pembungkus request (hasil bangun tanpa dikirim)
# ---------------------------------------------------------------------------

@dataclass
class PreparedRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None = None

    def body_json(self) -> Any:
        return json.loads(self.body) if self.body else None

    def describe(self, *, max_body: int = 1200) -> str:
        lines = [f"{self.method} {self.url}"]
        lines += [f"  {k}: {v}" for k, v in self.headers.items()]
        if self.body:
            text = self.body.decode(errors="replace")
            lines.append(f"  body ({len(self.body)} byte):")
            lines.append("  " + (text if len(text) <= max_body else text[:max_body] + " ..."))
        return "\n".join(lines)


def _abs(host: str, path: str) -> str:
    return f"{host.rstrip('/')}{path}"


# ---------------------------------------------------------------------------
# 10. Builder: device-keys, katalog, session, streak, me, usage, feedback
# ---------------------------------------------------------------------------

def build_device_registration_request(token: str, store: DeviceKeyStore) -> PreparedRequest:
    """register(): body {publicKey, client:'cli'}."""
    record = store.ensure()
    body = json_bytes({"publicKey": record.public_key, "client": store.client})
    return PreparedRequest(
        method="POST",
        url=_abs(api_host(), P_DEVICE_KEYS),
        headers={
            H_AUTH: f"Bearer {token}",
            "content-type": "application/json",
        },
        body=body,
    )


def build_catalog_request(
    token: str,
    store: DeviceKeyStore,
    *,
    account_id: str | None = None,
    register: bool | None = None,
    timestamp_ms: int | None = None,
) -> PreparedRequest:
    """ApL(): GET /api/v1/freebuff/models.

    Header: Authorization, x-freebuff-catalog-protocol:1, x-freebuff-client:cli,
    lalu x-freebuff-device-* (fetchId = undefined -> baris terakhir kanon kosong).
    Registrasi kunci hanya bila pengguna login (di sini: selalu bila register None).
    """
    url = _abs(api_host(), P_CATALOG)
    headers = {
        H_AUTH: f"Bearer {token}",
        H_CATALOG_PROTOCOL: CATALOG_PROTOCOL,
        H_CLIENT: CLIENT_KIND,
    }
    headers.update(
        device_sig_headers(
            store,
            token,
            method="GET",
            url=url,
            body=None,
            fetch_id=None,
            account_id=account_id,
            register=True if register is None else register,
            timestamp_ms=timestamp_ms,
        )
    )
    return PreparedRequest("GET", url, headers, None)


@dataclass
class SessionParams:
    """Parameter HxA()."""

    token: str
    instance_id: str | None = None          # 'cli:<uuid>'
    model: str = "m-61c26317cc"             # key katalog (bisa handle)
    catalog: CatalogRef | None = None        # hanya fetchId/protocol untuk header
    catalog_data: Mapping[str, Any] | None = None   # katalog penuh -> key jadi handle fbm1.*
    multi_session: bool | None = None
    compact: bool = False
    takeover_instance_id: str | None = None
    user_id: str | None = None
    client_env: ClientEnv | None = None
    extra_headers: Mapping[str, str] = field(default_factory=dict)


def build_session_request(
    method: str,
    params: SessionParams,
    store: DeviceKeyStore,
    *,
    timestamp_ms: int | None = None,
) -> PreparedRequest:
    """HxA(): POST /session/admission (mulai) atau GET /session (heartbeat).

    Urutan header di sini mengikuti urutan Object.assign di binary:
        Authorization, x-fb-timezone, x-freebuff-env, x-freebuff-client-version,
        [multi-session, purchase-continuity, desktop-attempt-id, heartbeat,
         include-unused-rate-limits], catalog-protocol, catalog-fetch,
        instance-id, compact-session, model, wallet-spend-limit,
        lalu device-key/ts/sig; x-freebuff-takeover-instance-id bila ada.
    """
    method = method.upper()
    path = P_ADMISSION if method == "POST" else P_SESSION
    if method == "DELETE":
        path = f"{P_SESSION}/attempt"
    url = _abs(api_host(), path)

    uuid_part = instance_uuid(params.instance_id)
    multi = params.multi_session if params.multi_session is not None else bool(uuid_part)

    headers: dict[str, str] = {H_AUTH: f"Bearer {params.token}"}
    headers.update(timezone_header())
    headers.update(client_env_header(params.client_env))
    headers[H_CLIENT_VERSION] = CLI_VERSION

    if multi:
        headers[H_MULTI_SESSION] = "1"
        headers[H_PURCHASE_CONTINUITY] = "1"
        if uuid_part and method != "GET":
            headers[H_DESKTOP_ATTEMPT] = uuid_part
        if method == "GET" and params.instance_id:
            headers[H_HEARTBEAT] = "1"
            if not params.compact:
                headers[H_INCLUDE_RATE_LIMITS] = "1"

    if params.catalog is not None:
        headers.update(catalog_headers(params.catalog))

    if (multi or method != "POST") and params.instance_id:
        headers[H_INSTANCE] = params.instance_id
    if method == "GET" and params.compact:
        headers[H_COMPACT] = "1"

    if method == "POST":
        if params.takeover_instance_id:
            headers[H_TAKEOVER] = params.takeover_instance_id
        model = params.model
        if model:
            model = catalog_handle(params.catalog_data, model) or model
        headers[H_MODEL] = model
        headers[H_SPEND_LIMIT] = HG_MODE

    headers.update(params.extra_headers)
    # PENTING: HxA() TIDAK mengirim x-freebuff-acting-user-id (dikonfirmasi capture #11/#16);
    # user_id hanya dipakai sebagai scope registrasi kunci device.

    headers.update(
        device_sig_headers(
            store,
            params.token,
            method=method,
            url=url,
            body=None,
            fetch_id=(params.catalog.fetch_id if params.catalog else None),
            account_id=params.user_id,
            timestamp_ms=timestamp_ms,
        )
    )
    return PreparedRequest(method, url, headers, None)


def parse_session_response(status_code: int, payload: Any, method: str = "POST") -> dict[str, Any]:
    """Bagian akhir HxA(): 404 -> none, 403 country/ban, 409 & 429 -> status khusus."""
    if status_code == 404:
        return {"status": "none"}
    if status_code == 403 and isinstance(payload, dict):
        if payload.get("status") in ("country_blocked", "banned"):
            return payload
    if status_code == 409 and method == "POST" and isinstance(payload, dict):
        if payload.get("status") in (
            "model_locked",
            "model_unavailable",
            "premium_slot_taken",
            "purchase_claim_released",
            "purchase_capacity",       # slot sesi dipakai instance lain (slotLimit 1)
            "session_superseded",
            "session_model_mismatch",
            "session_limit_reached",
        ):
            return payload
    if status_code == 429 and method == "POST" and isinstance(payload, dict):
        if payload.get("status") in ("rate_limited", "spend_limited", "ip_capped"):
            return payload
    if not 200 <= status_code < 300:
        return {"status": "error", "httpStatus": status_code, "payload": payload}
    return payload if isinstance(payload, dict) else {"status": "unknown"}


def build_streak_request(token: str) -> PreparedRequest:
    """Q9().get('/api/v1/freebuff/streak', {retry:false})."""
    return PreparedRequest(
        "GET",
        _abs(api_host(), P_STREAK),
        {H_AUTH: f"Bearer {token}"},
        None,
    )


def build_me_request(token: str, fields: Sequence[str] = ("id", "email")) -> PreparedRequest:
    """ZAH.me(): GET /api/v1/me?fields=id,email."""
    query = ",".join(fields)
    return PreparedRequest(
        "GET",
        _abs(api_host(), P_ME) + f"?fields={query}",
        {H_AUTH: f"Bearer {token}"},
        None,
    )


def build_usage_request(token: str, fingerprint_id: str = "cli-usage") -> PreparedRequest:
    """ZAH.usage(): POST /api/v1/usage {fingerprintId}."""
    return PreparedRequest(
        "POST",
        _abs(api_host(), P_USAGE),
        {H_AUTH: f"Bearer {token}", "Content-Type": "application/json"},
        json_bytes({"fingerprintId": fingerprint_id}),
    )


def build_feedback_request(token: str, payload: Mapping[str, Any]) -> PreparedRequest:
    """ZAH.feedback(): POST /api/v1/feedback (body bebas dari UI)."""
    return PreparedRequest(
        "POST",
        _abs(api_host(), P_FEEDBACK),
        {H_AUTH: f"Bearer {token}", "Content-Type": "application/json"},
        json_bytes(dict(payload)),
    )


def build_ads_policy_request(token: str) -> PreparedRequest:
    """iaL(): GET /api/v1/ads/policy (Authorization + user-agent CLI)."""
    return PreparedRequest(
        "GET", _abs(api_host(), P_ADS_POLICY), {H_AUTH: f"Bearer {token}", H_USER_AGENT: UA_CLI}, None
    )


# ---------------------------------------------------------------------------
# 11. Builder: agent-runs (START/FINISH) + agents/validate
# ---------------------------------------------------------------------------

def build_agent_run_start(
    token: str,
    *,
    agent_id: str,
    ancestor_run_ids: Sequence[str] = (),
    user_id: str | None = None,
) -> PreparedRequest:
    """tuA(): POST /api/v1/agent-runs {action:'START', agentId, ancestorRunIds}.

    Catatan: binary TIDAK mengirim Content-Type di sini (hanya Authorization +
    x-freebuff-acting-user-id) dan tidak menandatangani body.
    """
    headers = {H_AUTH: f"Bearer {token}"}
    if user_id:
        headers[H_ACTING_USER] = user_id
    body = json_bytes(
        {"action": "START", "agentId": agent_id, "ancestorRunIds": list(ancestor_run_ids)}
    )
    return PreparedRequest("POST", _abs(api_host(), P_AGENT_RUNS), headers, body)


def build_agent_run_finish(
    token: str,
    *,
    run_id: str,
    status: str,
    total_steps: int | None = None,
    direct_credits: float | None = 0,
    total_credits: float | None = 0,
    error_message: str | None = None,
    steps: Sequence[Mapping[str, Any]] = (),
    user_id: str | None = None,
) -> PreparedRequest:
    """QuA(): POST /api/v1/agent-runs {action:'FINISH', ...}.

    Bentuk persis capture #28/#65:
    {"action":"FINISH","runId":...,"status":"completed","totalSteps":2,
     "directCredits":0,"totalCredits":0,"steps":[{...}]}
    Nilai None dibuang (JSON.stringify membuang undefined), error max 5000 char.
    """
    headers = {H_AUTH: f"Bearer {token}"}
    if user_id:
        headers[H_ACTING_USER] = user_id
    payload: dict[str, Any] = {
        "action": "FINISH",
        "runId": run_id,
        "status": status,
        "totalSteps": total_steps,
        "directCredits": direct_credits,
        "totalCredits": total_credits,
        "errorMessage": error_message[:5000] if isinstance(error_message, str) else error_message,
        "steps": list(steps) if steps else None,
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    return PreparedRequest("POST", _abs(api_host(), P_AGENT_RUNS), headers, json_bytes(payload))


def build_agent_step(
    *,
    step_number: int,
    credits: float | None = None,
    child_run_ids: Sequence[str] = (),
    message_id: str | None = None,
    status: str | None = None,
    error_message: str | None = None,
    start_time: str | datetime | None = None,
) -> dict[str, Any]:
    """CuA(): satu elemen 'steps' untuk FINISH."""
    if isinstance(start_time, datetime):
        start_time = start_time.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "id": str(uuid.uuid4()),
        "stepNumber": step_number,
        "credits": credits,
        "childRunIds": list(child_run_ids),
        "messageId": message_id,
        "status": status,
        "errorMessage": error_message,
        "startTime": start_time,
    }


def build_agents_validate_request(
    token: str | None,
    agent_definitions: Iterable[Mapping[str, Any]],
    *,
    host: str | None = None,
) -> PreparedRequest:
    """Zw(): POST /api/agents/validate {agentDefinitions:[...]}.

    Body bisa sangat besar (capture: 953 KB / 120 definisi).
    """
    definitions = list(agent_definitions)
    headers = {"Content-Type": "application/json"}
    if token:
        headers[H_AUTH] = f"Bearer {token}"
    return PreparedRequest(
        "POST",
        _abs(host or api_host(), P_AGENTS_VALIDATE),
        headers,
        json_bytes({"agentDefinitions": definitions}),
    )


# ---------------------------------------------------------------------------
# 12. Builder: logs batch + PostHog batch
# ---------------------------------------------------------------------------

def build_log_record(
    *,
    event: str,
    data: Mapping[str, Any] | None = None,
    level: str = "info",
    message: str | None = None,
    client_session_id: str | None = None,
    user_id: str | None = None,
) -> dict[str, Any]:
    """Wt()/Z3A(): satu record /api/logs."""
    record: dict[str, Any] = {
        "level": level,
        "event": event,
        "message": message or event,
        "client_session_id": client_session_id,
        "data": dict(data or {}),
    }
    if user_id:
        record["userId"] = user_id
    return {k: v for k, v in record.items() if v is not None}


def build_logs_request(
    token: str | None,
    records: Sequence[Mapping[str, Any]],
    *,
    include_auth: bool = True,
) -> PreparedRequest:
    """O3A.sendBatch(): POST /api/logs {records:[...]} (retry dimatikan, timeout 5s)."""
    headers = {"Content-Type": "application/json"}
    if token and include_auth:
        headers[H_AUTH] = f"Bearer {token}"
    return PreparedRequest("POST", _abs(api_host(), P_LOGS), headers, json_bytes({"records": list(records)}))


def build_posthog_batch(
    events: Sequence[Mapping[str, Any]],
    *,
    api_key: str = POSTHOG_KEY,
    host: str = POSTHOG_HOST,
    sent_at: bool = False,
) -> PreparedRequest:
    """posthog-node 5.11.0 POST /batch/ (body standar + $lib/$geoip_disable)."""
    batch = []
    for event in events:
        properties = dict(event.get("properties") or {})
        properties.setdefault("$lib", "posthog-node")
        properties.setdefault("$lib_version", POSTHOG_LIB_VERSION)
        properties.setdefault("$geoip_disable", True)
        batch.append(
            {
                "distinct_id": event["distinct_id"],
                "event": event["event"],
                "properties": properties,
                "type": "capture",
                "library": "posthog-node",
                "library_version": POSTHOG_LIB_VERSION,
                "timestamp": event.get("timestamp")
                or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "uuid": event.get("uuid") or str(uuid.uuid4()),
            }
        )
    payload: dict[str, Any] = {"api_key": api_key, "batch": batch}
    if sent_at:
        payload["sent_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return PreparedRequest("POST", host.rstrip("/") + "/batch/", {"Content-Type": "application/json"}, json_bytes(payload))


# ---------------------------------------------------------------------------
# 13. Builder: chat/completions (payload terbesar & paling "opaque")
# ---------------------------------------------------------------------------

def build_codebuff_metadata(
    *,
    run_id: str,
    client_id: str,
    extras: Mapping[str, Any] | None = None,
    n: int | None = None,
    cost_mode: str | None = None,
    cache_debug_correlation: str | None = None,
) -> dict[str, Any]:
    """b5H().codebuff_metadata: {...extras, run_id, client_id, n?, cost_mode?, ...}.

    extras pada capture berisi: freebuff_instance_id, freebuff_multi_session,
    surface, freebuff_client_env, freebuff_input_profile, trace_session_id,
    repo_snapshot, compaction_*, llm_step_number.
    """
    meta: dict[str, Any] = dict(extras or {})
    meta["run_id"] = run_id
    meta["client_id"] = client_id
    if n:
        meta["n"] = n
    if cost_mode:
        meta["cost_mode"] = cost_mode
    if cache_debug_correlation:
        meta["cache_debug_correlation"] = cache_debug_correlation
    return meta


def build_chat_messages(
    *,
    system_prompt: str | None,
    user_text: str | None = None,
    history: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Nd(): system (string) + riwayat + user (array part {type:'text'})."""
    messages: list[dict[str, Any]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    for item in history:
        messages.append(dict(item))
    if user_text is not None:
        messages.append({"role": "user", "content": [{"type": "text", "text": user_text}]})
    return messages


def build_chat_request(
    token: str,
    store: DeviceKeyStore,
    *,
    model: str,
    messages: Sequence[Mapping[str, Any]],
    tools: Sequence[Mapping[str, Any]] | None = None,
    tool_choice: str | dict | None = "auto",
    run_id: str,
    client_id: str,
    user_id: str | None = None,
    catalog: CatalogRef | None = None,
    codebuff_metadata_extra: Mapping[str, Any] | None = None,
    provider: Mapping[str, Any] | None = None,
    cost_mode: str | None = "free",
    stream: bool = True,
    max_tokens: int | None = None,
    temperature: float | None = None,
    top_p: float | None = None,
    reasoning_effort: str | None = None,
    verbosity: str | None = None,
    session_user: str | None = None,
    timestamp_ms: int | None = None,
) -> PreparedRequest:
    """ZHH()+ai-sdk: body dengan urutan key PERSIS seperti capture.

    Urutan: model, user, max_tokens, temperature, top_p, frequency_penalty,
    presence_penalty, response_format, stop, seed, (providerOptions 'codebuff'
    yang tidak ada di schema di-hoist ke top-level: codebuff_metadata, provider),
    reasoning_effort, verbosity, messages, tools, tool_choice, stream[, stream_options].

    Header: Authorization, Content-Type, User-Agent ai-sdk, x-freebuff-sse-gzip-recovery,
    x-freebuff-acting-user-id, lalu requestHeaders(token,{method,url,body}) =
    x-freebuff-client-version, x-freebuff-catalog-fetch, x-freebuff-device-{key,ts,sig}.
    Signing memakai sha256 dari body JSON yang benar-benar dikirim.
    """
    url = _abs(api_host(), P_CHAT)

    body: dict[str, Any] = {
        "model": model,
        "user": session_user,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "top_p": top_p,
        "frequency_penalty": None,
        "presence_penalty": None,
        "response_format": None,
        "stop": None,
        "seed": None,
        "codebuff_metadata": build_codebuff_metadata(
            run_id=run_id,
            client_id=client_id,
            extras=codebuff_metadata_extra,
            cost_mode=cost_mode,
        ),
        "provider": dict(provider or {"data_collection": "deny"}),
        "reasoning_effort": reasoning_effort,
        "verbosity": verbosity,
        "messages": [dict(m) for m in messages],
        "tools": [dict(t) for t in tools] if tools is not None else None,
        "tool_choice": tool_choice,
    }
    body = {k: v for k, v in body.items() if v is not None}
    if stream:
        body["stream"] = True
    payload = json_bytes(body)

    headers: dict[str, str] = {H_AUTH: f"Bearer {token}"}
    headers["Content-Type"] = "application/json"
    headers[H_USER_AGENT] = UA_AI_SDK
    headers[H_SSE_GZIP] = "1"
    if user_id:
        headers[H_ACTING_USER] = user_id
    headers[H_CLIENT_VERSION] = CLI_VERSION
    if catalog and catalog.fetch_id:
        headers[H_CATALOG_FETCH] = catalog.fetch_id
    headers.update(
        device_sig_headers(
            store,
            token,
            method="POST",
            url=url,
            body=payload,
            fetch_id=(catalog.fetch_id if catalog else None),
            account_id=user_id,
            timestamp_ms=timestamp_ms,
        )
    )
    return PreparedRequest("POST", url, headers, payload)


# ---------------------------------------------------------------------------
# 14. Builder: iklan (/api/v1/ads dan freebuff.com/api/ads) + survey + profil
# ---------------------------------------------------------------------------

def client_device() -> dict[str, str]:
    """IC(): {os, timezone, locale}."""
    os_name = {"darwin": "macos", "win32": "windows", "linux": "linux"}.get(platform.system().lower(), "linux")
    zone = os.environ.get("TZ") or system_timezone() or "UTC"
    locale = (os.environ.get("LC_ALL") or os.environ.get("LANG") or "en-US").split(".")[0].replace("_", "-")
    return {"os": os_name, "timezone": zone, "locale": locale or "en-US"}


def browser_user_agent() -> str:
    """EY(): UA browser palsu sesuai platform."""
    key = {"darwin": "darwin", "windows": "win32", "linux": "linux"}.get(
        client_device()["os"], "linux"
    )
    return UA_BROWSER[key]


def build_ads_request(
    token: str,
    *,
    messages: Sequence[Mapping[str, Any]] = (),
    session_id: str,
    provider: str | None = None,
    surface: str | None = "cli_chat",
    placement_id: str | None = None,
    placement_ids: Sequence[str] = (),
    draft: str | None = None,
    sponsored_capability: Mapping[str, Any] | None = None,
    capability_inspection: Mapping[str, Any] | None = None,
    trace_context: Mapping[str, Any] | None = None,
    cli_dock_arm: str | None = "control",
    client_context: Mapping[str, Any] | None = None,
    use_freebuff_host: bool = False,
    client_env: ClientEnv | None = None,
    max_draft_chars: int = 4096,
) -> PreparedRequest:
    """hY(): POST /api/v1/ads (atau freebuff.com/api/ads untuk sponsored).

    Header: Content-Type, Authorization, User-Agent _E()='Freebuff-CLI/0.2.36',
    x-freebuff-env. Body: provider?, messages, sessionId, device, traceContext?,
    sponsoredCapability?, capabilityInspection?, surface?, placementId?,
    placementIds?, userAgent (UA browser), cliDockArm?, clientContext?.

    CATATAN: `clientContext` di binary dibangun dari puluhan sinyal heuristik
    (fungsi xaL/caL, ±400 baris). Di sini dipakai builder sederhana yang
    meniru bentuknya; isi nilainya bukan hasil ekstraksi 1:1.
    """
    host = freebuff_host() if use_freebuff_host else api_host()
    path = P_ADS_FREEBUFF if use_freebuff_host else P_ADS
    msgs = [dict(m) for m in messages]
    if draft:
        msgs = msgs + [{"role": "user", "content": draft[-max_draft_chars:]}]
    body: dict[str, Any] = {}
    if provider:
        body["provider"] = provider
    body["messages"] = msgs
    body["sessionId"] = session_id
    body["device"] = client_device()
    if trace_context:
        body["traceContext"] = dict(trace_context)
    if sponsored_capability:
        body["sponsoredCapability"] = dict(sponsored_capability)
    if capability_inspection:
        body["capabilityInspection"] = dict(capability_inspection)
    if surface:
        body["surface"] = surface
    if placement_id:
        body["placementId"] = placement_id
    if placement_ids:
        body["placementIds"] = list(placement_ids)
    body["userAgent"] = browser_user_agent()
    if cli_dock_arm:
        body["cliDockArm"] = cli_dock_arm
    if client_context is None:
        client_context = default_client_context()
    body["clientContext"] = dict(client_context)
    headers = {
        "Content-Type": "application/json",
        H_AUTH: f"Bearer {token}",
        H_USER_AGENT: UA_CLI,
        **client_env_header(client_env),
    }
    return PreparedRequest("POST", _abs(host, path), headers, json_bytes(body))


def _bucket(value: float, edges: Sequence[float], labels: Sequence[str]) -> str:
    for edge, label in zip(edges, labels):
        if value < edge:
            return label
    return labels[-1]


def default_client_context(
    *,
    harness: str = "base3-free-catalog",
    model_key: str = "m-61c26317cc",
    cols: int | None = None,
    rows: int | None = None,
    shell: str | None = None,
    ads_this_session: int = 0,
) -> dict[str, Any]:
    """clientContext seperti capture #14 (semua nilai sudah berbentuk bucket).

    Struktur: v, sys, attn, sess, agent, net, app, ui, work, term.
    CATATAN: binary membangun ini di xaL/caL (±400 baris) dari banyak sinyal
    runtime (RAM, load, disk, RTT, riwayat ketikan, isi terminal). Versi Python
    ini menghasilkan bentuk & tipe yang sama, dengan bucket wajar/umum.
    """
    machine = platform.machine().lower()
    try:
        size = os.get_terminal_size()
        cols = cols if cols is not None else size.columns
        rows = rows if rows is not None else size.lines
    except Exception:
        cols = cols or 0
        rows = rows or 0
    total_ram_gb = _total_ram_gb()
    cores = os.cpu_count() or 4
    return {
        "v": 1,
        "sys": {
            "osMajor": platform.release().split(".")[0] or "unknown",
            "arch": "arm64" if machine in ("aarch64", "arm64") else "x64",
            "ram": _bucket(total_ram_gb, (4, 8, 16, 32), ("<4", "4-8", "8-16", "16-32", "32+")),
            "uptime": "<1d",
            "load": "low",
            "freeMemory": "25-50%",
            "cores": _bucket(cores, (2, 5, 9, 17), ("1", "2-4", "5-8", "9-16", "17+")),
            "cpu": "intel",
            "diskFree": "50-200",
            "cpuTier": "x86_5" if machine in ("x86_64", "amd64") else "arm_1",
        },
        "attn": {
            "sinceInput": "never",
            "sinceSend": "never",
            "turnRunning": False,
            "pendingPrompt": False,
            "scrolledUp": False,
            "typingSpeed": "slow",
            "editRatio": "<5%",
        },
        "sess": {
            "adsThisSession": str(ads_this_session),
            "sinceLastAd": "never",
            "sinceLastClick": "never",
        },
        "agent": {"harness": harness, "model": model_key, "effort": "default", "mode": "build"},
        "net": {"rtt": "50-150", "failedRequests": "0", "adFetch": "300-1000"},
        "app": {"uptime": "<1h", "installAge": "<1d", "channel": "stable", "installMethod": "npm", "runtime": "bun-1.3"},
        "ui": {"language": (os.environ.get("LANG") or "en").split("_")[0].split(".")[0] or "en", "languageCount": "1"},
        "work": {"tool": "none", "lastError": "none", "turnFailures": "0", "skills": "0"},
        "term": {
            "terminal": "vte" if os.environ.get("TERM_PROGRAM") else "unknown",
            "links": True,
            "mouse": True,
            "multiplexer": "tmux" if os.environ.get("TMUX") else "none",
            "remote": "none" if not os.environ.get("SSH_CONNECTION") else "ssh",
            "cols": _bucket(cols, (40, 80, 120, 160), ("<40", "40-79", "80-119", "120-159", "160+")),
            "colors": "truecolor" if "256" in (os.environ.get("TERM") or "") or "truecolor" in (os.environ.get("COLORTERM") or "") else "16",
            "images": "none",
            "shell": shell or (Path(os.environ.get("SHELL", "/bin/sh")).name or "sh"),
            "focused": True,
            "rows": _bucket(rows, (12, 24, 40), ("<12", "12-23", "24-39", "40+")),
            "utf8": True,
            "proxy": bool(os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")),
        },
    }


def _total_ram_gb() -> float:
    try:
        with open("/proc/meminfo") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) / 1024 / 1024
    except Exception:
        pass
    return 8.0


def _survey_query(**params: Any) -> str:
    """URLSearchParams(): koma & lainnya di-encode (%2C, %3A)."""
    items = [(k, str(v)) for k, v in params.items() if v is not None and v != ""]
    return ("?" + urlencode(items, quote_via=quote, safe="")) if items else ""


def build_profile_survey_request(
    token: str,
    *,
    method: str = "GET",
    body: Mapping[str, Any] | None = None,
) -> PreparedRequest:
    """vA$(): GET/POST /api/profile-survey di host freebuff.com.

    GET  -> TANPA query string (dikonfirmasi capture #20; yang punya
            ?questionKinds=...&surface=cli hanya sponsored-survey #22).
    POST -> {action:'answer'|'dismiss'|'event', version, questionId?, optionIds?,
             durationMs?, event?, surface:'cli'}
    Header: authorization + user-agent Freebuff-CLI (content-type hanya untuk POST).
    """
    base = freebuff_host()
    if method.upper() == "GET":
        return PreparedRequest("GET", _abs(base, P_PROFILE_SURVEY), {H_AUTH: f"Bearer {token}", H_USER_AGENT: UA_CLI}, None)
    headers = {H_AUTH: f"Bearer {token}", H_USER_AGENT: UA_CLI, "content-type": "application/json"}
    return PreparedRequest("POST", _abs(base, P_PROFILE_SURVEY), headers, json_bytes(dict(body or {})))


def build_sponsored_survey_request(
    token: str,
    *,
    method: str = "GET",
    body: Mapping[str, Any] | None = None,
    question_kinds: Sequence[str] = ("single", "multi", "ranking", "text"),
    surface: str | None = "cli",
) -> PreparedRequest:
    """tA$(): GET /api/sponsored-survey?questionKinds=...&surface=cli (URLSearchParams)."""
    base = freebuff_host()
    if method.upper() == "GET":
        url = _abs(base, P_SPONSORED_SURVEY) + _survey_query(
            questionKinds=",".join(question_kinds), surface=surface
        )
        return PreparedRequest("GET", url, {H_AUTH: f"Bearer {token}", H_USER_AGENT: UA_CLI}, None)
    headers = {H_AUTH: f"Bearer {token}", H_USER_AGENT: UA_CLI, "content-type": "application/json"}
    return PreparedRequest("POST", _abs(base, P_SPONSORED_SURVEY), headers, json_bytes(dict(body or {})))


def project_key(cwd: str | Path | None = None) -> str:
    """z2A().projectKey: 'local:' + sha256(realpath cwd)[:32]."""
    base = Path(cwd or os.getcwd()).resolve()
    try:  # ikuti gitdir worktree seperti binary
        gitfile = base / ".git"
        text = gitfile.read_text() if gitfile.is_file() else ""
        match = re.search(r"^gitdir:\s*(.+)$", text, re.M)
        if match:
            resolved = (base / match.group(1).strip()).resolve()
            idx = str(resolved).find(os.sep + ".git" + os.sep + "worktrees" + os.sep)
            if idx > 0:
                base = Path(str(resolved)[:idx])
    except Exception:
        pass
    return f"local:{hashlib.sha256(str(base).encode()).hexdigest()[:32]}"


def build_project_profile_request(
    token: str,
    *,
    key: str | None = None,
    user_id: str | None = None,
    surface: str | None = "cli",
    report: Mapping[str, Any] | None = None,
) -> PreparedRequest:
    """z2A(): GET ?project_key=... atau POST {projectKey, surface, ...report}."""
    headers = {H_AUTH: f"Bearer {token}", "Content-Type": "application/json"}
    if user_id:
        headers[H_ACTING_USER] = user_id
    key = key or project_key()
    if report is None:
        return PreparedRequest(
            "GET",
            _abs(api_host(), P_PROJECT_PROFILE)
            + _survey_query(project_key=key),
            headers,
            None,
        )
    body = {"projectKey": key, "surface": surface}
    body.update(dict(report))
    return PreparedRequest("POST", _abs(api_host(), P_PROJECT_PROFILE), headers, json_bytes(body))


# ---------------------------------------------------------------------------
# 15. Aset lokal: system prompt & 16 tool schema (dari binary / capture)
# ---------------------------------------------------------------------------

_ASSET_DIRS = [Path(__file__).resolve().parent, Path.home()]


def _find_asset(name: str) -> Path | None:
    for directory in _ASSET_DIRS:
        for candidate in (directory / name, directory / "freebuff" / name):
            if candidate.is_file():
                return candidate
    return None


def default_tools() -> list[dict[str, Any]]:
    """16 tool schema yang dikirim di setiap request chat.

    Sumber: freebuff_default_tools.json (hasil ekstraksi bundle) atau, bila ada,
    file body capture Reqable.
    """
    path = _find_asset("freebuff_default_tools.json")
    if path:
        return json.loads(path.read_text())
    raise SystemExit("freebuff_default_tools.json tidak ditemukan (lihat docstring)")


def default_system_prompt(date: str | None = None) -> str:
    """System prompt 'You are Buffy, the coding agent behind Codebuff...'."""
    path = _find_asset("freebuff_system_prompt.txt")
    if not path:
        raise SystemExit("freebuff_system_prompt.txt tidak ditemukan")
    text = path.read_text()
    # QN$(): Intl.DateTimeFormat("en-US", {year,month:long,day}) -> "November 18, 2026"
    stamp = date or datetime.now().strftime("%B %-d, %Y") if os.name != "nt" else datetime.now().strftime("%B %d, %Y")
    return text.replace("@@DATE@@", stamp)


# ---------------------------------------------------------------------------
# 16. Klien HTTP (memakai requests, opsional)
# ---------------------------------------------------------------------------

class ApiClient:
    """Pembungkus tipis: kirim PreparedRequest, kembalikan (status, headers, body)."""

    def __init__(self, timeout: float = 30.0, user_agent: str | None = None):
        import requests  # import lokal supaya modul bisa dipakai offline

        self._requests = requests
        self.timeout = timeout
        self.user_agent = user_agent
        self.session = requests.Session()
        if user_agent:
            self.session.headers[H_USER_AGENT] = user_agent

    def send(self, prepared: PreparedRequest, *, stream: bool = False):
        response = self.session.request(
            prepared.method,
            prepared.url,
            headers=prepared.headers,
            data=prepared.body,
            timeout=self.timeout,
            stream=stream,
        )
        return response

    def send_json(self, prepared: PreparedRequest) -> tuple[int, Any]:
        response = self.send(prepared)
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, response.text


def freebuff_agent_id(catalog_row: Mapping[str, Any] | None = None) -> str:
    """Agent id untuk free mode: selalu 'base3-free-catalog' (HkA()/tV)."""
    return FREE_AGENT_ID


def chat_sequence_plan(prompt: str = "hi") -> list[str]:
    """Urutan request yang WAJIB dijalankan sebelum chat (capture #36..#59).

    Kalau salah satu langkah hilang, server menolak chat:
    409 freebuff_catalog_stale -> 403 free_mode_invalid_agent_model ->
    403 third_party_client_warning (dicatat sebagai strike).
    """
    return [
        "GET  /api/v1/freebuff/models            -> fetchId + handle fbm1.*",
        "GET  /api/v1/freebuff/session            -> heartbeat (x-freebuff-instance-id)",
        "POST /api/v1/freebuff/session/admission  -> x-freebuff-model = handle fbm1.*",
        f"POST /api/agents/validate                -> 120 definisi, {FREE_AGENT_ID} "
        "dengan model = handle",
        "GET  /api/v1/freebuff/session            -> heartbeat lagi",
        f"POST /api/v1/agent-runs START           -> agentId={FREE_AGENT_ID} -> runId",
        "POST /api/v1/chat/completions            -> codebuff_metadata.run_id = runId",
        "GET  /api/v1/project-profile             -> project_key=local:<sha256[:32]>",
        "POST /api/v1/agent-runs FINISH",
    ]


# ---------------------------------------------------------------------------
# 17. Verifikasi terhadap capture Reqable (bukti byte-exact)
# ---------------------------------------------------------------------------

REQABLE_TMP = Path.home() / ".local" / "share" / "reqable" / "tmp"

# Header dari capture Reqable record #23 (POST /api/v1/chat/completions, 15:18:13)
CAPTURE_CHAT = {
    "body_file": "decaa304-1f40-49d3-9709-1c054352205c",
    "method": "POST",
    "path": "/api/v1/chat/completions",
    "ts": "1794989919791",
    "key_id": "d1QqPFaqS938fQqRewQzxs",
    "sig": "LjuRS1nE6Lu7TmOP1nNmjc9lxLr9w0FO5l_pTRvrPc7ZwA_ppCO29rACAjo8j3B4b5xepSJSW2Mc0BTIbQofCA",
    "fetch_id": (
        "fbf1.AAHvH7id9tLSdOvGiMKGe980bre7X5o0NcqjDSEFK4103p_HECTbKoMep5jOkdo14LcaAnmNSJsObtH35"
        "_2cAK4phS5o6nGqHiCETvJqUgWU0pwYoFJ41lkTbWBN-7BTCKmhNSJJ4qy5ojPt8Ry2qPAb8_vLnaxVo9zqdDMv"
        "-Pbn1yZ2X8ByzF-bYdY"
    ),
}


def cmd_verify() -> int:
    """Buktikan pipeline tanda tangan + urutan payload: capture dan round-trip."""
    store = DeviceKeyStore()
    record = store.load()
    if record is None:
        print("SKIP: device-key.json tidak ada (jalankan login dulu)")
        return 0

    registered = set(record.registrations.values())
    print("== 1. Verifikasi tanda tangan device (record Reqable #23)")
    body_path = REQABLE_TMP / CAPTURE_CHAT["body_file"]
    if CAPTURE_CHAT["key_id"] not in registered:
        print(f"   SKIP: kunci capture ({CAPTURE_CHAT['key_id']}) sudah tidak aktif "
              f"(registrasi sekarang: {sorted(registered)})")
        capture_ok = True
    elif not body_path.is_file():
        print(f"   SKIP: body capture tidak ada di {body_path}")
        capture_ok = True
    else:
        body = body_path.read_bytes()
        canon = device_canonical_string(
            CAPTURE_CHAT["method"], CAPTURE_CHAT["path"], int(CAPTURE_CHAT["ts"]), body, CAPTURE_CHAT["fetch_id"]
        )
        capture_ok = DeviceKeyStore.verify(record, canon, CAPTURE_CHAT["sig"])
        print(f"   panjang body   : {len(body)} byte")
        print(f"   sha256(body)   : {_sha256_hex(body)}")
        print(f"   kanon          : {canon.splitlines()[1]} {canon.splitlines()[2]} ts={canon.splitlines()[3]}")
        print(f"   Ed25519 verify : {'LULUS (kanon & encoding byte-exact)' if capture_ok else 'GAGAL'}")

    print("\n== 1b. Round-trip tanda tangan dengan kunci aktif")
    probe = json_bytes({"probe": "verify", "ts": now_ms()})
    canon = device_canonical_string("POST", P_CHAT, 1794989919791, probe, "fbf1.probe")
    signature = record.private_object().sign(canon.encode())
    round_ok = DeviceKeyStore.verify(record, canon, _b64url(signature))
    print(f"   sign+verify    : {'LULUS' if round_ok else 'GAGAL'}")
    print(f"   keyId aktif    : {sorted(registered) or '(belum terdaftar)'}")

    print("\n== 2. Bandingkan payload chat yang kita bangun dengan capture #23")
    if body_path.is_file():
        captured = json.loads(body_path.read_bytes())
        creds = Credentials.load()
        prepared = build_chat_request(
            token=creds.token,
            store=store,
            model=captured["model"],
            messages=build_chat_messages(system_prompt=default_system_prompt(), user_text="ping"),
            tools=default_tools(),
            run_id=captured["codebuff_metadata"]["run_id"],
            client_id=captured["codebuff_metadata"]["client_id"],
            user_id=creds.user_id,
            catalog=CatalogRef(fetch_id=CAPTURE_CHAT["fetch_id"]),
            codebuff_metadata_extra={
                k: v for k, v in captured["codebuff_metadata"].items()
                if k not in ("run_id", "client_id", "cost_mode")
            },
            cost_mode=captured["codebuff_metadata"].get("cost_mode"),
            timestamp_ms=int(CAPTURE_CHAT["ts"]),
        )
        ours = prepared.body_json()
        print(f"   key order capture : {list(captured.keys())}")
        print(f"   key order kita    : {list(ours.keys())}")
        print(f"   urutan sama       : {list(captured.keys()) == list(ours.keys())}")
        print(f"   jumlah tool       : capture={len(captured['tools'])} kita={len(ours.get('tools', []))}")
        diff = [k for k in captured if k in ours and json.dumps(captured[k], sort_keys=True) != json.dumps(ours[k], sort_keys=True)]
        print(f"   field berbeda     : {diff or 'tidak ada'}")
        expected = [
            "Authorization", "Content-Type", "User-Agent", "x-freebuff-acting-user-id",
            "x-freebuff-catalog-fetch", "x-freebuff-client-version", "x-freebuff-device-key",
            "x-freebuff-device-sig", "x-freebuff-device-ts", "x-freebuff-sse-gzip-recovery",
        ]
        print(f"   set header sama   : {sorted(prepared.headers) == sorted(expected)}")
    else:
        print("   SKIP: body capture tidak tersedia")

    return 0 if (capture_ok and round_ok) else 1


# ---------------------------------------------------------------------------
# 18. CLI sederhana
# ---------------------------------------------------------------------------

def _load_catalog() -> dict[str, Any] | None:
    """Katalog tersimpan (hasil GET /api/v1/freebuff/models) bila pernah disimpan."""
    for candidate in (config_dir() / "freebuff-catalog.json", Path(__file__).resolve().parent / "freebuff-catalog.json"):
        try:
            if candidate.is_file():
                return json.loads(candidate.read_text())
        except Exception:
            continue
    return None


def _print_request(prepared: PreparedRequest, *, show_body: bool = True) -> None:
    print(prepared.describe(max_body=200_000 if show_body else 0))


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv[0] if argv else "help"

    if command in ("help", "-h", "--help"):
        print(__doc__)
        return 0

    if command == "verify":
        return cmd_verify()

    if command == "selftest":
        return cmd_selftest()

    if command == "fingerprint":
        print("fingerprintId :", current_fingerprint_id())
        print("payload       :", json.dumps(fingerprint_payload(), indent=1))
        return 0

    if command == "login":
        interval = int(argv[argv.index("--interval") + 1]) if "--interval" in argv else LOGIN_POLL_INTERVAL_MS
        state: dict[str, Any] = {}

        def on_code(result: LoginResult) -> None:
            print(f"Buka URL ini di browser:\n\n    {result.login_url}\n")
            print(f"fingerprintId   : {result.fingerprint_id}")
            print(f"fingerprintHash : {result.fingerprint_hash}")
            print(f"kedaluwarsa     : {result.expires_at}")
            print("\nMenunggu otorisasi...")

        def on_poll(attempts: int, status: int) -> None:
            print(f"  poll #{attempts}: HTTP {status}" + (" (menunggu)" if status == 401 else ""))

        result = login_flow(interval_ms=interval, on_code=on_code, on_poll=on_poll)
        state["result"] = result
        if result.status != "success":
            print(f"login gagal: {result.status} {result.error or ''}")
            return 1
        user = result.user or {}
        print(f"\nLogin sukses: {user.get('name')} <{user.get('email')}>")
        print(f"credentials   : {credentials_path()}")
        print(f"device key    : {result.device_key_id or '(gagal/tidak perlu)'}")
        return 0

    if command == "logout":
        creds_now = Credentials.load()
        raw = json.loads(credentials_path().read_text()).get("default", {})
        fp_id = raw.get("fingerprintId") or current_fingerprint_id()
        fp_hash = raw.get("fingerprintHash") or ""
        resp = ApiClient().send(
            build_logout_request(creds_now.token, user_id=creds_now.user_id, fingerprint_id=fp_id, fingerprint_hash=fp_hash)
        )
        print("logout server:", resp.status_code, resp.text[:200])
        print("kredensial lokal dihapus:", clear_credentials())
        return 0

    if command == "plan":
        print("Urutan request free mode (dari capture #36..#59):")
        for index, step in enumerate(chat_sequence_plan(), 1):
            print(f"  {index}. {step}")
        return 0

    if command == "run":
        prompt = argv[argv.index("--prompt") + 1] if "--prompt" in argv else "hi"
        confirm = "--confirm" in argv
        if not confirm:
            plan = chat_sequence_plan()
            print("DRY RUN (tambah --confirm untuk benar-benar mengirim):")
            for index, step in enumerate(plan, 1):
                print(f"  {index}. {step}")
            print(f"\n  prompt: {prompt!r}")
            print("  PERINGATAN: chat dari klien non-resmi berisiko strike pada akun.")
            return 0
        result = run_freebuff_session(prompt=prompt, confirm=True, on_delta=lambda chunk: print(chunk, end="", flush=True))
        print()
        print(f"instance={result.instance_id} validate={result.validate_status} run={result.run_id}")
        print(f"chat={result.chat_status} finish={result.finish_status}")
        if result.chat_error:
            print("error:", result.chat_error)
        return 0 if result.chat_status == 200 else 1

    if command == "environ":
        env = ClientEnv.detect()
        print("x-freebuff-env :", env.to_header())
        tz = timezone_header()
        print("x-fb-timezone  :", tz.get(H_TIMEZONE, "(tidak dikirim)"))
        print("api host       :", api_host())
        print("freebuff host  :", freebuff_host())
        print("project key    :", project_key())
        print("device key     :", device_key_path(), "->",
              "ada" if device_key_path().is_file() else "belum ada")
        return 0

    creds = Credentials.load()
    store = DeviceKeyStore()
    settings = load_settings()
    model_key = settings.get("freebuffModelKey", "m-61c26317cc")

    if command == "build":
        what = argv[1] if len(argv) > 1 else "session"
        prompt = None
        if "--prompt" in argv:
            prompt = argv[argv.index("--prompt") + 1]
        catalog_data = _load_catalog()
        if what == "session":
            _print_request(
                build_session_request(
                    "POST",
                    SessionParams(token=creds.token, instance_id=new_instance_id(), model=model_key, user_id=creds.user_id, catalog_data=catalog_data),
                    store,
                )
            )
        elif what == "heartbeat":
            _print_request(
                build_session_request(
                    "GET",
                    SessionParams(token=creds.token, instance_id=new_instance_id(), model=model_key, user_id=creds.user_id, catalog_data=catalog_data),
                    store,
                )
            )
        elif what == "catalog":
            _print_request(build_catalog_request(creds.token, store))
        elif what == "chat":
            catalog = _load_catalog()
            ref = CatalogRef.from_catalog(catalog)
            instance = new_instance_id()
            prepared = build_chat_request(
                token=creds.token,
                store=store,
                model=resolve_model(catalog, model_key),
                messages=build_chat_messages(system_prompt=default_system_prompt(), user_text=prompt or "ping"),
                tools=default_tools(),
                run_id=str(uuid.uuid4()),
                client_id=nanoid(),
                user_id=creds.user_id,
                catalog=ref,
                codebuff_metadata_extra={**instance_metadata(instance), **input_profile_metadata(InputProfile.from_prompt(prompt or "ping"))},
            )
            _print_request(prepared, show_body="--body" in argv)
        elif what == "agent-start":
            _print_request(build_agent_run_start(creds.token, agent_id=FREE_AGENT_ID, user_id=creds.user_id))
        elif what == "agent-finish":
            _print_request(
                build_agent_run_finish(creds.token, run_id=argv[argv.index("--run") + 1] if "--run" in argv else str(uuid.uuid4()), status="completed", total_steps=1, user_id=creds.user_id)
            )
        elif what == "logs":
            record = build_log_record(event="cli.app_launched", data={"version": CLI_VERSION}, client_session_id=load_analytics_id())
            _print_request(build_logs_request(creds.token, [record], include_auth=False))
        elif what == "ads":
            _print_request(
                build_ads_request(creds.token, session_id=str(uuid.uuid4()), placement_id="CLI-Intent")
            )
        elif what == "ads-sponsored":
            _print_request(
                build_ads_request(creds.token, session_id=str(uuid.uuid4()), provider="gravity", placement_id="Above-Input-CLI", use_freebuff_host=True, capability_inspection={"status": "unavailable", "reason": "no_git_repository"})
            )
        elif what == "streak":
            _print_request(build_streak_request(creds.token))
        elif what == "me":
            _print_request(build_me_request(creds.token))
        elif what == "profile":
            _print_request(build_project_profile_request(creds.token, user_id=creds.user_id))
        elif what == "surveys":
            _print_request(build_profile_survey_request(creds.token))
            _print_request(build_sponsored_survey_request(creds.token))
        elif what == "posthog":
            _print_request(
                build_posthog_batch(
                    [
                        {
                            "distinct_id": load_analytics_id() or "",
                            "event": "cli.app_launched",
                            "properties": {"version": CLI_VERSION, "platform": "linux"},
                        }
                    ]
                )
            )
        else:
            print(f"tidak dikenal: {what}")
            return 2
        return 0

    if command == "send":
        what = argv[1] if len(argv) > 1 else "streak"
        client = ApiClient()
        if what == "catalog":
            prepared = build_catalog_request(creds.token, store)
        elif what == "session":
            prepared = build_session_request("POST", SessionParams(token=creds.token, instance_id=new_instance_id(), model=model_key, user_id=creds.user_id), store)
        elif what == "streak":
            prepared = build_streak_request(creds.token)
        elif what == "me":
            prepared = build_me_request(creds.token)
        else:
            print(f"tidak dikenal: {what}")
            return 2
        print(prepared.describe())
        status, data = client.send_json(prepared)
        print(f"\n-> HTTP {status}")
        print(json.dumps(data, indent=1)[:4000] if not isinstance(data, str) else data[:4000])
        return 0

    print(__doc__)
    return 0




# ---------------------------------------------------------------------------
# 19. Selftest: cocokkan setiap builder dengan capture Reqable
# ---------------------------------------------------------------------------

# Set header (tanpa header transport) dari capture, per record
EXPECTED_HEADERS = {
    # #11 GET /api/v1/freebuff/session (heartbeat)
    "session_get": {
        "Authorization", "x-fb-timezone", "x-freebuff-env", "x-freebuff-client-version",
        "x-freebuff-multi-session", "x-freebuff-purchase-continuity", "x-freebuff-heartbeat",
        "x-freebuff-include-unused-rate-limits", "x-freebuff-catalog-protocol",
        "x-freebuff-catalog-fetch", "x-freebuff-instance-id", "x-freebuff-device-key",
        "x-freebuff-device-ts", "x-freebuff-device-sig",
    },
    # #16 POST /api/v1/freebuff/session/admission
    "session_post": {
        "Authorization", "x-fb-timezone", "x-freebuff-env", "x-freebuff-client-version",
        "x-freebuff-multi-session", "x-freebuff-purchase-continuity",
        "x-freebuff-desktop-attempt-id", "x-freebuff-catalog-protocol",
        "x-freebuff-catalog-fetch", "x-freebuff-instance-id", "x-freebuff-model",
        "x-freebuff-wallet-spend-limit", "x-freebuff-device-key", "x-freebuff-device-ts",
        "x-freebuff-device-sig",
    },
    # #17 POST /api/agents/validate
    "agents_validate": {"Authorization", "Content-Type"},
    # #21 POST /api/v1/agent-runs
    "agent_runs": {"Authorization", "x-freebuff-acting-user-id"},
    # #3 POST /api/logs
    "logs": {"Content-Type"},
}


def _compare_validate_with_capture() -> tuple[bool, str]:
    """Bangun ulang body /api/agents/validate dari capture lalu bandingkan byte."""
    if not REQABLE_TMP.is_dir():
        return True, "capture tidak ada (dilewati)"
    candidates = [
        path for path in REQABLE_TMP.iterdir()
        if path.is_file() and path.stat().st_size == 953100
    ]
    if not candidates:
        return True, "body capture tidak ada (dilewati)"
    path = max(candidates, key=lambda item: item.stat().st_mtime)
    raw = path.read_bytes()
    captured = json.loads(raw)
    free = next((d for d in captured["agentDefinitions"] if d.get("id") == FREE_AGENT_ID), None)
    if free is None:
        return False, "definisi free agent tidak ada di capture"
    fake_catalog = {
        "rows": [
            {
                "key": "m-capture",
                "handle": free["model"],
                "displayName": free["displayName"].replace("Buffy on ", ""),
                "opensAt": 0,
            }
        ]
    }
    prepared = build_free_agent_validate_request("dummy", fake_catalog, model_key="m-capture")
    if prepared.body == raw:
        return True, f"{len(raw)} byte identik"
    return False, f"beda {len(prepared.body)} vs {len(raw)} byte"


def _report(name: str, ok: bool, detail: str = "") -> bool:
    print(f"   [{'OK  ' if ok else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")
    return ok


def cmd_selftest() -> int:
    """Uji semua builder terhadap capture Reqable (tanpa mengubah state server)."""
    results: list[bool] = []
    creds = Credentials.load()
    store = DeviceKeyStore()
    catalog = _load_catalog()
    ref = CatalogRef.from_catalog(catalog)
    instance = new_instance_id()

    print("== header builder vs capture")
    session_get = build_session_request(
        "GET",
        SessionParams(token=creds.token, instance_id=instance, model=creds.user_id and "m-61c26317cc", user_id=creds.user_id, catalog=ref, catalog_data=catalog),
        store,
    )
    results.append(_report("session GET (#11)", set(session_get.headers) == EXPECTED_HEADERS["session_get"],
                           str(sorted(set(session_get.headers) ^ EXPECTED_HEADERS["session_get"]) or "")))

    session_post = build_session_request(
        "POST",
        SessionParams(token=creds.token, instance_id=instance, model="m-61c26317cc", user_id=creds.user_id, catalog=ref, catalog_data=catalog),
        store,
    )
    results.append(_report("session POST (#16)", set(session_post.headers) == EXPECTED_HEADERS["session_post"],
                           str(sorted(set(session_post.headers) ^ EXPECTED_HEADERS["session_post"]) or "")))
    results.append(_report("model POST = handle fbm1.*", session_post.headers.get(H_MODEL, "").startswith(CATALOG_PREFIX),
                           session_post.headers.get(H_MODEL, "")[:20]))

    validate = build_agents_validate_request(creds.token, [{"id": "x"}])
    results.append(_report("agents/validate (#17)", set(validate.headers) == EXPECTED_HEADERS["agents_validate"]))

    start = build_agent_run_start(creds.token, agent_id="base2", user_id=creds.user_id)
    results.append(_report("agent-runs START (#21)", set(start.headers) == EXPECTED_HEADERS["agent_runs"]))

    logs = build_logs_request(creds.token, [build_log_record(event="cli.app_launched")], include_auth=False)
    results.append(_report("logs batch (#3)", set(logs.headers) == EXPECTED_HEADERS["logs"]))

    print("\n== payload")
    chat = build_chat_request(
        token=creds.token, store=store, model=resolve_model(catalog, "m-61c26317cc"),
        messages=build_chat_messages(system_prompt=default_system_prompt(), user_text="ping"),
        tools=default_tools(), run_id=str(uuid.uuid4()), client_id=nanoid(),
        user_id=creds.user_id, catalog=ref,
        codebuff_metadata_extra={**instance_metadata(instance), **input_profile_metadata(InputProfile.from_prompt("ping"))},
    )
    body = chat.body_json()
    results.append(_report("urutan key chat", list(body) == [
        "model", "codebuff_metadata", "provider", "messages", "tools", "tool_choice", "stream"], str(list(body))))
    results.append(_report("model chat = fbm1 handle", str(body["model"]).startswith(CATALOG_PREFIX)))
    results.append(_report("16 tool schema", len(body["tools"]) == 16, str(len(body["tools"]))))
    results.append(_report("provider data_collection=deny", body["provider"] == {"data_collection": "deny"}))
    sig_headers = {k: v for k, v in chat.headers.items() if k.startswith("x-freebuff-device")}
    results.append(_report("tanda tangan body chat valid", DeviceKeyStore.verify(
        store.load(),
        device_canonical_string("POST", P_CHAT, int(chat.headers[H_DEVICE_TS]), chat.body,
                                chat.headers.get(H_CATALOG_FETCH)),
        chat.headers[H_DEVICE_SIG],
    )))

    print("\n== env/profile header")
    env = ClientEnv.detect().to_header()
    results.append(_report("format x-freebuff-env", bool(re.match(
        r"^v1;in=\d+;out=\d+;tp=none;term=[01];ct=[01];sz=\d+x\d+;ci=\d+;ssh=[01];l=\d+;p=\w+;g=\w+;osc=\w+;tzo=-?\d+;px=\w+;tls=[01];ca=[01];cde=\w+$",
        env)), env))
    profile = InputProfile.from_prompt("hello world").to_header()
    results.append(_report("format x-freebuff-input-profile", profile.startswith("v1;tc=") and ";cps=" in profile, profile))

    print("\n== login / fingerprint (#289)")
    fp = current_fingerprint_id()
    results.append(_report("fingerprintId enhanced-<43 char>",
                           bool(re.fullmatch(r"enhanced-[A-Za-z0-9_-]{43}", fp)), fp[:28] + "..."))
    results.append(_report("payload fingerprint v2.0",
                           set(fingerprint_payload()) == {"system", "cpu", "os", "runtime", "network", "machineId", "fingerprintVersion"}))
    code_req = build_login_code_request(fp)
    results.append(_report("POST /api/auth/cli/code", code_req.method == "POST"
                           and code_req.url == "https://freebuff.com/api/auth/cli/code"
                           and list(code_req.body_json()) == ["fingerprintId"]))

    print("\n== request yang dulu hilang: /api/agents/validate")
    ok_validate, detail = _compare_validate_with_capture()
    results.append(_report("agents/validate byte-identik dgn capture", ok_validate, detail))

    print("\n== verifikasi capture (tanda tangan asli)")
    results.append(_report("Ed25519 atas body capture #23", cmd_verify() == 0))

    ok = all(results)
    print(f"\nRINGKASAN: {sum(results)}/{len(results)} lulus")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# 20. Agen free mode + /api/agents/validate (request yang WAJIB ada)
# ---------------------------------------------------------------------------
#
# Temuan dari capture baru (18 Nov 2026, chat 200 tanpa strike):
# urutan sesi yang berhasil adalah
#
#   #36 GET  /api/v1/freebuff/models            (menerbitkan fetchId)
#   #37 GET  /api/v1/freebuff/session           (heartbeat, X-instance-id)
#   #39 POST /api/v1/freebuff/session/admission (x-freebuff-model = handle)
#   #50 POST /api/agents/validate               (120 definisi, TERMASUK
#                                                base3-free-catalog dengan
#                                                model = handle fbm1.*)
#   #53 GET  /api/v1/freebuff/session           (heartbeat)
#   #56 POST /api/v1/agent-runs                 (START base3-free-catalog)
#   #58 POST /api/v1/chat/completions           (codebuff_metadata.run_id)
#   #59 GET  /api/v1/project-profile
#
# Tanpa langkah /api/agents/validate itu, server tidak punya ikatan
# (agent, model-handle) untuk token ini dan chat ditolak dengan
# 409 freebuff_catalog_stale / 403 free_mode_invalid_agent_model /
# 403 third_party_client_warning (strike). Itulah "request yang hilang".

FREE_AGENT_DEFINITIONS_FILE = "freebuff_agent_definitions.json"


def load_agent_definitions() -> list[dict[str, Any]]:
    """120 definisi agen yang dikirim ke /api/agents/validate (dari bundle/capture)."""
    path = _find_asset(FREE_AGENT_DEFINITIONS_FILE)
    if not path:
        raise SystemExit(f"{FREE_AGENT_DEFINITIONS_FILE} tidak ditemukan")
    return json.loads(path.read_text())


def free_agent_definition(
    catalog: Mapping[str, Any] | None,
    definitions: Sequence[Mapping[str, Any]] | None = None,
    *,
    model_key: str | None = None,
) -> dict[str, Any]:
    """HkA(row): definisi `base3-free-catalog` dengan model = handle katalog.

    Nama tampilan menjadi `Buffy on <displayName>`; itulah pasangan
    (agentId, model) yang dipakai START + chat.
    """
    definitions = list(definitions or load_agent_definitions())
    key = model_key or (catalog or {}).get("recommendedKey") or "m-61c26317cc"
    row = catalog_row(catalog, key)
    if row is None:
        raise SystemExit(f"model {key} tidak ada di katalog")
    handle = row.get("handle")
    if not handle:
        raise SystemExit("katalog tidak memuat handle fbm1.* untuk model ini")
    base = next((d for d in definitions if d.get("id") == FREE_AGENT_ID), None)
    if base is None:
        raise SystemExit(f"definisi {FREE_AGENT_ID} tidak ada di {FREE_AGENT_DEFINITIONS_FILE}")
    definition = copy.deepcopy(dict(base))
    definition["model"] = handle
    definition["displayName"] = f"Buffy on {row.get('displayName', key)}"
    return definition


def build_free_agent_definitions(
    catalog: Mapping[str, Any] | None,
    definitions: Sequence[Mapping[str, Any]] | None = None,
    *,
    model_key: str | None = None,
) -> list[dict[str, Any]]:
    """Semua 120 definisi dengan `base3-free-catalog` sudah diikat ke handle katalog."""
    base_list = [copy.deepcopy(dict(d)) for d in (definitions or load_agent_definitions())]
    free = free_agent_definition(catalog, base_list, model_key=model_key)
    for index, item in enumerate(base_list):
        if item.get("id") == FREE_AGENT_ID:
            base_list[index] = free
            break
    else:
        base_list.append(free)
    return base_list


def build_free_agent_validate_request(
    token: str | None,
    catalog: Mapping[str, Any] | None,
    *,
    model_key: str | None = None,
    definitions: Sequence[Mapping[str, Any]] | None = None,
) -> PreparedRequest:
    """POST /api/agents/validate dengan definisi free agent yang benar."""
    return build_agents_validate_request(
        token,
        build_free_agent_definitions(catalog, definitions, model_key=model_key),
    )


@dataclass
class FreeSessionResult:
    """Hasil satu sesi free mode (semua langkah, apa pun statusnya)."""

    catalog: Mapping[str, Any] | None = None
    instance_id: str | None = None
    admission: Mapping[str, Any] | None = None
    validate_status: int | None = None
    run_id: str | None = None
    chat_status: int | None = None
    chat_text: str = ""
    chat_error: str | None = None
    usage: Mapping[str, Any] | None = None
    finish_status: int | None = None


def run_freebuff_session(
    *,
    prompt: str,
    model_key: str | None = None,
    cwd: str | Path | None = None,
    client: "ApiClient" | None = None,
    timeout: float = 120.0,
    confirm: bool = False,
    on_delta=None,
    max_attempts: int = 2,
    takeover: bool = True,
) -> FreeSessionResult:
    """Jalankan urutan lengkap free mode sampai chat.

    confirm=False -> hanya menyiapkan (dry run): mengembalikan result dengan
    semua request yang AKAN dikirim, tanpa memanggil jaringan.

    PERINGATAN: mengirim chat dari klien non-resmi berisiko strike pada akun.
    """
    creds = Credentials.load()
    store = DeviceKeyStore()
    client = client or ApiClient(timeout=timeout)
    model_key = model_key or load_settings().get("freebuffModelKey") or "m-61c26317cc"
    result = FreeSessionResult()

    if not confirm:
        result.catalog = _load_catalog()
        result.instance_id = new_instance_id()
        return result

    # 1. katalog (selalu segar)
    status, catalog = client.send_json(build_catalog_request(creds.token, store))
    result.catalog = catalog if isinstance(catalog, dict) else None
    if not result.catalog:
        raise SystemExit(f"katalog gagal (HTTP {status})")
    ref = CatalogRef.from_catalog(result.catalog)
    instance = new_instance_id()
    result.instance_id = instance
    params = SessionParams(
        token=creds.token,
        instance_id=instance,
        model=model_key,
        catalog=ref,
        catalog_data=result.catalog,
        user_id=creds.user_id,
    )

    # 2. heartbeat GET /session (dilakukan CLI sebelum admission)
    client.send_json(build_session_request("GET", params, store))

    # 3. admission (x-freebuff-model = handle)
    status, payload = client.send_json(build_session_request("POST", params, store))
    result.admission = payload if isinstance(payload, dict) else None
    admission = result.admission or {}

    # 3b. slot sesi cuma 1 (slotLimit) -> 409 purchase_capacity berisi
    #     currentInstanceId milik instance lain; ambil alih bila diizinkan.
    if admission.get("status") != "active" and takeover and admission.get("currentInstanceId"):
        takeover_params = SessionParams(
            token=creds.token,
            instance_id=instance,
            model=model_key,
            catalog=ref,
            catalog_data=result.catalog,
            user_id=creds.user_id,
            takeover_instance_id=admission["currentInstanceId"],
        )
        status, payload = client.send_json(build_session_request("POST", takeover_params, store))
        result.admission = payload if isinstance(payload, dict) else None
        admission = result.admission or {}
        params = takeover_params

    if admission.get("status") != "active":
        result.chat_error = (
            "admission tidak aktif: "
            f"{admission.get('status')} (currentInstanceId={admission.get('currentInstanceId')}). "
            "Slot free mode cuma satu; tutup sesi lain atau pakai takeover=True."
        )
        result.chat_status = None
        result.finish_status = None
        return result

    # 4. WAJIB: /api/agents/validate dengan base3-free-catalog -> handle
    status, payload = client.send_json(
        build_free_agent_validate_request(creds.token, result.catalog, model_key=model_key)
    )
    result.validate_status = status
    if status >= 400:
        result.chat_error = f"agents/validate HTTP {status}: {str(payload)[:300]}"
        return result

    # 5-7. heartbeat -> START run -> chat; 428/410 = sesi berakhir, ulangi
    #      dengan admission baru (CLI: "send your message again").
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            instance = new_instance_id()
            result.instance_id = instance
            params = SessionParams(
                token=creds.token,
                instance_id=instance,
                model=model_key,
                catalog=ref,
                catalog_data=result.catalog,
                user_id=creds.user_id,
            )
            client.send_json(build_session_request("GET", params, store))
            _, retry_payload = client.send_json(build_session_request("POST", params, store))
            retry_state = retry_payload if isinstance(retry_payload, dict) else {}
            if retry_state.get("status") != "active" and takeover and retry_state.get("currentInstanceId"):
                params.takeover_instance_id = retry_state["currentInstanceId"]
                _, retry_payload = client.send_json(build_session_request("POST", params, store))
                retry_state = retry_payload if isinstance(retry_payload, dict) else {}
            result.admission = retry_state
            if retry_state.get("status") != "active":
                result.chat_error = f"admission ulang gagal: {retry_state.get('status')}"
                return result

        # heartbeat lagi (CLI melakukannya sebelum run)
        client.send_json(build_session_request("GET", params, store))

        # START run untuk agen free mode
        status, data = client.send_json(
            build_agent_run_start(creds.token, agent_id=FREE_AGENT_ID, user_id=creds.user_id)
        )
        run_id = (data or {}).get("runId") if isinstance(data, dict) else None
        result.run_id = run_id
        if not run_id:
            result.chat_error = f"agent-runs START gagal: {status} {str(data)[:200]}"
            return result

        prepared = build_chat_request(
            token=creds.token,
            store=store,
            model=resolve_model(result.catalog, model_key),
            messages=build_chat_messages(system_prompt=default_system_prompt(), user_text=prompt),
            tools=default_tools(),
            run_id=run_id,
            client_id=nanoid(),
            user_id=creds.user_id,
            catalog=ref,
            codebuff_metadata_extra={
                **instance_metadata(instance),
                **input_profile_metadata(InputProfile.from_prompt(prompt)),
                "trace_session_id": str(uuid.uuid4()),
                "repo_snapshot": json.dumps(repo_snapshot(cwd), separators=(",", ":")),
                "compaction_version": "summary-v1",
                "compaction_root_model": resolve_model(result.catalog, model_key),
                "compaction_root_version": "summary-v1",
                "compaction_root_run_id": run_id,
                "compaction_request_id": str(uuid.uuid4()),
                "compaction_request_group": "other",
                "llm_step_number": "1",
            },
        )
        response = client.send(prepared, stream=True)
        result.chat_status = response.status_code
        if response.status_code != 200:
            body = response.text[:500]
            result.chat_error = body
            if response.status_code in (410, 428) and attempt < max_attempts:
                continue  # sesi berakhir -> admission baru lalu coba lagi
            break

        chunks: list[str] = []
        for line in response.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                event = json.loads(payload)
            except Exception:
                continue
            if event.get("usage"):
                result.usage = event["usage"]
            delta = ((event.get("choices") or [{}])[0].get("delta") or {}).get("content")
            if delta:
                chunks.append(delta)
                if on_delta:
                    on_delta(delta)
        result.chat_text = "".join(chunks)
        result.chat_error = None
        break

    # 8. FINISH
    status, _ = client.send_json(
        build_agent_run_finish(
            creds.token,
            run_id=run_id,
            status="completed" if result.chat_status == 200 else "failed",
            total_steps=1,
            user_id=creds.user_id,
        )
    )
    result.finish_status = status
    return result


def repo_snapshot(cwd: str | Path | None = None, *, limit: int = 4000) -> dict[str, Any]:
    """/repo_snapshot di codebuff_metadata (bentuk sama seperti capture)."""
    base = Path(cwd or os.getcwd())
    has_git = (base / ".git").exists()
    files = 0
    tests = 0
    try:
        for index, entry in enumerate(base.rglob("*")):
            if index > limit:
                break
            if not entry.is_file():
                continue
            name = entry.name
            if name.endswith((".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java", ".rb", ".php", ".c", ".h", ".cpp")):
                files += 1
                if "test" in str(entry).lower() or "spec" in name.lower():
                    tests += 1
    except Exception:
        pass
    return {
        "gitAvailable": has_git,
        "repositoryVisibility": "unknown",
        "fileCount": files,
        "fileCountIsLowerBound": False,
        "testFileCount": tests,
        "changedFileCount": 0,
        "changedFileScanTruncated": False,
    }



# ---------------------------------------------------------------------------
# 21. Login flow (capture #288..#305): fingerprint -> code -> poll -> token
# ---------------------------------------------------------------------------
#
#   POST https://freebuff.com/api/auth/cli/code        {"fingerprintId":...}
#     -> {fingerprintId, fingerprintHash, loginUrl, expiresAt, expiresInMs}
#   GET  https://freebuff.com/api/auth/cli/status?fingerprintId&fingerprintHash&expiresAt
#     -> 401 {"error":"Authentication failed"} saat masih menunggu
#     -> 200 {user:{id,name,email,authToken,fingerprintId,fingerprintHash},
#             message:"Authentication successful!"}
#   POST /api/v1/freebuff/device-keys  {"publicKey":..., "client":"cli"}
#   User-Agent di ketiga request: "Bun/1.3.14" (fetch bawaan Bun).

UA_BUN = "Bun/1.3.14"
LOGIN_POLL_INTERVAL_MS = 5000
LOGIN_POLL_TIMEOUT_MS = 3_600_000
FINGERPRINT_VERSION = "2.0"


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text().strip()
    except Exception:
        return ""


def machine_id() -> str:
    """WsL(): systeminformation.machineId() -> /etc/machine-id."""
    for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        value = _read_text(candidate)
        if value and len(value) >= 8:
            return value
    raise SystemExit("machine id tidak terbaca (/etc/machine-id)")


def system_info() -> dict[str, str]:
    """zsL().system: manufacturer/model/serial/uuid dari DMI."""
    dmi = "/sys/class/dmi/id"
    return {
        "manufacturer": _read_text(f"{dmi}/sys_vendor"),
        "model": _read_text(f"{dmi}/product_name"),
        "serial": _read_text(f"{dmi}/product_serial"),
        "uuid": _read_text(f"{dmi}/product_uuid"),
    }


def cpu_info() -> dict[str, Any]:
    """zsL().cpu: manufacturer/brand/cores/physicalCores."""
    vendor = brand = ""
    cores = 0
    physical: set[tuple[str, str]] = set()
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("vendor_id") and not vendor:
                vendor = line.split(":", 1)[1].strip()
            elif line.startswith("model name") and not brand:
                brand = line.split(":", 1)[1].strip()
            elif line.startswith("processor"):
                cores += 1
            elif line.startswith("physical id"):
                physical.add(("id", line.split(":", 1)[1].strip()))
            elif line.startswith("core id"):
                physical.add(("core", line.split(":", 1)[1].strip()))
    except Exception:
        cores = os.cpu_count() or 0
    return {
        "manufacturer": vendor,
        "brand": brand,
        "cores": cores or (os.cpu_count() or 0),
        "physicalCores": len({p for p in physical if p[0] == "core"}) or 0,
    }


def os_info() -> dict[str, str]:
    """zsL().os: platform/distro/arch/hostname."""
    distro = ""
    for line in _read_text("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            distro = line.split("=", 1)[1].strip().strip('"')
            break
    machine = platform.machine().lower()
    return {
        "platform": platform.system().lower(),
        "distro": distro,
        "arch": "x64" if machine in ("x86_64", "amd64") else ("arm64" if machine in ("aarch64", "arm64") else machine),
        "hostname": socket.gethostname(),
    }


def shell_name() -> str:
    """g1$(): shell dari $SHELL."""
    return Path(os.environ.get("SHELL") or "/bin/sh").name


def mac_addresses() -> list[str]:
    """ZsL(): MAC non-internal, diurutkan (capture memakai urutan sort)."""
    macs: list[str] = []
    base = Path("/sys/class/net")
    try:
        for iface in base.iterdir():
            if iface.name == "lo":
                continue
            mac = _read_text(str(iface / "address"))
            if mac and mac != "00:00:00:00:00:00" and mac not in macs:
                macs.append(mac)
    except Exception:
        pass
    return sorted(macs)


def interface_count() -> int:
    try:
        return len([item for item in Path("/sys/class/net").iterdir()])
    except Exception:
        return 0


def fingerprint_payload() -> dict[str, Any]:
    """Objek yang di-hash menjadi fingerprintId (wsL())."""
    return {
        "system": system_info(),
        "cpu": cpu_info(),
        "os": os_info(),
        "runtime": {
            "nodeVersion": FINGERPRINT_NODE_VERSION,
            "platform": "linux",
            "arch": "x64",
            "shell": shell_name(),
            "cpuCount": os.cpu_count() or 0,
        },
        "network": {
            "macAddresses": mac_addresses(),
            "interfaceCount": interface_count(),
        },
        "machineId": machine_id(),
        "fingerprintVersion": FINGERPRINT_VERSION,
    }


def enhanced_fingerprint_id() -> str:
    """wsL(): "enhanced-" + base64url(sha256(JSON.stringify(payload)))."""
    payload = json_bytes(fingerprint_payload())
    return "enhanced-" + _b64url(hashlib.sha256(payload).digest())


def legacy_fingerprint_id() -> str:
    """NsL(): "codebuff-cli-<8 char base64url acak>" (fallback bila enhanced gagal)."""
    return "codebuff-cli-" + _b64url(secrets.token_bytes(6))[:8]


def current_fingerprint_id() -> str:
    """zW(): enhanced fingerprint, fallback ke legacy."""
    try:
        return enhanced_fingerprint_id()
    except Exception:
        return legacy_fingerprint_id()


# nodeVersion yang dicatat binary saat fingerprint dibuat (runtime Bun 1.3.14)
FINGERPRINT_NODE_VERSION = "v22.6.0"


def build_login_code_request(fingerprint_id: str | None = None) -> PreparedRequest:
    """loginCode(): POST {freebuff}/api/auth/cli/code {fingerprintId}."""
    body = json_bytes({"fingerprintId": fingerprint_id or current_fingerprint_id()})
    return PreparedRequest(
        "POST",
        _abs(freebuff_host(), P_AUTH_CODE),
        {"Content-Type": "application/json", H_USER_AGENT: UA_BUN},
        body,
    )


def build_login_status_request(
    fingerprint_id: str,
    fingerprint_hash: str,
    expires_at: int,
) -> PreparedRequest:
    """loginStatus(): GET {freebuff}/api/auth/cli/status?fingerprintId&fingerprintHash&expiresAt."""
    query = urlencode(
        {
            "fingerprintId": fingerprint_id,
            "fingerprintHash": fingerprint_hash,
            "expiresAt": int(expires_at),
        },
        quote_via=quote,
        safe="",
    )
    return PreparedRequest(
        "GET",
        f"{freebuff_host()}{P_AUTH_STATUS}?{query}",
        {H_USER_AGENT: UA_BUN},
        None,
    )


def build_logout_request(
    token: str,
    *,
    user_id: str | None,
    fingerprint_id: str,
    fingerprint_hash: str,
) -> PreparedRequest:
    """logout(): POST {freebuff}/api/auth/cli/logout {userId,fingerprintId,fingerprintHash}."""
    body = json_bytes(
        {
            "userId": user_id,
            "fingerprintId": fingerprint_id,
            "fingerprintHash": fingerprint_hash,
        }
    )
    return PreparedRequest(
        "POST",
        _abs(freebuff_host(), P_AUTH_LOGOUT),
        {
            "Content-Type": "application/json",
            H_USER_AGENT: UA_BUN,
            H_AUTH: f"Bearer {token}",
        },
        body,
    )


# ---------------------------------------------------------------------------
# 22. Penyimpanan kredensial (credentials.json + keychain Bun.secrets)
# ---------------------------------------------------------------------------

def keychain_store(token: str, path: Path | None = None) -> bool:
    """Bun.secrets.set(): tulis token ke libsecret (service freebuff-cli)."""
    import shutil
    import subprocess

    if not shutil.which("secret-tool"):
        return False
    account = str(path or credentials_path())
    label = f"{KEYCHAIN_SERVICE}/{account}"
    try:
        result = subprocess.run(
            ["secret-tool", "store", f"--label={label}", "service", KEYCHAIN_SERVICE, "account", account],
            input=token,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return False
    return result.returncode == 0


def keychain_delete(path: Path | None = None) -> bool:
    import shutil
    import subprocess

    if not shutil.which("secret-tool"):
        return False
    account = str(path or credentials_path())
    try:
        subprocess.run(
            ["secret-tool", "clear", "service", KEYCHAIN_SERVICE, "account", account],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return False
    return True


def save_credentials(
    user: Mapping[str, Any],
    *,
    profile: str = "default",
    use_keychain: bool = True,
) -> Path:
    """Tulis credentials.json ala binary: token ke keychain, sisanya ke file (0600).

    Bentuk file (JSON.stringify(..., null, 2)):
        {"default": {"id","name","email","fingerprintId","fingerprintHash",
                     "tokenStore": "keychain"}}
    """
    path = credentials_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = str(user.get("authToken") or "")
    entry: dict[str, Any] = {
        "id": user.get("id"),
        "name": user.get("name"),
        "email": user.get("email"),
        "fingerprintId": user.get("fingerprintId"),
        "fingerprintHash": user.get("fingerprintHash"),
    }
    stored = False
    if token and use_keychain:
        stored = keychain_store(token, path)
    if not stored and token:
        entry["authToken"] = token  # fallback: token tetap di file
    elif token:
        entry["tokenStore"] = "keychain"

    existing: dict[str, Any] = {}
    if path.is_file():
        try:
            existing = json.loads(path.read_text())
        except Exception:
            existing = {}
    existing[profile] = entry
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(existing, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    os.chmod(path, 0o600)
    return path


def clear_credentials(profile: str = "default") -> bool:
    """Logout lokal: hapus entri profil + token di keychain."""
    path = credentials_path()
    keychain_delete(path)
    try:
        data = json.loads(path.read_text())
    except Exception:
        return False
    data.pop(profile, None)
    if not data:
        path.unlink(missing_ok=True)
        return True
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    return True


# ---------------------------------------------------------------------------
# 23. Orkestrasi login (request code -> poll -> simpan -> daftar device key)
# ---------------------------------------------------------------------------

@dataclass
class LoginResult:
    ok: bool = False
    status: str = "idle"          # success | timeout | aborted | error
    login_url: str | None = None
    fingerprint_id: str | None = None
    fingerprint_hash: str | None = None
    expires_at: int | None = None
    user: Mapping[str, Any] | None = None
    attempts: int = 0
    device_key_id: str | None = None
    error: str | None = None


def login_flow(
    *,
    client: "ApiClient" | None = None,
    fingerprint_id: str | None = None,
    interval_ms: int = LOGIN_POLL_INTERVAL_MS,
    timeout_ms: int = LOGIN_POLL_TIMEOUT_MS,
    on_code=None,
    on_poll=None,
    save: bool = True,
) -> LoginResult:
    """LoginDevice: minta kode, tampilkan loginUrl, polling sampai token terbit.

    on_code(result) dipanggil setelah kode diterbitkan (untuk mencetak URL).
    on_poll(attempts, status) dipanggil tiap percobaan.
    """
    client = client or ApiClient(timeout=30)
    fp = fingerprint_id or current_fingerprint_id()
    result = LoginResult(fingerprint_id=fp)

    status, payload = client.send_json(build_login_code_request(fp))
    if status >= 400 or not isinstance(payload, dict):
        result.status = "error"
        result.error = f"login code HTTP {status}: {str(payload)[:200]}"
        return result
    result.login_url = payload.get("loginUrl")
    result.fingerprint_hash = payload.get("fingerprintHash")
    result.expires_at = payload.get("expiresAt")
    result.fingerprint_id = payload.get("fingerprintId", fp)
    if on_code:
        on_code(result)

    started = time.time() * 1000
    while True:
        if time.time() * 1000 - started >= timeout_ms:
            result.status = "timeout"
            return result
        result.attempts += 1
        status, payload = client.send_json(
            build_login_status_request(result.fingerprint_id or fp, result.fingerprint_hash or "", result.expires_at or 0)
        )
        if on_poll:
            on_poll(result.attempts, status)
        if status == 200 and isinstance(payload, dict) and isinstance(payload.get("user"), dict):
            user = payload["user"]
            result.status = "success"
            result.ok = True
            result.user = user
            if save:
                save_credentials(user)
                store = DeviceKeyStore()
                store.record = None
                try:
                    record = store.ensure()
                    result.device_key_id = store.register(
                        record,
                        DeviceKeyStore.scope_for(api_host(), str(user.get("authToken") or ""), str(user.get("id") or "")),
                        token=str(user.get("authToken") or ""),
                        api_origin=api_host(),
                    )
                except Exception as exc:
                    result.error = f"device key: {exc}"
            return result
        time.sleep(interval_ms / 1000)

if __name__ == "__main__":
    raise SystemExit(main())
