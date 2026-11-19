# Freebuff FastAPI Gateway

Bungkus HTTP di atas `freebuff_requests.py` supaya endpoint Freebuff bisa
dipanggil agen/klien lain lewat API **mirip OpenAI**.

## Menjalankan

```bash
FREEBUFF_GATEWAY_TOKEN=rahasia python3 freebuff_gateway_fastapi.py --port 8000

# pakai slot sesi tertentu
python3 freebuff_gateway_fastapi.py --session-id agen-1 --token rahasia --port 8000

# lihat slot sesi yang tersimpan
python3 freebuff_gateway_fastapi.py --list-sessions
```

Argumen CLI:

| Argumen | Arti |
|---|---|
| `--session-id <id>` | Pakai/ciptakan slot sesi dengan id ini. State disimpan per id di `~/.config/manicode/gateway-sessions/<id>.json`; `trace_session_id` & `client_id` dihitung **deterministik** dari id (id sama -> identitas & sesi sama, walau proses dijalankan ulang). Tanpa argumen ini dipakai `gateway-session.json` tunggal seperti sebelumnya. |
| `--state <path>` | Override path file state (sama dengan env `FREEBUFF_SESSION_STATE`). |
| `--host`, `--port` | Default `127.0.0.1:8000`. |
| `--token` | Bearer token (sama dengan env `FREEBUFF_GATEWAY_TOKEN`). |
| `--list-sessions` | Cetak daftar slot: id, ukuran, instance, status, waktu expiry. |

`GET /healthz` dan `GET /freebuff/session` menampilkan `sessionId` yang aktif.
Env `FREEBUFF_SESSION_ID` setara dengan `--session-id` (berguna untuk uvicorn
langsung: `FREEBUFF_SESSION_ID=agen-1 uvicorn freebuff_gateway_fastapi:app`).

- Kredensial diambil otomatis dari `~/.config/manicode/credentials.json` +
  keychain (`Credentials.load`).
- Jika `FREEBUFF_GATEWAY_TOKEN` kosong, tidak ada auth (hanya untuk local).
- Setiap request chat menjalankan urutan 9 langkah free mode penuh
  (catalog → heartbeat → admission+takeover → agents/validate → heartbeat →
  run START → chat → FINISH) dan mengunci **satu slot sesi** (semaphore) supaya
  tidak ada dua chat bersamaan.

Env opsional: `FREEBUFF_CATALOG_TTL` (default 300 s), `FREEBUFF_TIMEOUT`
(default 180 s), `FREEBUFF_HOST` (default 127.0.0.1), `FREEBUFF_PORT` (8000).

## Endpoint

| Method & path | Keterangan |
|---|---|
| `GET /healthz` | status + akun |
| `GET /v1/models` | daftar model (mirip OpenAI; `recommended`, `handle`, `premium`, `context_window`) |
| `POST /v1/chat/completions` | chat; `stream:true` → SSE, `stream:false` → JSON lengkap. Menerima `tools`/`tool_choice` untuk loop tool-call oleh agen |
| `GET /freebuff/catalog` | katalog mentah (`fetchId`, `version`, `rows`) |
| `GET /freebuff/session` | status admission (otomatis admit/takeover) |
| `GET /freebuff/streak` | streak + freebucks |
| `GET /freebuff/me` | profil akun |
| `GET /freebuff/fingerprint` | fingerprintId + payload (untuk login manual) |
| `POST /freebuff/login/start` | terbitkan `loginUrl` + fingerprintHash |
| `GET /freebuff/login/status` | cek status login; saat sukses otomatis simpan kredensial |

## Contoh klien OpenAI-compatible

```bash
TOKEN=rahasia; BASE=http://127.0.0.1:8000

curl -H "Authorization: Bearer $TOKEN" $BASE/v1/models

curl -N -X POST $BASE/v1/chat/completions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"model":"recommended","stream":true,
       "messages":[{"role":"user","content":"Refactor fungsi ini"}],"tools":null}'
```

Loop tool-call oleh agen: kirim `tools` (skema fungsi), gateway meneruskan
`tool_calls` pada respons; agen mengeksekusi lalu mengirim hasil sebagai
message ber-`role:"tool"` pada request berikutnya (konteks/run dipertahankan
selama sesi admission aktif).

## Klien seperti opencode/OpenHands (penting)

Upstream free mode **menolak** request yang membawa daftar `tools` bukan milik
CLI resmi nilainya `403 third_party_client_warning` (terhitung strike). Karena
itu gateway sekarang:

1. **Selalu** mengirim `tools` resmi CLI ke upstream, apa pun yang dikirim klien.
2. **Menerjemahkan** nama & argumen tool dua arah:

   | CLI (upstream) | nama klien yang dikenali |
   |---|---|
   | `read_files` | `read`, `read_file`, `view_file`, `view` |
   | `write_file` | `write`, `write_file`, `create_file` |
   | `str_replace` | `edit`, `str_replace`, `apply_patch` |
   | `run_terminal_command` | `bash`, `shell`, `run_command`, `execute` |
   | `code_search` | `grep`, `search_code`, `ripgrep` |
   | `glob` | `glob`, `find_files`, `file_search` |
   | `list_directory` | `ls`, `list_dir`, `list_files` |
   | `write_todos` | `todowrite`, `todo_write` |
   | `web_search` | `websearch`, `search_web` |
   | `read_url` | `webfetch`, `fetch_url` |
   | `ask_user` | `question`, `ask_followup_question` |

   Nama argumen juga disesuaikan dengan skema tool klien (`path`/`filePath`,
   `oldString`/`old_string`, `command`/`cmd`, dst). Tool klien yang tidak punya
   padanan dibiarkan dengan nama CLI.
3. **Menggabung** semua pesan `system` dari klien jadi satu system prompt di
   belakang system prompt CLI (Buffy). Ini yang bikin request opencode lolos:
   dua pesan system terpisah tetap diterima, tapi system prompt CLI wajib ada
   (tanpa itu upstream membalas `403 free_mode_cli_required`).
4. **Retry sekali otomatis** saat upstream membalas `409/410/428`
   (`waiting_room_required` = "Your free session has ended. Send your message
   again"): admission + run START dibuat ulang lalu request diulang.

Pesan `role:"tool"` dan `assistant.tool_calls` dikirim dalam bentuk OpenAI
klasik (`tool_call_id` + string `content`), karena upstream hanya menerima part
`text`/`image_url`/`file` (format AI-SDK `tool-call`/`tool-result` ditolak 422).

## Sesi dipakai ulang (jatah sesi tidak habis)

Free mode hanya memberi beberapa sesi (slot) per jaringan/akun, jadi gateway
**tidak** membuka sesi baru tiap request:

- `instanceId` + admission disimpan di `~/.config/manicode/gateway-session.json`
  (mode 0600, bisa diubah lewat `FREEBUFF_SESSION_STATE`). Restart proses
  memakai instance yang sama, bukan mengambil-alih/membuka sesi baru.
- Admission dipakai ulang selama `expiresAt` masih > 2 menit. Bila mendekati
  habis, gateway hanya mengirim **heartbeat** `GET /freebuff/session` (murah,
  memperpanjang sesi) dan baru admission bila sesi benar-benar mati.
- Balasan `409/410/428` tidak lagi membuang sesi: `recover_session()`
  heartbeat dulu, admission baru hanya kalau server bilang sesi berakhir.
- Yang dibuat baru per request hanya **agent-run** (`START`/`FINISH`), sama
  seperti CLI resmi untuk setiap pesan user.
- `POST /freebuff/session/reset` memaksa sesi baru (mis. setelah
  `superseded`); `GET /freebuff/session` menampilkan `instanceId`, `reused`,
  `freebucks`, `statePath`, dan `session` (trace/client/run/step).

### Identitas yang stabil selama satu sesi

Capture CLI menunjukkan metadata berikut **tidak berubah** antar pesan dalam
satu sesi, jadi gateway menyimpannya di state file dan memakainya ulang:

| Field | Perilaku |
|---|---|
| `trace_session_id` | tetap selama sesi (baru hanya saat `reset`) |
| `client_id` | tetap selama sesi |
| `run_id` + `compaction_root_run_id` | satu agent-run untuk seluruh percakapan; `START` dipanggil sekali, `FINISH` tidak per request |
| `repo_snapshot` | diambil sekali di awal sesi, lalu dipakai ulang |
| `llm_step_number` | naik 1 tiap request (1, 2, 3, …) |

Hanya `compaction_request_id` yang baru pada setiap request, sesuai CLI.
Karena `FINISH` per request bisa membuat server **melepas klaim sesi**
(`status: purchase_claim_released`), gateway tidak lagi mengirim `FINISH` tiap
pesan. `FINISH` hanya dikirim lewat `POST /freebuff/session/reset` (dan saat
shutdown bila `FREEBUFF_FINISH_ON_SHUTDOWN=1`).

Status `purchase_claim_released` / `ip_capped` / `rate_limited` sekarang
dibalas `429` dengan pesan + waktu `nextExpiryAt`, bukan error 409 generik.

Env tambahan: `FREEBUFF_SESSION_STATE` (path file state),
`FREEBUFF_HB_INTERVAL` (detik, default 45).

Catatan kuota: tiap obrolan tetap memakan **freebucks** (jendela per jam,
mis. 5 freebucks/jam); habis -> upstream membalas `rate_limited`. Pilih model
non-premium (`m-61c26317cc` dsb) untuk pemakaian hemat.

Jalankan uvicorn **satu worker** (`--workers 1`, default) agar state sesi tidak
dipegang dua proses sekaligus.

## Catatan

- Slot free mode hanya 1. Bila CLI resmi sedang aktif, gateway otomatis
  melakukan **takeover** via `x-freebuff-takeover-instance-id` (sesi CLI akan
  "dilepas").
- `stream` di request chat selalu dikirim `true` ke upstream; untuk `stream:false`
  gateway menggabungkan SSE jadi satu respons dengan `usage`.