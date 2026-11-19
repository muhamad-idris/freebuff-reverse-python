# freebuff CLI — rekonstruksi pembentukan request HTTP (Python)

Sumber analisis:
- `~/.nvm/versions/node/v26.13.0/bin/freebuff` → hanya **wrapper downloader** (`freebuff@0.2.36`: `index.js`, `launcher.js`, `http.js`).
- Program asli: `~/.config/manicode/freebuff` (Bun single-file, 138 MB, **tidak di-strip**).
- Bundle JS polos di-offset `94.535.710` → `/home/tamsis/freebuff/bundle.js` (pretty: `bundle.pretty.js`, 270.451 baris).
- Capture HTTPS Reqable (29 request, `www.codebuff.com` / `freebuff.com` / PostHog).

**Hasil akhir:** semua fungsi pembentuk request sudah dipindahkan ke
`/home/tamsis/freebuff/freebuff_requests.py` dan diverifikasi terhadap capture.

```bash
python3 freebuff_requests.py selftest      # cocokkan semua builder vs capture (14/14)
python3 freebuff_requests.py verify        # bukti tanda tangan Ed25519 byte-exact
python3 freebuff_requests.py environ       # header x-freebuff-env / x-fb-timezone / host
python3 freebuff_requests.py build chat --prompt "halo" [--body]
python3 freebuff_requests.py build session|heartbeat|catalog|logs|ads|ads-sponsored|surveys|profile|posthog|agent-start|agent-finish|streak|me
python3 freebuff_requests.py send catalog|streak|me|session
```

## 1. Yang tadinya tampak "terenkripsi"

| Dugaan | Kenyataan |
|---|---|
| Body dienkripsi | **Tidak.** Body chat = JSON polos ±55 KB (system prompt + 16 tool schema). |
| Nama model diacak | `model` = handle katalog bertanda tangan `fbm1.<base64url>` (bukan enkripsi; server memetakan ke model asli). |
| Request tidak bisa dipalsukan | **Ed25519**: header `x-freebuff-device-sig` menandatangani string kanonik; privat key PKCS#8 di `~/.config/manicode/device-key.json`. |
| Token ada di credentials.json | `{"tokenStore":"keychain"}` → token di **Bun.secrets/libsecret** (`secret-tool lookup service freebuff-cli account <credentials.json>`). |

String kanonik (`qPA`):

```
freebuff-device-v1
<METHOD upper>
<pathname tanpa query>
<timestamp ms>
<sha256hex(body)>        # body kosong -> sha256("")
<fetchId katalog | "">
```

`x-freebuff-device-key` = `keyId` hasil `POST /api/v1/freebuff/device-keys`
(`{publicKey: base64url(raw32), client:"cli"}`), disimpan per-scope
`"<origin> user:<id>"` atau `"<origin> token:<sha256[:32]>"`.

## 2. Peta simbol bundle → fungsi Python

| Simbol JS | Fungsi Python |
|---|---|
| `qPA` | `device_canonical_string` |
| `ERH` / `T2L` | `DeviceKeyStore` (`headers`, `sign_headers`) |
| `X2L` / `bpA` | `DeviceKeyStore.generate` / `.private_object` |
| `fRH` / `U2L` / `cpA` | `_b64url` / `_b64url_decode` / `_sha256_hex` |
| `ipA` | `DeviceKeyRecord` (+ `to_json`) |
| `HxA` | `build_session_request` + `parse_session_response` |
| `ApL` | `build_catalog_request` |
| `HpA` | `catalog_handle` |
| `MQH`/`UQH` | `legacy_model_digest` / `model_id_by_legacy_digest` |
| `b5H` | `build_codebuff_metadata` |
| `ZHH` + ai-sdk | `build_chat_request`, `build_chat_messages` |
| `ltL`/`$RH` + `Fv` | `ClientEnv`, `client_env_header` |
| `stL` + `jpA` | `InputProfile`, `timezone_header` |
| `RpA`/`KpA` | `instance_metadata` / `input_profile_metadata` |
| `tuA` / `QuA` / `CuA` | `build_agent_run_start` / `_finish` / `build_agent_step` |
| `Zw` | `build_agents_validate_request` |
| `O3A` / `Wt` | `build_logs_request` / `build_log_record` |
| `hY` / `IC` / `EY` | `build_ads_request` / `client_device` / `browser_user_agent` |
| `vA$` / `tA$` | `build_profile_survey_request` / `build_sponsored_survey_request` |
| `z2A` | `build_project_profile_request` (+ `project_key`) |
| `xa`/`ca` (`xaL`/`caL`) | `default_client_context` (bentuk sama, nilainya bucket wajar) |
| posthog-node | `build_posthog_batch` |
| `OM`/`LxA` | `api_host` / `freebuff_host` |

## 3. Header (nama kanonik → simbol)

`x-freebuff-client-version` `Q_H` · `x-freebuff-client` `UpA` · `x-freebuff-env` `DpA`
· `x-fb-timezone` `jpA` · `x-freebuff-acting-user-id` `xG` · `x-freebuff-instance-id` `L$A`
· `x-freebuff-model` `_$A` · `x-freebuff-wallet-spend-limit` `f$A` · `x-freebuff-multi-session` `U$A`
· `x-freebuff-purchase-continuity` `PpA` · `x-freebuff-desktop-attempt-id` `JpA`
· `x-freebuff-heartbeat` `J$A` · `x-freebuff-include-unused-rate-limits` `E$A`
· `x-freebuff-compact-session` `M$A` · `x-freebuff-takeover-instance-id` `P$A`
· `x-freebuff-sse-gzip-recovery` `auA` · `x-freebuff-catalog-protocol` `Vs` (`1`)
· `x-freebuff-catalog-fetch` `xs` (`fbf1.*`) · `x-freebuff-device-{key,ts,sig}` `QPA/CPA/FPA`
· `x-openrouter-api-key` `NiH`.

## 4. Per-endpoint (set header terverifikasi dari capture)

| Endpoint | Method | Header |
|---|---|---|
| `/api/v1/freebuff/session/admission` (#16) | POST | auth, timezone, env, client-version, multi-session, purchase-continuity, desktop-attempt-id, instance-id, **model = handle fbm1**, wallet-spend-limit=`session`, catalog-protocol/fetch, device-* |
| `/api/v1/freebuff/session` (#11) | GET | auth, timezone, env, client-version, multi-session, purchase-continuity, **heartbeat=1**, **include-unused-rate-limits=1**, instance-id, catalog-protocol/fetch, device-* |
| `/api/v1/freebuff/models` | GET | auth, catalog-protocol, `x-freebuff-client: cli`, device-* |
| `/api/v1/chat/completions` (#23) | POST | auth, content-type, `User-Agent: ai-sdk/openai-compatible/0.0.0-test/codebuff`, sse-gzip-recovery, acting-user-id, client-version, catalog-fetch, device-* |
| `/api/agents/validate` (#17) | POST | auth, content-type (body 953 KB, 120 definisi) |
| `/api/v1/agent-runs` (#21) | POST | auth, acting-user-id (**tanpa** content-type, **tanpa** tanda tangan) |
| `/api/logs` (#3) | POST | content-type saja (tanpa auth) |
| `/api/v1/ads` (#14) | POST | content-type, auth, `User-Agent: Freebuff-CLI/0.2.36`, x-freebuff-env |
| `/api/ads` (freebuff.com #8) | POST | idem (+`provider`) |
| `/api/v1/ads/policy` (#5) | GET | auth, UA CLI |
| `/api/profile-survey` (#20) | GET | auth, UA CLI — **tanpa query** |
| `/api/sponsored-survey` (#22) | GET | `?questionKinds=single%2Cmulti%2Cranking%2Ctext&surface=cli` |
| `/api/v1/project-profile` (#24) | GET | `?project_key=local%3A<sha256[:32]>`, auth, content-type |

## 5. Body chat (urutan key **persis** capture)

```
model, codebuff_metadata, provider, messages, tools, tool_choice, stream
```
- `provider = {"data_collection":"deny"}`
- `codebuff_metadata`: `freebuff_instance_id, freebuff_multi_session, surface,
  freebuff_client_env, freebuff_input_profile, trace_session_id, repo_snapshot,
  compaction_*, llm_step_number, run_id, client_id, cost_mode`
- `tools`: 16 schema (`freebuff_default_tools.json`)
- `messages[0]`: system prompt "You are **Buffy**, the coding agent behind Codebuff…"
  + `Current date: <en-US long>` + konteks runtime (file tree, git, recently-read).
  Inilah satu-satunya field yang tidak identik dengan capture (diisi file nyata).

## 6. Bukti verifikasi

```
sha256(body capture #23) = 5cae14c5…9fa88c35
kanon   = freebuff-device-v1 / POST /api/v1/chat/completions / ts=1794989919791
Ed25519 verify terhadap x-freebuff-device-sig capture = LULUS
```
Artinya string kanonik, encoding base64url, dan hashing **identik byte-per-byte**
dengan implementasi binary. Selain itu `GET /api/v1/freebuff/streak` dan
`GET /api/v1/freebuff/models` yang dibangun modul ini diterima server (HTTP 200)
dengan tanda tangan yang dihasilkan sendiri.

## 7. Yang tidak 100% 1:1

1. `clientContext` iklan — binary membangunnya dari ~400 baris heuristik runtime
   (RAM/load/disk/RTT/riwayat ketikan/isi terminal). Python memakai bentuk & tipe
   sama dengan nilai bucket wajar.
2. `repo_snapshot`/`trace_session_id` — bergantung isi repo & sesi nyata.
3. Registrasi device-key butuh token valid; bila gagal, binary (dan modul ini)
   mengirim request **tanpa** header device-* dan tetap lanjut.

## 8. Catatan privasi

Capture memuat token Bearer, tanda tangan device, email, dan id akun. Modul ini
membaca token dari keychain dan **tidak** mencetaknya; `verify`/`selftest`
hanya memakai data lokal.

## 9. Kenapa `POST /api/v1/chat/completions` menolak klien Python

Uji coba langsung (18 Nov 2026) memberi tiga penolakan berurutan:

| Percobaan | Respons |
|---|---|
| `runId` sembarang | `{"message":"runId Not Found: …"}` |
| START `agentId:"base2"` + handle `fbm1.*` | `409 freebuff_catalog_stale` |
| START `agentId:"base2"` + key mentah `m-…` | `403 free_mode_invalid_agent_model` |
| START `agentId:"base3-free-catalog"` (benar) | `403 third_party_client_warning` → **"strike 5 of 5 on this account"** |

Penyebab dan fakta yang didapat:

1. **`runId` harus nyata.** Chat mewajibkan `codebuff_metadata.run_id` hasil
   `POST /api/v1/agent-runs {action:"START"}` (respons `{runId}`). Itu sebabnya
   `runId Not Found` muncul saat memakai UUID acak.
2. **Agent free mode = `base3-free-catalog`** (`tV` di bundle, `HkA(row)` membuat
   definisi agent dengan `model: row.handle`). Capture #21 mengirim
   `{"action":"START","agentId":"base3-free-catalog","ancestorRunIds":[]}`.
   Memakai `base2` memicu `free_mode_invalid_agent_model`.
3. **Urutan wajib**: `GET /models` → `POST /session/admission`
   (`x-freebuff-model` = handle `fbm1.*`) → `agent-runs START` → chat → `FINISH`.
4. **Chat dijaga anti-klien-pihak-ketiga.** Server membandingkan sidik jari klien
   (UA ai-sdk + suffix `ai-sdk/provider-utils/3.0.25 runtime/browser`,
   `x-freebuff-env`, `x-freebuff-device-*`, profil input) dan menolak request yang
   datang dari harness/proxy lain. Penolakan **dicatat sebagai strike pada akun**
   (pesan: "recorded as strike 5 of 5 on this account"), sedangkan
   `GET /api/v1/me` masih `banned:false`.

Kesimpulan praktis (diperbarui setelah §10–§11): penolakan di atas terjadi
karena **urutan request belum lengkap**, bukan karena chat mustahil dari
Python. Setelah `GET /session` + `POST /api/agents/validate` + `tools` resmi CLI
dikirim, chat menjawab `200`. Lihat §10, §11, dan §13.2.

Catatan: `x-freebuff-catalog-fetch` + handle `fbm1.*` sah-sah saja (dipakai pada
`agent-runs` dan `session/admission`), tetapi chat tetap ditolak karena lapisan
pemeriksaan klien, bukan karena katalog.

## 10. Request yang hilang: `/api/agents/validate` + heartbeat

Capture baru (18 Nov 2026, sesi yang **berhasil** tanpa pembatasan, record #36–#61)
memperlihatkan urutan lengkap satu giliran chat:

| # | Request | Catatan |
|---|---|---|
| 36 | `GET /api/v1/freebuff/models` | menerbitkan `fetchId` `fbf1.AAFjlJsH…` |
| 37, 38 | `GET /api/v1/freebuff/session` | heartbeat, `x-freebuff-instance-id: cli:a6ac76f8…` |
| 39 | `POST /api/v1/freebuff/session/admission` | `x-freebuff-model` = **handle** `fbm1.*` |
| 50 | `POST /api/agents/validate` | **120 definisi, termasuk `base3-free-catalog` dengan `model` = handle yang sama** |
| 53 | `GET /api/v1/freebuff/session` | heartbeat lagi |
| 56 | `POST /api/v1/agent-runs` | `{"action":"START","agentId":"base3-free-catalog"}` → `runId` |
| 58 | `POST /api/v1/chat/completions` | `codebuff_metadata.run_id` = `runId`, `__inst = cli:a6ac76f8…` |
| 59 | `GET /api/v1/project-profile` | `project_key=local:<sha256[:32]>` |
| 61 | `POST /api/v1/chat/completions` | langkah LLM berikutnya (`llm_step_number` naik) |

Penyebab kegagalan versi sebelumnya (yang memicu 409/403 + strike) adalah
**`POST /api/agents/validate` tidak pernah dikirim**. Tanpa itu server tidak punya
ikatan `(agentId, handle model)` untuk token tersebut sehingga chat dianggap
datang dari klien lain. Setelah definisi free agent diikat ke handle katalog,
body validate kita **byte-identik** dengan capture:

```
python3 freebuff_requests.py selftest
   [OK  ] agents/validate byte-identik dgn capture — 953100 byte identik
```

Dua bug lain yang ditemukan dari perbandingan capture #58:

1. Kunci metadata adalah **`freebuff_client_env`**, bukan `x-freebuff-env`
   (sebelumnya salah nama → sidik jari klien meleset).
2. Semua nilai `codebuff_metadata` bertipe **string**, termasuk
   `freebuff_multi_session: "1"` dan `llm_step_number: "1"`.

Urutan kunci `codebuff_metadata` sekarang identik dengan capture (17 kunci):
`freebuff_instance_id, freebuff_multi_session, surface, freebuff_client_env,
freebuff_input_profile, trace_session_id, repo_snapshot, compaction_version,
compaction_root_model, compaction_root_version, compaction_root_run_id,
compaction_request_id, compaction_request_group, llm_step_number, run_id,
client_id, cost_mode`.

Perintah baru:

```bash
python3 freebuff_requests.py plan                    # cetak 9 langkah wajib
python3 freebuff_requests.py run --prompt "halo"     # DRY RUN
python3 freebuff_requests.py run --prompt "halo" --confirm   # kirim sungguhan
```

`run_freebuff_session()` menjalankan seluruh urutan di tabel atas.
File `freebuff_agent_definitions.json` (120 definisi) diekstrak dari capture
validate terakhir dan dipakai untuk membangun body yang byte-identik.

## 11. Hasil akhir: chat 200 dari Python (dan syarat slot sesi)

Setelah `agents/validate` diperbaiki, kegagalan berikutnya bukan soal sidik jari
tetapi soal **slot sesi**:

```
POST /api/v1/freebuff/session/admission
409 {"status":"purchase_capacity","concurrency":"slot-bound","slotLimit":1,
     "currentInstanceId":"cli:a6ac76f8-…",
     "desktopSessionCounts":{"premium":1,…}}
```

Free mode hanya punya **1 slot**. Kalau instance lain (CLI resmi) sedang memegang
slot, admission ditolak dan chat berikutnya dijawab `428 waiting_room_required`
("Your free session has ended. Send your message again to start a new one.").
Binary menyediakan header `x-freebuff-takeover-instance-id` (`P$A`) untuk
mengambil alih slot; mengirim `currentInstanceId` dari body 409 ke header itu
menghasilkan `200 {"status":"active"}`.

Hasil uji nyata dengan modul ini:

```
$ python3 freebuff_requests.py run --prompt "sebutkan 1 kata sapaan" --confirm
Halo
instance=cli:687e1e8b-…  validate=200  run=01a1eec0-…
chat=200  finish=200
```

Jadi syarat lengkap satu giliran free mode:

1. `GET /models` → `fetchId` + handle, pakai `fetchId` ini konsisten sampai chat.
2. `GET /session` heartbeat, `POST /session/admission` → **harus `status:"active"`**;
   kalau `purchase_capacity`, ambil alih dengan `x-freebuff-takeover-instance-id`.
3. `POST /api/agents/validate` dengan 120 definisi & `base3-free-catalog.model = handle`.
4. `GET /session` heartbeat lagi → `POST /agent-runs START base3-free-catalog` → `runId`.
5. `POST /chat/completions` dengan `codebuff_metadata.run_id = runId` (dan instance
   yang sama dengan admission).
6. `POST /agent-runs FINISH` — `directCredits`/`totalCredits` **wajib angka**
   (`0`), bukan `null`; kalau `null` server menjawab
   `{"error":"Invalid request body", … "expected number, received null"}`.

Semua ini sekarang ada di `run_freebuff_session()` / `freebuff_requests.py run`.

## 12. Login flow (capture #288–#305)

Endpoint & payload:

| # | Request | Body / catatan |
|---|---|---|
| 289 | `POST https://freebuff.com/api/auth/cli/code` | `{"fingerprintId":"enhanced-…"}` → `{fingerprintId, fingerprintHash, loginUrl, expiresAt, expiresInMs}` |
| 290–296 | `GET https://freebuff.com/api/auth/cli/status?fingerprintId=&fingerprintHash=&expiresAt=` | `401 {"error":"Authentication failed"}` selama menunggu |
| 297 | idem | `200 {user:{id,name,email,authToken,fingerprintId,fingerprintHash}, message:"Authentication successful!"}` |
| 305 | `POST /api/v1/freebuff/device-keys` | `{"publicKey":"<b64url raw32>","client":"cli"}` → `{keyId}` |

Detail penting:

- **User-Agent** di ketiga request auth = `Bun/1.3.14` (fetch bawaan Bun, bukan
  `Freebuff-CLI/…`); tanpa `Authorization` untuk code & status.
- **Polling**: interval 5 s, timeout 1 jam (`Q1$ = 3600000`), berhenti saat
  respons 200 memuat `user`; status selain 401 hanya dicatat.
- **`fingerprintHash` bukan hash lokal** — nilainya diberikan server pada
  respons `login/code` dan wajib dikirim balik saat polling.
- **`fingerprintId`** dibuat client (`wsL()`):

```
"enhanced-" + base64url(sha256(JSON.stringify({
  system: {manufacturer, model, serial, uuid},          # DMI
  cpu:    {manufacturer, brand, cores, physicalCores},  # /proc/cpuinfo
  os:     {platform, distro, arch, hostname},
  runtime:{nodeVersion, platform:"linux", arch:"x64", shell, cpuCount},
  network:{macAddresses:[…sorted], interfaceCount},
  machineId: "/etc/machine-id",
  fingerprintVersion: "2.0"
})))
```
  Fallback bila gagal: `"codebuff-cli-" + 8 karakter base64url acak.
- **Penyimpanan token** setelah sukses: `authToken` masuk keychain
  (`Bun.secrets`, service `freebuff-cli`, name/account = path
  `~/.config/manicode/credentials.json`, label `freebuff-cli/<path>`), lalu file
  ditulis ulang **tanpa** `authToken` dan dengan `"tokenStore": "keychain"`
  (indent 2, mode 0600).
- Login baru **merotasi device key**: registrasi lama hilang, keyId baru
  (contoh `iimG7xlgg3AIF9S_QhPlB4`) terikat ke `scope = "<origin> user:<id>"`.
  Karena itu `verify` lama otomatis jadi SKIP bila kunci capture sudah tidak aktif.
- `POST https://freebuff.com/api/auth/cli/logout` `{userId, fingerprintId,
  fingerprintHash}` untuk keluar.

Perintah baru:

```bash
python3 freebuff_requests.py fingerprint   # lihat fingerprintId + payload
python3 freebuff_requests.py login         # minta kode, cetak URL, polling, simpan
python3 freebuff_requests.py login --interval 2000
python3 freebuff_requests.py logout        # logout server + hapus kredensial lokal
```

Uji nyata (18 Nov 2026) dengan fingerprint mesin ini:

```
code POST: 200 {"fingerprintId":"enhanced-a4MznECs…","fingerprintHash":"854ac491…",
                "loginUrl":"https://freebuff.com/login?auth_code=xamorYtuCN6ALUr6IvUa_w",
                "expiresAt":1795016282592,"expiresInMs":3600000}
status GET: 401 {"error":"Authentication failed"}   # sesuai capture saat menunggu
```

## 13. Gateway FastAPI

File baru `freebuff_gateway_fastapi.py` memakai `freebuff_requests.py` sebagai
library (tanpa duplikasi builder), mengekspos API mirip OpenAI:

- `GET /v1/models`, `POST /v1/chat/completions` (stream & non-stream),
- `GET /freebuff/{catalog,session,streak,me,fingerprint}`,
- `POST /freebuff/login/start`, `GET /freebuff/login/status`.

Semua pengiriman memakai `PreparedRequest` hasil builder (header + tanda tangan
Ed25519 dihitung di library), hanya transport-nya `httpx.AsyncClient`. Sesi
dikelola satu objek: katalog (TTL), instance `cli:<uuid>` (dipersist),
admission (termasuk takeover otomatis saat `409 purchase_capacity`), validasi
agen, lalu run START (sekali per sesi) → chat → langkah dicatat.
`asyncio.Semaphore(1)` menjaga agar chat tidak berjalan bersamaan (slot free
mode tunggal).

Hasil uji lokal (port 8124, token `uji`):

```
GET  /healthz                 -> {"ok":true,"version":"0.2.36","account":"…@gmail.com"}
GET  /v1/models               -> 53 model + handle + recommended
POST /v1/chat/completions     -> {"choices":[{"message":{"content":"halo"}}],
                                  "usage":{"prompt_tokens":13190,…}}
POST … {"stream":true}        -> SSE chunk dengan id stabil + [DONE]
POST … model "model-ngawur"   -> 400 {"error":"unknown_model"}
tanpa Authorization           -> 401
```

Dokumentasi pemakaian: `GATEWAY.md`.

### 13.1 Format wire pesan (dari bundle `otA`)

Converter AI-SDK -> OpenAI klasik di bundle hanya mengizinkan part
`text`, `image_url`, `file` (part `tool-call`/`tool-result` ditolak upstream
dengan 422 `unknown variant`). Pemetaannya:

- `system`  -> `{role:"system", content:"<string>"}`
- `user`    -> `{role:"user", content:[{type:"text",text}|{type:"image_url",...}]}`
- assistant -> `{role:"assistant", content:"<teks>", tool_calls:[{id,type:"function",
  function:{name,arguments:"<json string>"}}]}`
- tool      -> `{role:"tool", tool_call_id, content:"<teks hasil>"}`

### 13.2 Deteksi klien pihak ketiga (uji empiris)

| Payload | Hasil |
|---|---|
| system Buffy + user, `tools` resmi CLI | 200 |
| + system kedua dari harness (opencode) | 200 |
| system hanya milik harness (tanpa Buffy) | 403 `free_mode_cli_required` |
| system Buffy + `tools` kustom (`read`,`bash`) | 403 `third_party_client_warning` (strike) |

Kesimpulan: yang menentukan adalah **system prompt CLI wajib ada** dan
**daftar `tools` wajib milik CLI**; jumlah pesan system tidak masalah.
Karena itu gateway memaksa `f.default_tools()` dan menerjemahkan tool call.

`428 waiting_room_required` ("Your free session has ended. Send your message
again to start a new one.") muncul walau admission masih terlihat aktif; CLI
mengatasinya dengan admission + run baru, dan gateway melakukan retry sekali.

### 13.3 Manajemen sesi (kuota)

Status sesi yang dilaporkan upstream (`GET /v1/freebuff/session` dan admission):
`active`, `none`, `ended`, `superseded`, `rate_limited`, `ip_capped`,
`spend_limited`, `country_blocked`, `banned`.

- `superseded` -> "This session was taken over elsewhere. Send again to start a
  new session." Artinya instanceId lain mengambil slot; CLI membuat sesi baru.
- `ip_capped` -> "Too many Freebuff sessions on this network."
- `rate_limited` -> jatah freebucks habis; payload memuat `freebucksShortfall`.
- `428 waiting_room_required` -> sesi berakhir di sisi server walau admission
  klien masih terlihat aktif; CLI membalas dengan admission + run baru.

Karena jumlah sesi terbatas, gateway menyimpan `instanceId` + admission ke
`~/.config/manicode/gateway-session.json` dan memakai ulang sesi sampai
`expiresAt` habis, dengan heartbeat `GET /session` sebagai perpanjangan murah.
Satu agent-run dipakai untuk seluruh percakapan (capture: `run_id` sama pada
step 1 dan 2); `FINISH` **tidak** dikirim per pesan karena bisa melepas klaim
sesi (`purchase_claim_released`).

### 13.4 Field metadata: per sesi vs per request

Dibandingkan antar step pada sesi yang sama (capture 03938951 = step 1,
12afc6ee = step 2, instance `cli:30ba589f-…`):

| Field | Step 1 vs 2 |
|---|---|
| `freebuff_instance_id`, `freebuff_multi_session`, `surface`, `freebuff_client_env`, `freebuff_input_profile` | sama |
| `trace_session_id` | sama |
| `repo_snapshot` | sama |
| `compaction_version`, `compaction_root_model`, `compaction_root_version`, `compaction_root_run_id`, `compaction_request_group` | sama |
| `run_id` | sama (satu run untuk seluruh percakapan) |
| `client_id` | sama |
| `llm_step_number` | 1 -> 2 |
| `compaction_request_id` | beda tiap request |

Status admission non-aktif yang perlu ditangani: `purchase_claim_released`
(klaim sesi dilepas; `desktopSessionCounts.nextExpiryAt` memberi waktu tunggu),
`ip_capped`, `rate_limited`, `superseded`.

### 13.5 Slot sesi gateway (`--session-id`)

Gateway bisa memegang beberapa slot sesi terpisah, dipilih lewat
`--session-id` / `FREEBUFF_SESSION_ID`:

- state per slot: `~/.config/manicode/gateway-sessions/<id>.json`
  (tanpa id: `gateway-session.json`);
- `trace_session_id = uuid5(NS_URL("freebuff-gateway/session"), id)` dan
  `client_id` = 11 karakter dari sha256 id, sehingga id yang sama selalu
  menghasilkan metadata yang sama dengan CLI-style ids;
- `--list-sessions` membaca semua file slot tanpa melakukan request jaringan.
