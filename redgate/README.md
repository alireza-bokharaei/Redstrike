# Redstrike 2.3.1 — راهنمای فنی / Technical Guide

[معرفی پروژه / Project overview](../README.md) · [فارسی](#fa) · [English](#en)

---

<a id="fa"></a>
<div dir="rtl" lang="fa">

## فارسی

### محدودهٔ این راهنما

این پوشه شامل کد اجرایی **یورش (Redstrike)** است: Gateway، سرویس ابزار MCP، Runner، رابط وب، تنظیمات، Skills و تست‌ها. راهنمای زیر برای کار با همین اجزا است؛ معرفی، نصب اولیه و الزامات استفادهٔ مجاز در [README اصلی](../README.md) آمده است.

**همهٔ فرمان‌های این راهنما از پوشهٔ `redgate/` اجرا می‌شوند، مگر خلاف آن گفته شود.** ابزار فقط برای ارزیابیِ دارای مجوز و محدودهٔ معتبر است. [امنیت](SECURITY.md) و [محدودیت‌ها](LIMITATIONS.md) را رعایت کنید.

### اجزای اجرایی

<div dir="ltr">

```text
Browser: JavaScript / SVG
    |
    | same-origin API + operator Bearer token
    v
Gateway: FastAPI -- SQLite WAL / mission checkpoints / audit
    |                    |
    | internal token     +-- configured model runtime (mock by default)
    +-- MCP: bounded Python tools
    +-- Go Runner: native HTTP evidence / approved script adapters
```

</div>

Gateway احراز هویت، مجوز engagement، RoE، محدوده، سهمیه و سیاست‌ها را بررسی می‌کند. MCP و Runner سرویس‌های داخلی با توکن جداگانه‌اند؛ توکن سرویس نباید در مرورگر یا درخواست هدف استفاده شود. برای هر پایگاه دادهٔ SQLite تنها یک فرایند Gateway اجرا کنید.

### ساختار پوشه‌ها

| مسیر | محتوا |
|---|---|
| `gateway/` | API، سیاست‌ها، احراز هویت، هماهنگی مأموریت، شواهد، حافظه، اعتبارسنجی و رابط وب |
| `gateway/migrations/` | migrationهای افزایشی و کنترل‌شدهٔ SQLite |
| `mcp_server/` | پل ابزارهای Python و قراردادهای ورودی/خروجی |
| `sandbox_runner/` | Runner و جمع‌آورندهٔ بومی HTTP در Go |
| `config/` | محدوده، نقش‌ها، سیاست ابزار/اسکریپت و تنظیمات مدل |
| `skills/` | گردش‌کارهای YAML برای بررسی و گزارش |
| `scripts/` | راه‌اندازی، مدیریت Docker، اعتبارنامه، مدل و پشتیبان‌گیری |
| `tests/` | تست‌های Python، Go-integration، JavaScript و مرورگر |
| `docs/` | معماری، استقرار و گزارش بررسی‌ها |

### فایل‌های پیکربندی

| فایل | کاربرد |
|---|---|
| `config/allowlist.yaml` | اهداف مجاز، بازه و وضعیت engagement و کنترل‌های DNS |
| `config/operators.yaml` | هویت، نقش، سهمیه، نام متغیر هش توکن و دسترسی به engagement |
| `config/tool_policy.yaml` | فعال‌بودن، محدودیت و سطح ریسک ابزارها |
| `config/script_policy.yaml` | سیاست اعتبارسنجی و اجرای اسکریپت |
| `config/llm_proxy.yaml` | تنظیمات اولیهٔ proxy مدل |
| `config/local_models.yaml` | فهرست و مشخصات مدل‌ها و quantization |
| `config/Modelfile.redgate` | قالب آماده‌سازی مدل Ollama |
| `skills/*.yaml` | تعریف مراحل هر Skill |

تنظیمات نمونه را با مجوز واقعی جایگزین کنید. نام نقش به‌تنهایی مجوز دسترسی به engagement نیست. گذر از تأیید انسانی یا داشتن نقش admin، مجوز خروج از محدودهٔ هدف ایجاد نمی‌کند.

### متغیرهای محیطی مهم

| متغیر | کاربرد |
|---|---|
| `REDGATE_DB_PATH` | مسیر SQLite؛ در Compose برابر `/app/data/redgate.db` |
| `REDGATE_ARTIFACT_DIR` | ریشهٔ مجاز برای بررسی سخت‌سازی فایل‌های باینری (پیش‌فرض `data/artifacts`) |
| `REDGATE_CONFIG_DIR` / `REDGATE_SKILLS_DIR` | مسیر تنظیمات و Skills |
| `REDGATE_INTERNAL_TOKEN` | اعتبارنامهٔ ارتباط Gateway با سرویس‌های داخلی |
| `REDGATE_TOKEN_HASH_*` | هش توکن‌های اپراتور که تنظیمات هویت به آن‌ها ارجاع می‌دهد |
| `REDGATE_LLM_MODE` | حالت مدل؛ پیش‌فرض راه‌اندازی `mock` |
| `REDGATE_LLM_BASE_URL` / `REDGATE_LLM_MODEL` | endpoint و شناسهٔ مدل اولیه |
| `REDGATE_LLM_API_KEY_FILE` | مسیر فایل کلید مدل؛ در Compose برابر `/run/secrets/llm_api_key` |
| `REDGATE_IMAGE_FLAVOR` | هدف ساخت `full` یا `lite` در Compose |
| `REDGATE_BIND_ADDR` | آدرس انتشار پورت Compose؛ پیش‌فرض `127.0.0.1` |
| `REDGATE_GATEWAY_HOST` | آدرس bind راه‌انداز محلی؛ پیش‌فرض `127.0.0.1` |
| `REDGATE_DEMO_MODE` | فقط آزمایشگاه خصوصی؛ در Compose همیشه خاموش است |

bootstrap فایل `.env` خصوصی می‌سازد؛ آن را وارد Git نکنید. راه‌انداز محلی `.env` را خودکار source نمی‌کند. تنظیمات runtime ذخیره‌شده در SQLite بر تنظیمات اولیهٔ مدل اولویت دارند. فایل کلیدِ موجود در مسیر پیکربندی‌شده نیز بر کلید محیطی اولویت دارد؛ [جزئیات نگهداری کلید](SECURITY.md).

### قراردادهای API

مستندات تعاملی در **`/docs`** است. مسیرهای workspace زیر به **Bearer token اپراتور و دسترسی به engagement** نیاز دارند. کنترل مأموریت علاوه بر آن محدود به مالک مأموریت یا admin دارای دسترسی است. تمام مسیرهای جدول با `/api/v1` شروع می‌شوند.

| بخش | مسیرها |
|---|---|
| Workspace | `GET /workspace?engagement_id=…` |
| مأموریت | `POST /missions`، `GET /missions`، `GET /missions/{mission_id}` |
| کنترل مأموریت | `POST /missions/{mission_id}/control` با `start`، `pause`، `resume` یا `cancel` |
| خروجی مأموریت | `GET /missions/{mission_id}/graph`، `GET /missions/{mission_id}/report.md`، `GET /missions/{mission_id}/export.json` |
| دارایی | `GET /assets` و `GET /assets/graph` با پارامتر engagement |
| شواهد | `POST /evidence/capture`، `GET /evidence`، `GET /evidence/{evidence_id}` و `GET /evidence/{evidence_id}/export.json` |
| بازآزمایی یافته | `POST /recon/findings/{finding_id}/retest`، `GET /recon/findings/{finding_id}/retests` و `GET /recon/findings/{finding_id}/evidence` |
| بررسی و تحلیل | `POST /recon/run`، `GET /recon/runs`، `PATCH /recon/findings/{finding_id}` |
| سایر امکانات | `/skills`، `/memory`، `/models/*`، `/scan`، `/script/*`، `/approvals`، `/allowlist`، `/policies/*` و `/audit/verify`؛ با مجوزهای متناسب هر مسیر |

مسیرهای `/healthz`، `/readyz` و `/api/v1/health` بررسی سرویس و قابلیت‌های نصب‌شده را ارائه می‌کنند؛ آن‌ها را با اجرای ارزیابی اشتباه نگیرید.

### قراردادهای API ۲٫۲

| مسیر | کاربرد |
|---|---|
| `GET /api/v1/capabilities` | توصیف حالت‌ها، لایه‌ها، پرسش‌های دروازه و ثابت‌های غیرقابل‌تغییر |
| `POST /api/v1/session/start` | پروتکل آغاز جلسه: مأموریت، محدوده، RoE، بودجه و وضعیت TLS |
| `POST /api/v1/capabilities/resolve` | تصمیم مجاز/ممنوع برای هر قابلیت در یک حالت |
| `POST /api/v1/capabilities/toggle` | فعال/غیرفعال‌سازی حالت‌ها (فقط admin) |
| `POST /api/v1/tls/audit` | تحلیل عمیق TLS روی هدف در محدوده؛ نتیجه تغییرناپذیر و هش‌شده |
| `GET /api/v1/tls/audits` | فهرست تحلیل‌های TLS یک engagement |
| `POST /api/v1/expansion/requests` | ثبت درخواست گسترش (هدف/بودجه/سهمیه/سطح بازبینی) |
| `POST /api/v1/expansion/requests/{id}/decide` | تأیید یا رد توسط فرد دوم |
| `POST /api/v1/gate/evaluate` | ارزیابی یافته‌ها با دروازهٔ هفت‌پرسشی |
| `GET /api/v1/agents/roles` · `POST /api/v1/agents/plan` | کاتالوگ و برنامهٔ مشورتی نقش‌ها |
| `POST /api/v1/binary/triage` | بررسی فقط‌خواندنی سخت‌سازی ELF (approver/admin) |

### سطح تهاجمی ۲٫۳

مدل کنترل، همان جملهٔ پرامپت است: **وضعیت پیش‌فرض درون محدودهٔ اعلام‌شده اجازه‌دهنده است؛ تأیید دو‌نفره فقط برای اقدام‌های پرتأثیر.**

| وضعیت (posture) | پیش‌فرض | ریسک | رضایت لازم | دو‌نفره |
|---|---|---|---|---|
| `posture:permissive_in_scope` | **بله** | medium | operator | خیر |
| `posture:strict_readonly` | انتخابی (تنگ‌تر) | low | operator | برای هر اقدام غیر‌فقط‌خواندنی |
| `posture:ctf_aggressive` | انتخابی | high | operator | خیر |

فقط چهار مورد دو‌نفره‌اند: `exploitation:proof_of_concept`، `credential:post_exploitation`، `mass_scan:expanded_budget` و `tool:hydra`. وضعیت هرگز محدوده را گسترش نمی‌دهد: allowlist، پنجرهٔ RoE، pinning روی DNS و مسدودسازی متادیتای ابری در همهٔ وضعیت‌ها اعمال می‌شوند — حتی `ctf_aggressive`.

| مسیر | کاربرد |
|---|---|
| `GET /api/v1/offensive/brief` | پروتکل آغاز جلسه: مأموریت، محدوده، RoE و بودجهٔ باقی‌مانده، وضعیت TLS، لایه‌ها و محدودیت‌ها |
| `GET/POST /api/v1/offensive/policy` · `/posture` · `/consent` | مشاهده و تنظیم وضعیت و ثبت رضایت هش‌شده |
| `POST /api/v1/offensive/decide` | «اجازه دارم این را اجرا کنم؟» بدون اجرا |
| `GET /api/v1/offensive/tools` · `POST /tools/run` | ۱۴۴ ابزار کاتالوگ + زیرمجموعهٔ واقعاً نصب‌شده |
| `POST /api/v1/offensive/findings` … `/{id}/verify` | چرخهٔ PoC با تأیید مستقل |
| `POST /api/v1/offensive/chains` | زنجیرهٔ حمله فقط از یافته‌های تأییدشده |
| `POST /api/v1/offensive/explore/discover` … `/mass-scan` | کشف بازگشتی و بودجهٔ اسکن انبوه |
| `POST /api/v1/offensive/bounty/…` | دامنهٔ برنامه، بررسی تکراری، پیش‌نویس گزارش |
| `GET /api/v1/offensive/agents` · `POST /loops` · `GET /brain` | ۴۹ نقش مشورتی، حلقهٔ شکار با دروازهٔ هفت‌پرسشی، حافظهٔ فقط‌افزودنی |

سه نکتهٔ صداقت که باید بدانید: کاتالوگ ۱۴۴ ابزار دارد ولی روی تصویر مرجع فقط چهار باینری نصب است و اجرای بقیه `status: unavailable` با argv معتبر برمی‌گرداند؛ `pwntools` نصب نیست و لایهٔ آن صریحاً `unavailable` گزارش می‌دهد (بدون جعل خروجی)؛ و همگام‌سازی Bug Bounty بدون اعتبارنامهٔ پلتفرم انجام نمی‌شود، پس دامنهٔ دستی‌وارد‌شده همیشه `source: manual` است و بررسی تکراری محلی در بهترین حالت `unverified` می‌ماند. جزئیات کامل در [docs/OFFENSIVE_SURFACE.md](docs/OFFENSIVE_SURFACE.md) و تأیید زنده در [docs/VERIFICATION_2.3.md](docs/VERIFICATION_2.3.md).

### بودجه، شواهد و بازآزمایی

- ورودی مأموریت: `targets` با ۱ تا ۸ میزبان، `max_actions` از ۱ تا ۶۴ با پیش‌فرض ۲۴، و `max_seconds` از ۱۰ تا ۱۸۰۰ با پیش‌فرض ۳۰۰.
- هم‌زمان حداکثر دو مأموریت در سامانه و یک مأموریت برای هر مالک اجرا می‌شود؛ حتی اگر admin آن را ادامه دهد، سهمیه به مالک اصلی تعلق دارد.
- مهلت از اولین شروع محاسبه و هنگام توقف موقت نیز سپری می‌شود. بودجهٔ رزروشده پیش از I/O کسر می‌شود و بازگردانده نمی‌شود. بازیابی پیشرفت، تضمین exactly-once برای شبکه نیست.
- شواهد HTTP فقط `http`/`https`، متد HEAD/GET و مسیر origin-relative بدون query یا fragment می‌پذیرند. بدنه پیش‌فرض ذخیره نمی‌شود؛ `body_preview_bytes` فقط با GET و تا ۸۱۹۲ بایت مجاز است.
- احراز هویت هدف، هدر دلخواه، cookie replay و دنبال‌کردن redirect در این جمع‌آورنده پشتیبانی نمی‌شوند. TLS بر اساس نام اصلی و IP تأییدشده کنترل می‌شود.
- بازآزمایی فقط برای هدرهای امنیتیِ پشتیبانی‌شده است و `still_present`، `not_observed` یا `inconclusive` ثبت می‌کند. نتیجهٔ جدید، مدرک یا نظر قبلی را تغییر نمی‌دهد و اثبات رفع قطعی نیست.

### عملیات و توسعه

<div dir="ltr">

```bash
./scripts/redgate.sh doctor
./scripts/redgate.sh up --full
./scripts/redgate.sh status
./scripts/redgate.sh backup
./scripts/redgate.sh down
```

</div>

برای راه‌اندازی اولیه ابتدا `./scripts/bootstrap_env.sh` را اجرا کنید؛ برای ارتقای موجود آن را با `--force` اجرا نکنید. `down` داده‌ها را نگه می‌دارد. `full` شامل هر چهار زبان است؛ `lite` ابزارهای اسکریپت Go/JavaScript را ندارد ولی جمع‌آوری بومی HTTP را حفظ می‌کند. هدف ساخت جداگانهٔ `evidence` اجرای اسکریپت را رد می‌کند.

برای توسعه، ابتدا وابستگی‌ها و ابزارهای توضیح‌داده‌شده در [README اصلی](../README.md) را نصب کنید، سپس:

<div dir="ltr">

```bash
./scripts/verify.sh
./scripts/start_local.sh
```

</div>

تست مرورگر به یک Gateway آزمایشگاهیِ محلی در حالت demo و Chromium نصب‌شده نیاز دارد؛ `npm ci` مرورگر دانلود نمی‌کند. از [روش تکرار تست مرورگر](docs/VERIFICATION_2.1.0.md) استفاده کنید و demo را هرگز عمومی نکنید. این تست با اجرای مستقیم سرویس‌ها روی میزبان نوشته شده، نه loopback داخل Compose.

**مرز اجرا:** اجرای مستقیم یا یک Runner مشترک، جداسازی کد متخاصم نیست. شبکه‌های Compose نیز سیاست خروجی مقصد را اجرا نمی‌کنند. پیش از کار واقعی، TLS، محدودسازی خروجی مستقل، جداسازی مناسب، ظرفیت میزبان و بازیابی پشتیبان را بررسی کنید.

### راهنماهای تکمیلی و مجوز

[استقرار و بازیابی](docs/DEPLOYMENT.md) · [معماری](docs/ARCHITECTURE.md) · [گزارش بررسی](docs/VERIFICATION_2.1.0.md) · [امنیت](SECURITY.md) · [محدودیت‌ها](LIMITATIONS.md)

مجوز کد پروژه و اخطار استفادهٔ مجاز در [LICENSE](LICENSE) آمده است. هیچ فایل اعتبارنامه، پایگاه داده یا دادهٔ واقعی ارزیابی را وارد مخزن نکنید.

</div>

---

<a id="en"></a>

## English

### Scope of this guide

This directory contains **Redstrike's** executable components: the Gateway, MCP tool service, Runner, web console, configuration, Skills and tests. This guide covers those components; see the [main README](../README.md) for the project introduction, initial setup and authorized-use requirements.

**Run commands below from `redgate/` unless stated otherwise.** Use the software only with authorization and a valid scope. Follow [Security](SECURITY.md) and [Limitations](LIMITATIONS.md).

### Runtime components

```text
Browser: JavaScript / SVG
    |
    | same-origin API + operator Bearer token
    v
Gateway: FastAPI -- SQLite WAL / mission checkpoints / audit
    |                    |
    | internal token     +-- configured model runtime (mock by default)
    +-- MCP: bounded Python tools
    +-- Go Runner: native HTTP evidence / approved script adapters
```

The Gateway checks authentication, engagement access, RoE, scope, quotas and policies. MCP and Runner are internal services using a separate token; never use that token in the browser or target requests. Run only one Gateway process per SQLite database.

### Directory layout

| Path | Contents |
|---|---|
| `gateway/` | API, policies, authentication, mission coordination, evidence, memory, validators and web console |
| `gateway/migrations/` | Controlled additive SQLite migrations |
| `mcp_server/` | Python tool bridge and input/output contracts |
| `sandbox_runner/` | Go Runner and native HTTP collector |
| `config/` | Scope, roles, tool/script policies and model configuration |
| `skills/` | YAML assessment/reporting pipelines |
| `scripts/` | Startup, Docker lifecycle, credentials, model setup and backups |
| `tests/` | Python, Go-integration, JavaScript and browser tests |
| `docs/` | Architecture, deployment and verification records |

### Configuration files

| File | Purpose |
|---|---|
| `config/allowlist.yaml` | Authorized targets, engagement windows/status and DNS controls |
| `config/operators.yaml` | Identity, role, quota, token-hash environment names and engagement access |
| `config/tool_policy.yaml` | Tool availability, limits and risk levels |
| `config/capabilities.yaml` | Capability manifest: six operational modes, mode composition rules, ceilings, TLS profile, expansion limits and evidence-gate questions |
| `config/policies.yaml` | 2.3 control model: three postures, the four two-person policies, and the per-tool flag surface |
| `gateway/intel_engine.py` | 2.3.1 hypothesis ranking, budget, exhaustion gate, chain planning, evidence scoring, CVSS 3.1 |
| `gateway/coverage.py` | 2.3.1 coverage ledger ("covered" needs a check) and response fingerprint diffing |
| `config/script_policy.yaml` | Script validation/execution policy |
| `config/llm_proxy.yaml` | Initial model-proxy settings |
| `config/local_models.yaml` | Model catalog and quantization metadata |
| `config/Modelfile.redgate` | Ollama model-preparation template |
| `skills/*.yaml` | Skill step definitions |

Replace sample settings with your actual authorization. A role name alone does not grant engagement access. Human approval or an admin role does not authorize out-of-scope target contact.

### Key environment variables

| Variable | Purpose |
|---|---|
| `REDGATE_DB_PATH` | SQLite path; `/app/data/redgate.db` in Compose |
| `REDGATE_ARTIFACT_DIR` | Only directory tree readable by binary hardening triage (default `data/artifacts`) |
| `REDGATE_CONFIG_DIR` / `REDGATE_SKILLS_DIR` | Configuration and Skill directories |
| `REDGATE_INTERNAL_TOKEN` | Gateway-to-internal-service credential |
| `REDGATE_TOKEN_HASH_*` | Operator-token hashes referenced by identity configuration |
| `REDGATE_LLM_MODE` | Model mode; startup defaults to `mock` |
| `REDGATE_LLM_BASE_URL` / `REDGATE_LLM_MODEL` | Initial model endpoint and ID |
| `REDGATE_LLM_API_KEY_FILE` | Model-key file; `/run/secrets/llm_api_key` in Compose |
| `REDGATE_IMAGE_FLAVOR` | Compose build target: `full` or `lite` |
| `REDGATE_BIND_ADDR` | Compose published address; default `127.0.0.1` |
| `REDGATE_GATEWAY_HOST` | Local launcher's bind address; default `127.0.0.1` |
| `REDGATE_DEMO_MODE` | Private labs only; always disabled by Compose |

Bootstrap creates a private `.env`; never commit it. The local launcher does not automatically source it. Saved SQLite runtime settings override initial model settings. An existing configured key file also takes precedence over the environment key; see [key handling](SECURITY.md).

### API contracts

Interactive schemas are available at **`/docs`**. Workspace routes below require an **operator Bearer token and engagement access**. Mission controls additionally require the mission owner or an assigned admin. Prefix each table entry with `/api/v1`.

| Area | Routes |
|---|---|
| Workspace | `GET /workspace?engagement_id=…` |
| Missions | `POST /missions`, `GET /missions`, `GET /missions/{mission_id}` |
| Mission controls | `POST /missions/{mission_id}/control` with `start`, `pause`, `resume` or `cancel` |
| Mission outputs | `GET /missions/{mission_id}/graph`, `GET /missions/{mission_id}/report.md`, `GET /missions/{mission_id}/export.json` |
| Assets | `GET /assets`, `GET /assets/graph` with engagement query |
| Evidence | `POST /evidence/capture`, `GET /evidence`, `GET /evidence/{evidence_id}` and `GET /evidence/{evidence_id}/export.json` |
| Finding retests | `POST /recon/findings/{finding_id}/retest`, `GET /recon/findings/{finding_id}/retests` and `GET /recon/findings/{finding_id}/evidence` |
| Recon and analysis | `POST /recon/run`, `GET /recon/runs`, `PATCH /recon/findings/{finding_id}` |
| Other features | `/skills`, `/memory`, `/models/*`, `/scan`, `/script/*`, `/approvals`, `/allowlist`, `/policies/*` and `/audit/verify`, subject to each route's permissions |

`/healthz`, `/readyz` and `/api/v1/health` provide service checks and installed capabilities; they do not execute an assessment.

### 2.2 API contracts

| Route | Purpose |
|---|---|
| `GET /api/v1/capabilities` | Describe modes, layers, gate questions and invariants |
| `POST /api/v1/session/start` | Session-start protocol: mission, scope, RoE, budget and TLS status |
| `POST /api/v1/capabilities/resolve` | Allow/deny decision per capability in a mode (single or composed) |
| `POST /api/v1/capabilities/compose` | Resolve `"pentest+ssl_tls_analysis"` without declaring it |
| `POST /api/v1/decide/approach` | Deterministic, advisory next-step plan for a target |
| `POST /api/v1/capabilities/toggle` | Enable/disable modes (admin only) |
| `POST /api/v1/tls/audit` | Deep TLS analysis of an in-scope target; immutable, hashed record |
| `GET /api/v1/tls/audits` | Engagement-scoped TLS audit history |
| `POST /api/v1/expansion/requests` | Submit a scope/budget/quota/privilege expansion request |
| `POST /api/v1/expansion/requests/{id}/decide` | Independent approval or rejection |
| `POST /api/v1/gate/evaluate` | Evaluate findings against the seven-question gate |
| `GET /api/v1/agents/roles` · `POST /api/v1/agents/plan` | Advisory role catalogue and plan |
| `POST /api/v1/binary/triage` | Read-only ELF hardening triage (approver/admin) |

### 2.3 offensive surface

The control model is the prompt's sentence, implemented literally: **the default
posture is permissive within the declared scope; two-person approval applies only
to high-impact actions.**

| Posture | Default | Risk | Consent | Two-person |
|---|---|---|---|---|
| `posture:permissive_in_scope` | **yes** | medium | operator | no |
| `posture:strict_readonly` | opt-in narrowing | low | operator | anything not read-only |
| `posture:ctf_aggressive` | opt-in | high | operator | no |

Only four actions need two people: `exploitation:proof_of_concept`,
`credential:post_exploitation`, `mass_scan:expanded_budget` and `tool:hydra`. A
posture never widens reach: the allowlist, RoE window, DNS pinning and
cloud-metadata denial hold in every posture, including `ctf_aggressive`.

| Route | Purpose |
|---|---|
| `GET /api/v1/offensive/brief` | Session Start Protocol: mission, scope, RoE + remaining budget, TLS status, layers, restrictions |
| `GET/POST /api/v1/offensive/policy` · `/posture` · `/consent` | Inspect posture, set it (approver only), record hashed consent |
| `POST /api/v1/offensive/decide` | "May I run this?" without running it |
| `GET /api/v1/offensive/tools` · `POST /tools/run` | The 183-tool catalogue (15 families incl. mobile, wireless, forensics) and the honestly-installed subset |
| `POST /api/v1/offensive/findings` … `/{id}/verify` | PoC lifecycle with independent reproduction |
| `POST /api/v1/offensive/chains` | Attack chains from verified findings only |
| `POST /api/v1/offensive/explore/discover` … `/mass-scan` | Recursive discovery and budgeted mass scanning |
| `POST /api/v1/offensive/bounty/…` | Program scope, duplicate checks, report drafts |
| `GET /api/v1/agents` · `POST /loops` · `GET /brain` | 49 advisory roles, 7-Question-Gate hunt loops, append-only brain |

Three honesty notes: the catalogue has 183 entries but only four binaries are
installed on the reference image, and a missing binary returns
`status: unavailable` with the validated argv rather than invented output;
`pwntools` is not installed, so that layer reports `unavailable` explicitly;
and bug-bounty sync needs platform credentials, so a hand-entered scope stays
`source: manual` and a local duplicate check stays `unverified`. Full detail in
[docs/OFFENSIVE_SURFACE.md](docs/OFFENSIVE_SURFACE.md); live evidence in
[docs/VERIFICATION_2.3.md](docs/VERIFICATION_2.3.md).

### Budgets, evidence and retests

- Mission inputs: `targets` with 1–8 hosts, `max_actions` from 1–64 (default 24), and `max_seconds` from 10–1800 (default 300).
- At most two missions globally and one per owner execute concurrently. An admin resuming work does not change the original owner's quota attribution.
- The deadline starts on first start and continues while paused. Actions are reserved before I/O and not refunded. Checkpoint recovery is not exactly-once network execution.
- HTTP evidence accepts only `http`/`https`, HEAD/GET and an origin-relative path without query or fragment. No body is stored by default; `body_preview_bytes` requires GET and is capped at 8192.
- Target authentication, arbitrary headers, cookie replay and redirect following are unsupported by this collector. TLS uses the original hostname and an approved pinned IP.
- Retests cover supported missing-security-header checks only and append `still_present`, `not_observed` or `inconclusive`. They do not overwrite earlier evidence or analyst verdicts and do not prove remediation.

### Operations and development

```bash
./scripts/redgate.sh doctor
./scripts/redgate.sh up --full
./scripts/redgate.sh status
./scripts/redgate.sh backup
./scripts/redgate.sh down
```

Run `./scripts/bootstrap_env.sh` first for a new deployment; do not use its `--force` option for an upgrade. `down` retains data. `full` includes all four language toolchains; `lite` omits Go/JavaScript script toolchains but retains native HTTP capture. The separate `evidence` build target rejects scripts.

For development, install the dependencies and tools listed in the [main README](../README.md), then run:

```bash
./scripts/verify.sh
./scripts/start_local.sh
```

Browser testing needs a local demo-lab Gateway and an installed Chromium; `npm ci` does not download a browser. Follow the [reproduction guide](docs/VERIFICATION_2.1.0.md) and never expose demo login publicly. That test targets directly host-run services, not container loopback in Compose.

**Execution boundary:** direct host execution or a shared Runner is not hostile-code isolation. Compose networks do not enforce destination-level egress policy. Validate TLS, independent egress controls, containment, host capacity and backup restoration before live work.

### Further documentation and license

[Deployment and restoration](docs/DEPLOYMENT.md) · [Architecture](docs/ARCHITECTURE.md) · [Verification record](docs/VERIFICATION_2.1.0.md) · [Security](SECURITY.md) · [Limitations](LIMITATIONS.md)

Project licensing and the authorized-use notice are in [LICENSE](LICENSE). Never commit credentials, databases or real engagement data.
