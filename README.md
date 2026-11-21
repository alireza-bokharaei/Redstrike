# Redstrike | یورش

**ارزیابی امنیتیِ مجاز، کنترل‌شده و قابل‌بررسی**

**Authorized security assessment with policy controls and an auditable workflow**

نسخه / Version **2.3.0** · **Python · Bash · Go · JavaScript · Docker**

[فارسی](#fa) · [English](#en) · [راهنمای فنی / Technical guide](redgate/README.md)

---

<a id="fa"></a>
<div dir="rtl" lang="fa">

## فارسی

### یورش چیست؟

**یورش (Redstrike)** فضای کاری یکپارچه‌ای برای برنامه‌ریزی، اجرای محدود و مستندسازی ارزیابی‌های امنیتیِ مجاز است. اپراتور می‌تواند محدودهٔ یک ارزیابی را تعیین کند، مأموریت بسازد، بررسی‌های فقط‌خواندنی انجام دهد، شواهد HTTP جمع‌آوری کند و نتیجه را برای بازبینی انسانی نگه دارد.

در این پروژه، مدل زبانی جایگزین مجوز مالک دارایی یا تصمیم تحلیلگر نیست. درخواست‌ها از درگاه کنترل سیاست عبور می‌کنند؛ دسترسی اپراتور، محدودهٔ هدف، بازهٔ قواعد درگیری یا **RoE**، سهمیه و سیاست ابزارها در همان مسیر بررسی می‌شوند. **مشاهدهٔ داشبورد یا ذخیرهٔ برنامه به‌تنهایی اسکن را شروع نمی‌کند.**

> **فقط استفادهٔ قانونی و مجاز:** پیش از تماس با هر هدف، مجوز کتبی و محدودهٔ معتبر داشته باشید. تنظیمات نمونه، مجوز آزمایش دارایی‌های واقعی نیستند. [سیاست امنیتی](redgate/SECURITY.md) و [محدودیت‌های اجرایی](redgate/LIMITATIONS.md) را پیش از استقرار بخوانید.

### قابلیت‌ها

- **مدیریت مأموریت:** برنامه‌ریزی و شروع صریح، توقف موقت، ادامه و لغو؛ همراه با بودجهٔ اقدام، مهلت مطلق و ذخیرهٔ پیشرفت. پس از راه‌اندازی مجدد، ادامهٔ تماس با هدف نیازمند اقدام صریح اپراتور است.
- **گراف دارایی و مسیر بررسی:** نمایش موجودی هر ارزیابی و ارتباط میان هدف، اقدام، بررسی، یافته، مدرک و بازآزمایی در رابط SVG با کنترل صفحه‌کلید.
- **شواهد HTTP:** جمع‌آورندهٔ بومی Go برای HEAD/GET ناشناس، اتصال به IP تأییدشده با حفظ Host و TLS SNI و بررسی گواهی. هدرهای احراز هویت داخلی یا کوکی به هدف فرستاده نمی‌شوند و redirect دنبال نمی‌شود.
- **بازآزمایی یافته‌ها:** تکرار بررسی هدرهای امنیتیِ پشتیبانی‌شده در همان endpoint اصلی. نتیجه به تاریخچه افزوده می‌شود؛ مدرک قبلی و نظر تحلیلگر بازنویسی نمی‌شوند.
- **گردش‌کارهای Skills و حافظه:** تعریف زنجیرهٔ بررسی‌ها در YAML و نگهداری یادداشت‌ها در محدودهٔ همان ارزیابی.
- **مدل زبانی قابل‌پیکربندی:** پشتیبانی از Ollama و LM Studio، انتخاب مدل و تنظیمات runtime. حالت پیش‌فرض `mock` بدون دانلود مدل یا فراخوانی سرویس هوش مصنوعی کار می‌کند.
- **کنترل اجرای اسکریپت:** اعتبارسنجی Python، Bash، Go و JavaScript، کنترل SHA-256 و اجرای محدود فرایندها؛ همراه با سیاست ابزار، سهمیه، نقش‌ها و مسیر تأیید دونفره برای عملیات مشمول تأیید.
- **گزارش و عملیات:** خروجی Markdown/JSON، سوابق audit زنجیره‌هش‌شده، پشتیبان‌گیری سازگار با SQLite WAL، چرخش کلید و ابزارهای Bash برای مدیریت سرویس‌ها.
- **حالت‌های عملیاتی و گسترش کنترل‌شده (۲٫۲):** اعلام حالت مأموریت، تحلیل عمیق و اجباری TLS، درخواست گسترش دامنه/بودجه/سهمیه با تأیید فرد دوم و استناد به بند RoE، دروازهٔ هفت‌پرسشی شواهد، کاتالوگ نقش‌های مشورتی و بررسی سخت‌سازی ELF.

### آنچه در ۲٫۲ افزوده شد: حالت‌های عملیاتی و مرز گسترده‌تر

نسخهٔ ۲٫۲ دامنهٔ اختیارات را **بازتر** می‌کند، ولی هیچ‌یک از ثابت‌های کد را حذف نمی‌کند. مأموریت اکنون می‌تواند یک **حالت عملیاتی** اعلام کند؛ سقف اقدام، میزبان و زمان همان حالت از `config/capabilities.yaml` خوانده و روی مأموریت قفل می‌شود:

| حالت | کاربرد | سقف پیش‌فرض |
|---|---|---|
| `vulnerability_discovery` | کشف نظام‌مند آسیب‌پذیری | ۸ میزبان / ۶۴ اقدام / ۱۸۰۰ ثانیه |
| `bug_bounty` | چرخهٔ شکار و پیش‌نویس گزارش | ۸ / ۶۴ / ۱۸۰۰ |
| `pentest` | ارزیابی سرتاسری مجاز | ۸ / ۶۴ / ۱۸۰۰ |
| `ctf` | حل چالش، بدون گسترش شبکه | ۴ / ۳۲ / ۹۰۰ |
| `assessment` | بازبینی پیکربندی و سخت‌سازی | ۸ / ۴۸ / ۱۸۰۰ |

- **تحلیل عمیق SSL/TLS الزامی است.** در هر حالت دارای سطح TLS، اسکن پروتکل (TLS 1.0 تا 1.3)، کشف رمزهای ضعیف، بررسی گواهی (انقضا، SAN، اندازهٔ کلید، الگوریتم امضا، زنجیرهٔ اعتماد) و HSTS انجام می‌شود. اتصال همیشه به IP تأییدشده Pin می‌شود و SNI اصلی حفظ می‌شود. نتیجه به‌صورت رکورد تغییرناپذیر و هش‌شده ذخیره می‌شود.
- **درخواست گسترش میان‌مأموریت.** اپراتور می‌تواند هدف، بودجه، سهمیه یا سطح بازبینی بیشتری **درخواست** کند. تا زمانی که فرد دیگری آن را تأیید نکند هیچ چیز تغییر نمی‌کند. هر درخواست باید به یک **بند صریح RoE** در `allowlist.yaml` استناد کند؛ انگیزشی که چنین بندی ندارد اصلاً قابل گسترش نیست.
- **دروازهٔ هفت‌پرسشی شواهد.** یک یافته فقط وقتی «تأییدشده» است که هر هفت پرسش با شواهد قطعی و قابل تکرار پاسخ بگیرد. خروجی مدل زبانی به‌تنهایی هرگز پرسش‌های بازدارنده را رد نمی‌کند.
- **کاتالوگ نقش‌های مشورتی.** ۲۱ نقش (recon، hunter، chain-builder، devil's advocate، report-writer و …) فقط برنامه می‌دهند؛ نه ابزاری اجرا می‌کنند، نه دامنه را گسترش می‌دهند، نه یافته‌ای را تأیید می‌کنند.
- **لایهٔ دودویی محدود.** برای مأموریت‌های CTF/باینری، بررسی فقط‌خواندنی سخت‌سازی ELF (NX، PIE، RELRO، canary، RPATH، بخش‌های W+X) با کتابخانهٔ استاندارد پایتون انجام می‌شود. `pwntools` وارد یا فراخوانی نمی‌شود و هیچ قابلیت ساخت اکسپلویت وجود ندارد.

**ثابت‌های غیرقابل‌تغییر (در ۲٫۲ هم پابرجا):** فلگ‌های ممنوع `nmap`/`sqlmap` در کد قفل‌اند، رنج‌های متادیتای ابری همیشه مسدودند، قاعدهٔ دو‌نفره در سطح دیتابیس اعمال می‌شود، و اجرای اسکریپت همچنان به اعتبارسنجی استاتیک و هش SHA-256 وابسته است. هیچ حالت یا تأییدی نمی‌تواند این‌ها را باز کند.

### معماری و فناوری‌ها

| بخش | مسئولیت |
|---|---|
| **رابط وب — JavaScript و SVG** | کنسول اپراتور، مأموریت‌ها، گراف‌ها، شواهد و گزارش؛ بدون CDN یا سرور جداگانهٔ فرانت‌اند در زمان اجرا |
| **Gateway — Python / FastAPI** | API، احراز هویت، محدوده و RoE، سیاست‌ها، هماهنگی مأموریت و اعتبارسنجی خروجی مدل |
| **MCP — Python** | سرویس داخلی ابزارها با احراز هویت و ورودی محدود |
| **Runner — Go** | جمع‌آوری بومی شواهد HTTP و اجرای محدود اسکریپت‌های تأییدشده |
| **SQLite** | داده‌های ارزیابی، حافظه، پیشرفت مأموریت، شواهد و سوابق؛ همراه با WAL و migrationهای افزایشی |
| **Bash و Docker Compose** | راه‌اندازی، اعتبارنامه، پشتیبان‌گیری، بسته‌بندی و تفکیک شبکه‌های کنترل، هدف و inference |

پیکربندی فعلی برای **یک فرایند Gateway به‌ازای هر پایگاه دادهٔ SQLite** است، نه زمان‌بند توزیع‌شده. پروفایل اختیاری PostgreSQL در Compose صرفاً سرویس پایگاه داده را ایجاد می‌کند و backend برنامه را تغییر نمی‌دهد.

### نصب و راه‌اندازی با Docker

پیش‌نیازها: **Linux، Git، Docker Engine، Docker Compose نسخهٔ ۲٫۲۰ یا بالاتر و BuildKit**. اسکریپت ساخت اعتبارنامه به OpenSSL یا Python 3 نیز نیاز دارد.

<div dir="ltr">

```bash
git clone https://github.com/alireza-bokharaei/Redstrike.git
cd Redstrike/redgate
./scripts/bootstrap_env.sh
./scripts/redgate.sh doctor
./scripts/redgate.sh up --full
```

</div>

اگر مخزن را از قبل دریافت کرده‌اید، از ریشهٔ آن وارد پوشهٔ `redgate/` شوید. اسکریپت `bootstrap_env.sh` برای راه‌اندازی اولیه است؛ فایل `.env` موجود را بدون `--force` جایگزین نمی‌کند. **از `--force` برای ارتقای معمول استفاده نکنید؛ همهٔ توکن‌های اپراتور و سرویس را عوض می‌کند.**

1. توکن‌های خصوصی نمایش‌داده‌شده را همان بار اول در محل امن ذخیره کنید؛ فقط هش توکن‌های اپراتور در `.env` می‌ماند.
2. آدرس **http://127.0.0.1:8000** را باز کنید و از دکمهٔ **Token** وارد شوید.
3. پیش از بررسی واقعی، محدوده و زمان اعتبار را در `config/allowlist.yaml` و دسترسی‌ها را در `config/operators.yaml` با مجوز خود تطبیق دهید.
4. مستندات تعاملی API در `/docs` است. مسیرهای `/healthz` و `/readyz` برای بررسی سرویس در دسترس‌اند.

Compose فقط پورت Gateway را روی loopback میزبان منتشر و ورود demo را غیرفعال می‌کند. MCP و Runner پورت عمومی ندارند. دسترسی راه دور باید پشت TLS و کنترل دسترسی شبکه قرار بگیرد.

### حالت‌های اجرا و فرمان‌های روزمره

| حالت | کاربرد و محدودیت |
|---|---|
| **`full`** | حالت پیش‌فرض؛ شامل ابزارهای اعتبارسنجی و اجرای هر چهار زبان |
| **`lite`** | شامل ابزارهای اسکریپت Python/Bash و جمع‌آورندهٔ بومی Go؛ بدون اعتبارسنجی یا اجرای اسکریپت Go/JavaScript |
| **`evidence`** | هدف ساخت جداگانهٔ Runner که اجرای اسکریپت را رد می‌کند؛ حالت کامل Compose نیست |

<div dir="ltr">

```bash
./scripts/redgate.sh up --lite
./scripts/redgate.sh status
./scripts/redgate.sh logs gateway
./scripts/redgate.sh backup
./scripts/redgate.sh down
```

</div>

فرمان `logs` تا Ctrl+C باز می‌ماند. پشتیبان، snapshot سازگار SQLite را به‌صورت gzip با دسترسی `0600` در `backups/` ذخیره می‌کند. فرمان `down` داده‌های named volume را نگه می‌دارد. **برای ارتقا از `down --volumes` استفاده نکنید.** پیش از ارتقا، پشتیبان بگیرید و فرایند بازیابی را در محیط آزمایشی بررسی کنید.

### جریان یک ارزیابی

1. **تعریف محدوده:** مجوز، اهداف، بازهٔ RoE، نقش‌ها، سهمیه و سیاست ابزارها را بازبینی کنید.
2. **برنامه‌ریزی:** ارزیابی یا engagement مجاز را انتخاب و مأموریت را با هدف، Skill و بودجهٔ محدود ذخیره کنید.
3. **شروع صریح:** مأموریت را شروع کنید؛ وضعیت، پیشرفت و مسیر بررسی در کنسول قابل مشاهده است.
4. **بازبینی شواهد:** یافته‌ها، هدرها، پیش‌نمایش مجاز و ارتباطات گراف را بررسی کنید. وجود یک دارایی در گراف، اثبات بررسی‌شدن یا امن‌بودن آن نیست.
5. **بازآزمایی و گزارش:** بررسی‌های پشتیبانی‌شده را با تصمیم صریح تکرار و گزارش Markdown یا JSON را برای تحلیل انسانی دریافت کنید.

هر مأموریت **۱ تا ۸ میزبان**، **۱ تا ۶۴ اقدام** با پیش‌فرض ۲۴، و **۱۰ تا ۱۸۰۰ ثانیه** با پیش‌فرض ۳۰۰ می‌پذیرد. با اعلام یک حالت ۲٫۲، سقف همان حالت اعمال می‌شود و اعلام‌نکردن حالت یعنی همان محدودهٔ پیش‌فرض ۲٫۱ باقی می‌ماند. هم‌زمان حداکثر **دو مأموریت در کل سامانه و یک مأموریت برای هر مالک** اجرا می‌شود. توقف موقت، مهلت را تمدید نمی‌کند و بودجهٔ اقدام رزروشده یا ناموفق بازگردانده نمی‌شود.

### مدل زبانی محلی

برای نوشتن تنظیمات اولیهٔ Ollama قابل‌دسترسی از Compose، بعد از bootstrap و از پوشهٔ `redgate/`:

<div dir="ltr">

```bash
./scripts/setup_local_llm.sh --compose ollama
```

</div>

این فرمان **وزن مدل را دانلود و سرویس inference را راه‌اندازی نمی‌کند**. دریافت مدل فقط با گزینهٔ صریح `--pull` انجام می‌شود و ممکن است چندین گیگابایت باشد. راهنما و گزینه‌ها:

<div dir="ltr">

```bash
./scripts/setup_local_llm.sh --help
```

</div>

برای Gateway روی میزبان از `--local` استفاده کنید. LM Studio در Compose به `--base-url` قابل‌دسترسی از داخل کانتینر و تنظیم مسیریابی میزبان نیاز دارد؛ `127.0.0.1` داخل کانتینر، میزبان شما نیست.

تنظیمات runtime ذخیره‌شده در SQLite بر مقادیر اولیهٔ `.env` اولویت دارند. برای پایگاه دادهٔ موجود، تنظیمات را از بخش **Local AI → Runtime** به‌روز کنید. اجرای واقعاً محلی به endpoint محلی، وزن‌های از قبل آماده و منابع سخت‌افزاری کافی نیاز دارد؛ مجوز و اندازهٔ مدل را جداگانه بررسی کنید.

### توسعه و تست

برای مجموعهٔ کامل بررسی‌ها به **Python 3.11+، Go 1.22+، Node.js 22.13+ و ShellCheck** نیاز دارید. از ریشهٔ مخزن:

<div dir="ltr">

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r redgate/requirements-dev.txt
cd redgate
npm ci --ignore-scripts
./scripts/verify.sh
./scripts/start_local.sh
```

</div>

`verify.sh` شامل بررسی Bash/ShellCheck، نحو JavaScript و ESLint، تست‌های رابط، تست race و vet و build در Go، Ruff و مجموعهٔ تست‌های Python است. اعتبارسنجی Compose فقط در صورت وجود ابزار و `.env` انجام می‌شود؛ این اسکریپت به‌تنهایی ساخت و اجرای کانتینر را اثبات نمی‌کند.

راه‌انداز محلی به‌طور پیش‌فرض loopback، حالت `mock` و اعتبارنامهٔ موقت خصوصی دارد؛ مسیر فایل توکن‌ها را چاپ می‌کند و `.env` را خودکار به shell وارد نمی‌کند. این اجرا جای جداسازی میزبان را نمی‌گیرد. حالت `REDGATE_DEMO_MODE=true` فقط برای آزمایشگاه خصوصی است؛ هر فردی که به چنین Gatewayای دسترسی داشته باشد می‌تواند هویت آزمایشی بگیرد.

### مرزهای امنیتی و عملیاتی

- Runner، sandbox کامل سیستم‌عامل یا ماشین مجازی نیست. پیش از اجرای کد نامطمئن، به جداسازی مناسب و سیاست خروجی مستقلِ **default-deny برای IPv4 و IPv6** نیاز دارید. شبکه‌های Compose به‌تنهایی firewall مقصد نیستند و Redstrike قوانین پیشنهادی firewall را نصب نمی‌کند.
- شواهد به‌طور پیش‌فرض با **HEAD و بدون بدنه** ذخیره می‌شوند. پیش‌نمایش متنی فقط با GET صریح و حداکثر **۸ کیبی‌بایت** است. پالایش الگو‌محور، حذف همهٔ اسرار و اطلاعات شخصی را تضمین نمی‌کند.
- SHA-256 مدرک، همان نمای **ذخیره‌شده و پالایش‌شده** را کنترل می‌کند، نه اصالت بستهٔ خام شبکه. حفاظت از میزبان، پایگاه داده و پشتیبان‌ها همچنان لازم است.
- `not_observed` به معنای رفع قطعی آسیب‌پذیری نیست. شناسایی، اهمیت کسب‌وکاری و نتیجهٔ نهایی باید توسط انسان بازبینی شوند.
- لغو، درخواست قبلاً ارسال‌شده را پس نمی‌گیرد. پس از وقفه ممکن است اقدام بدون checkpoint تکرار شود؛ اجرای شبکه تضمین exactly-once ندارد.
- مقدارهای محدودیت منابع در Compose، سنجش کارایی نیستند. برای میزبان واقعی، منابع، جداسازی، بازیابی و مدل inference را جداگانه آزمایش کنید؛ کاهش اندازه یا افزایش سرعتِ اندازه‌گیری‌نشده ادعا نمی‌شود.

### مستندات و مجوز

- [راهنمای فنی و API](redgate/README.md)
- [معماری و یکپارچگی داده](redgate/docs/ARCHITECTURE.md)
- [استقرار، پشتیبان‌گیری، ارتقا و بازیابی](redgate/docs/DEPLOYMENT.md)
- [گزارش بررسی‌ها و روش تکرار تست مرورگر](redgate/docs/VERIFICATION_2.1.0.md)
- [حالت‌های عملیاتی و گسترش کنترل‌شدهٔ ۲٫۲](redgate/docs/CAPABILITY_MODES.md)
- [امنیت](redgate/SECURITY.md) · [محدودیت‌ها](redgate/LIMITATIONS.md) · [گردش‌کارهای CI](.github/workflows/verify.yml)

Redstrike با مجوز **MIT**، همراه با اخطار استفادهٔ مجاز درج‌شده در [LICENSE](redgate/LICENSE)، منتشر می‌شود. وابستگی‌ها، ابزارها و مدل‌های مورد استفاده، مجوزهای خود را دارند. اعتبارنامه‌ها، داده‌های ارزیابی و خروجی‌های اجرایی را وارد Git نکنید.

</div>

---

<a id="en"></a>

## English

### What is Redstrike?

**Redstrike** is an integrated workspace for planning, bounded execution and documentation of authorized security assessments. Operators can define an engagement's scope, create missions, perform read-only checks, collect HTTP evidence and retain results for human review.

A language model does not replace asset-owner authorization or an analyst's judgment. Requests pass through the governance gateway, where operator access, target scope, the **Rules of Engagement (RoE)** window, quotas and tool policies are checked. **Viewing a dashboard or saving a plan does not itself start a scan.**

> **Lawful, authorized use only:** obtain written permission and a valid scope before contacting any target. Sample configuration is not authorization to test real assets. Read the [security policy](redgate/SECURITY.md) and [operational limitations](redgate/LIMITATIONS.md) before deployment.

### Capabilities

- **Mission management:** plan and explicitly start, pause, resume or cancel work, with finite action/deadline budgets and saved progress. Target contact never automatically resumes after a restart.
- **Asset and exploration graphs:** view engagement inventory and relationships between goals, actions, checks, findings, evidence and retests through keyboard-operable SVG graphs.
- **HTTP evidence:** a native Go collector makes anonymous HEAD/GET requests, pins the actual connection to an approved IP, preserves Host/TLS SNI and verifies certificates. It forwards no internal authorization headers or cookies and follows no redirects.
- **Finding retests:** repeat supported missing-security-header checks at the original endpoint. Append observations without overwriting previous evidence or the analyst's verdict.
- **Skills and memory:** define check pipelines in YAML and keep notes scoped to their engagement.
- **Configurable language models:** support for Ollama and LM Studio, model selection and runtime settings. Default `mock` mode requires no model download or AI-service call.
- **Script execution controls:** Python, Bash, Go and JavaScript validation, SHA-256 checks and bounded process execution, alongside tool policies, quotas, roles and a two-person approval path where required.
- **Reporting and operations:** Markdown/JSON exports, hash-chained audit records, WAL-consistent SQLite backups, key rotation and Bash service-management helpers.
- **Operational modes and governed expansion (2.2):** mission mode declaration, mandatory deep TLS analysis, RoE-clause-bound expansion requests for scope/budget/quota with independent approval, the seven-question evidence gate, an advisory agent-role catalogue and ELF hardening triage.
- **Governed offensive surface (2.3):** 144 catalogued tools behind a declarative per-tool flag policy, a permissive-in-scope posture with two-person approval reserved for high-impact actions, a PoC lifecycle with independent reproduction, attack chains, recursive discovery with budgeted mass scanning, a bug-bounty workflow, a pwntools layer and 49 advisory agents with hunt loops and an append-only reasoning brain.

### New in 2.3: a wide offensive surface, one control model

Version 2.3 makes the platform *capable* of real offensive work — 144 tools across
DNS, network, web, injection, TLS, cloud, Active Directory, password, OSINT,
binary, exploit-search and reporting — while keeping the boundary where 2.1 put
it: a signed scope, an allowlist, DNS pinning, cloud-metadata denial and an
append-only audit ledger.

The control model is deliberately asymmetric:

| Action | Approval |
|---|---|
| Read-only checks (headers, DNS, TLS, TCP probe) | none |
| Ordinary active testing (nmap, nuclei, ffuf, gobuster, content discovery) | operator acknowledgement of the posture |
| High-impact: state-changing PoC, credential handling, mass scanning beyond budget, online auth attempts | **two people** |

A posture decides how much *asking* happens, never *what is reachable*:
`posture:ctf_aggressive` still refuses an out-of-scope target and still refuses
`sqlmap --os-shell`. Timing (`-T4`) is a policy row a mission can opt into;
capability flags that turn a finding into a compromise stay refused always.

Three parts are deliberately honest about this sandbox: the catalogue lists 144
tools but only four binaries are installed here, `pwntools` is not installed
(−> `status: unavailable`, never invented output), and bug-bounty sync has no
credentials (−> scope stays `source: manual`, duplicate checks stay `unverified`).
Full detail: [redgate/docs/OFFENSIVE_SURFACE.md](redgate/docs/OFFENSIVE_SURFACE.md)
and [redgate/docs/VERIFICATION_2.3.md](redgate/docs/VERIFICATION_2.3.md).

### New in 2.2: operational modes and a widened — still governed — boundary

Version 2.2 widens *what a mission may do* without removing a single code-level invariant. A mission can declare an **operational mode**; its host, action and time ceilings come from `config/capabilities.yaml` and are frozen onto the mission:

| Mode | Purpose | Default ceiling |
|---|---|---|
| `vulnerability_discovery` | Systematic vulnerability discovery | 8 hosts / 64 actions / 1800 s |
| `bug_bounty` | Hunting loop and report drafting | 8 / 64 / 1800 |
| `pentest` | Full authorised engagement | 8 / 64 / 1800 |
| `ctf` | Challenge solving, no network widening | 4 / 32 / 900 |
| `assessment` | Configuration and hardening review | 8 / 48 / 1800 |

- **Deep SSL/TLS analysis is mandatory.** Every TLS-bearing mode sweeps the protocol floor (TLS 1.0–1.3), detects weak ciphers, inspects the certificate (expiry, SAN coverage, key size, signature algorithm, trust chain) and HSTS. Each handshake is pinned to a scope-validated IP while keeping the original SNI. Results are stored as immutable, hashed records.
- **Mid-engagement expansion.** An operator may *request* extra targets, budget, quota or review level. Nothing changes until a **different** person approves. Every request must cite an explicit **RoE clause** declared in `allowlist.yaml`; an engagement without such a clause cannot be widened at all.
- **Seven-question evidence gate.** A finding is `confirmed` only when all seven questions pass with deterministic, reproducible evidence. Model text alone can never satisfy a blocking question; it produces a `rejected` observation instead.
- **Advisory agent catalogue.** 21 roles (recon, hunters, chain-builder, devil's advocate, report-writer, …) plan only: they cannot execute a tool, widen scope, approve, or confirm a finding.
- **Restricted binary layer.** For CTF/binary missions, read-only ELF hardening triage (NX, PIE, RELRO, canary, RPATH, W+X segments) runs on the Python standard library. `pwntools` is not imported or invoked, and no exploit generation exists.

**Unchanged invariants:** the `nmap`/`sqlmap` flag blocklists stay in code, cloud-metadata ranges stay denied, the Two-Person Rule is enforced by the database, and script execution still requires static validation plus SHA-256 pinning. No mode or approval can unlock them.

### Architecture and technology

| Component | Responsibility |
|---|---|
| **Web console — JavaScript and SVG** | Operator workspace, missions, graphs, evidence and reports; no runtime CDN or separate frontend server |
| **Gateway — Python / FastAPI** | API, authentication, scope/RoE, policies, mission coordination and model-output validation |
| **MCP — Python** | Authenticated internal tool service with constrained inputs |
| **Runner — Go** | Native HTTP evidence capture and bounded execution of approved scripts |
| **SQLite** | Engagement data, memory, mission progress, evidence and ledgers, with WAL and additive migrations |
| **Bash and Docker Compose** | Lifecycle, credentials, backups, packaging and separate control, target-egress and inference networks |

The current deployment model uses **one Gateway process per SQLite database**, not a distributed scheduler. The optional PostgreSQL Compose profile provisions a database service only; it does not change the application's backend.

### Install and start with Docker

Requirements: **Linux, Git, Docker Engine, Docker Compose v2.20+ and BuildKit**. Credential bootstrap also needs OpenSSL or Python 3.

```bash
git clone https://github.com/alireza-bokharaei/Redstrike.git
cd Redstrike/redgate
./scripts/bootstrap_env.sh
./scripts/redgate.sh doctor
./scripts/redgate.sh up --full
```

For an existing checkout, enter `redgate/` from the repository root. `bootstrap_env.sh` is for initial setup and refuses to overwrite an existing `.env` without `--force`. **Do not use `--force` for a routine upgrade: it rotates all operator and service tokens.**

1. Save the private tokens when first printed; only operator-token hashes remain in `.env`.
2. Open **http://127.0.0.1:8000** and sign in using **Token**.
3. Before live work, replace the sample scope/RoE in `config/allowlist.yaml` and review access in `config/operators.yaml` against your authorization.
4. Interactive API documentation is at `/docs`; `/healthz` and `/readyz` expose service checks.

Compose publishes only the Gateway port on host loopback and disables demo login. MCP and Runner have no published ports. Remote access requires TLS and network access control.

### Runtime modes and daily commands

| Mode | Purpose and limits |
|---|---|
| **`full`** | Default; includes validation/execution toolchains for all four languages |
| **`lite`** | Python/Bash script toolchains and the native Go collector; no Go/JavaScript script validation or execution |
| **`evidence`** | Separate Runner build target that rejects script execution, not a complete Compose mode |

```bash
./scripts/redgate.sh up --lite
./scripts/redgate.sh status
./scripts/redgate.sh logs gateway
./scripts/redgate.sh backup
./scripts/redgate.sh down
```

`logs` follows output until Ctrl+C. Backup writes a consistent SQLite snapshot as gzip with mode `0600` to `backups/`. `down` retains named-volume data. **Never use `down --volumes` for an upgrade.** Back up first and rehearse restoration in staging.

### Assessment workflow

1. **Define scope:** review authorization, targets, the RoE window, roles, quotas and tool policies.
2. **Plan:** select an authorized engagement and save a mission with its goal, Skill and finite budgets.
3. **Start explicitly:** launch the mission and follow its status, progress and exploration trail in the console.
4. **Review evidence:** inspect findings, headers, permitted previews and graph relationships. Inventory is not tested coverage or proof of security.
5. **Retest and report:** explicitly repeat supported checks and export Markdown or JSON for human analysis.

A mission accepts **1–8 hosts**, **1–64 actions** (default 24) and **10–1800 seconds** (default 300). Declaring a 2.2 mode applies that mode's ceiling instead; omitting the mode keeps the legacy 2.1 bounds unchanged. At most **two missions globally and one per owner** execute concurrently. Pausing does not extend the deadline; failed or reserved actions are not refunded.

### Local language models

After bootstrap, run from `redgate/` to write initial container-reachable Ollama settings:

```bash
./scripts/setup_local_llm.sh --compose ollama
```

This command **does not download model weights or start an inference service**. Downloads require explicit `--pull` and may consume many GB. Inspect the helper's options with:

```bash
./scripts/setup_local_llm.sh --help
```

Use `--local` for a host-run Gateway. LM Studio with Compose requires a container-reachable `--base-url` and operator-configured host routing: container `127.0.0.1` is not your host.

Saved SQLite runtime settings override initial `.env` values. For an existing database, update the settings through **Local AI → Runtime**. Truly local execution requires a local endpoint, prepared weights and adequate hardware; review model size and licensing separately.

### Development and tests

Complete verification requires **Python 3.11+, Go 1.22+, Node.js 22.13+ and ShellCheck**. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r redgate/requirements-dev.txt
cd redgate
npm ci --ignore-scripts
./scripts/verify.sh
./scripts/start_local.sh
```

`verify.sh` runs Bash/ShellCheck, JavaScript syntax/ESLint and interface tests, Go race/vet/build, Ruff and the Python suite. Compose configuration is checked only when the CLI and `.env` are available; this script alone does not establish image build/runtime behavior.

The local launcher defaults to loopback, `mock` AI and temporary private credentials; it prints the token-file path and does not automatically source `.env`. It is not host isolation. `REDGATE_DEMO_MODE=true` is for private labs only: anyone reaching such a Gateway can obtain a lab identity.

### Security and operational boundaries

- The Runner is not a complete OS sandbox or VM. Untrusted code requires appropriate independent containment and externally enforced **default-deny IPv4/IPv6 egress**. Compose networks alone are not destination firewalls; Redstrike does not install its rendered firewall rules.
- Evidence defaults to **HEAD without a response body**. Text previews require explicit GET and are capped at **8 KiB**. Heuristic redaction cannot guarantee removal of all secrets or personal data.
- Evidence SHA-256 checks cover the **stored, redacted representation**, not raw-wire authenticity. Protect the host, database and backups independently.
- `not_observed` does not prove remediation. Identification, business impact and final conclusions require human review.
- Cancellation cannot retract sent traffic. An interrupted action without a checkpoint may be repeated; network execution is not exactly-once.
- Compose resource settings are not performance measurements. Validate resources, containment, restoration and inference on your intended host; no unmeasured image-size or speed advantage is asserted.

### Documentation and license

- [Technical guide and API](redgate/README.md)
- [Architecture and data integrity](redgate/docs/ARCHITECTURE.md)
- [Deployment, backups, upgrades and restoration](redgate/docs/DEPLOYMENT.md)
- [Verification record and reproducible browser test](redgate/docs/VERIFICATION_2.1.0.md)
- [2.2 operational modes and governed expansion](redgate/docs/CAPABILITY_MODES.md)
- [2.3 offensive surface: control model, tools, lifecycle, agents](redgate/docs/OFFENSIVE_SURFACE.md)
- [2.3 live verification record](redgate/docs/VERIFICATION_2.3.md)
- [Security](redgate/SECURITY.md) · [Limitations](redgate/LIMITATIONS.md) · [CI workflow](.github/workflows/verify.yml)

Redstrike is distributed under the **MIT License**, with an authorized-use notice in [LICENSE](redgate/LICENSE). Dependencies, tools and models retain their respective licenses. Never commit credentials, engagement data or runtime artifacts to Git.
