# HISN – Secure Web Gateway

نظام مراقبة أمني وتكامل مع **Squid + E2Guardian**. لا ينشئ HISN بروكسي في مسار حركة المرور؛ بل يقرأ السجلات، يطابق مؤشرات التهديدات، يربط الأحداث، ويسجّل القرارات في PostgreSQL. الواجهة: FastAPI وReact/TypeScript.

## حالة النسخة الحالية

**نسخة هندسية تجريبية قابلة للاختبارات المعزولة، وليست جاهزة للنشر الإنتاجي دون تحقق إضافي على Kali Linux.**

- تسجيل دخول بجلسات عشوائية مخزنة كـhash في قاعدة البيانات، Cookies آمنة، CSRF، صلاحيتا `admin` و`viewer`، قفل مؤقت بعد خمس محاولات خاطئة.
- مراقبة موارد النظام وحالة PostgreSQL وSquid وE2Guardian.
- قراءة تدريجية لصيغتي سجلات محددتين مع checkpoints وربط الأحداث بالعميل والوجهة والفترة الزمنية.
- استيراد مؤشرات Domain/IP من CSV محلي موثوق، ومطابقة Domain/IP؛ إظهار مستوى الثقة والمصدر.
- حفظ أحداث وحوادث وقرارات وتدقيق، والكشف عن المحاولات المتكررة بقواعد قابلة للتفسير.
- معالجة قرارات High Confidence مع فحص الاستثناءات؛ الحجب **معطّل افتراضيًا**. عند تفعيله، تُجهَّز النطاقات في قائمة HISN مستقلة، ولا يوصف ذلك بأنه حجب فعلي دون تحقق من E2Guardian.
- صفحات أمنية تعرض بيانات Backend الحقيقية؛ التحكم المحدود في خدمات Linux يتطلب صلاحيات نظام مُعتمدة وإعداد تشغيل صريح.

## البدء

راجع [دليل Kali Linux](docs/KALI_DEPLOYMENT.md) و[القيود](docs/KNOWN_LIMITATIONS.md). **لا تنسخ ملف البيئة السري إلى Git**. مثال إعدادات: `backend/.env.example`.

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with real PostgreSQL credentials and secure cookie setting.
alembic upgrade head
python scripts/create_admin.py
python scripts/create_viewer.py
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

في جلسة ثانية لتشغيل المعالجة:

```bash
cd backend
source .venv/bin/activate
python -m app.jobs.worker --once --log /path/to/test-access.log
# or run continuously only after validating real log layout + permissions:
python -m app.jobs.worker --interval 5
```

Frontend:

```bash
cd frontend
npm ci
npm run build
npm run dev
```

Vite development at `http://localhost:5173` (reverse proxy `/api` to `127.0.0.1:8000`). في التطوير المحلي عبر HTTP فقط، اضبط `HISN_COOKIE_SECURE=false` داخل `.env`؛ في الإنتاج يجب أن تكون `true` مع HTTPS.

## الاختبارات

```bash
cd backend
HISN_DATABASE_URL=sqlite:////tmp/hisn-test.db PYTHONPATH=. pytest -q
```

SQLite في هذا الأمر مخصص للاختبارات المعزولة فقط، ولا يحل محل PostgreSQL للنشر. اقرأ [تقرير الاختبار](docs/TEST_REPORT.md) لمعرفة ما تحقق وما تعذّر فحصه.

## المراجع الداخلية

- [المعمارية](docs/ARCHITECTURE.md)
- [توثيق API](docs/API.md)
- [الأمن والإعدادات](docs/SECURITY.md)
- [Kali Linux](docs/KALI_DEPLOYMENT.md)
- [تقرير التنفيذ والاختبارات](docs/TEST_REPORT.md)
- [القيود المعروفة](docs/KNOWN_LIMITATIONS.md)
"# HISN" 
