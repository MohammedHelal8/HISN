
import {
  useEffect,
  useState,
  type FormEvent,
} from "react";

import "../App.css";

type LoginPageProps = {
  onLogin: () => void | Promise<void>;
};

const LOCKOUT_STORAGE_KEY = "hisn_login_locked_until";

function readLockoutDeadline(): number {
  const stored = sessionStorage.getItem(LOCKOUT_STORAGE_KEY);
  const deadline = Number(stored);

  if (!stored || !Number.isFinite(deadline)) {
    return 0;
  }

  if (deadline <= Date.now()) {
    sessionStorage.removeItem(LOCKOUT_STORAGE_KEY);
    return 0;
  }

  return deadline;
}

function LoginPage({ onLogin }: LoginPageProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [lockedUntil, setLockedUntil] = useState<number>(
    readLockoutDeadline
  );

  const [now, setNow] = useState(Date.now());

  const remainingSeconds = Math.max(
    0,
    Math.ceil((lockedUntil - now) / 1000)
  );

  const isLocked = remainingSeconds > 0;

  useEffect(() => {
    if (!lockedUntil) return;

    const interval = window.setInterval(() => {
      const currentTime = Date.now();
      setNow(currentTime);

      if (currentTime >= lockedUntil) {
        sessionStorage.removeItem(LOCKOUT_STORAGE_KEY);
        setLockedUntil(0);
        setError("");
      }
    }, 250);

    return () => window.clearInterval(interval);
  }, [lockedUntil]);

  function activateLockout(seconds: number) {
    const safeSeconds = Math.max(
      1,
      Math.min(3600, Math.ceil(seconds))
    );

    const deadline = Date.now() + safeSeconds * 1000;

    sessionStorage.setItem(
      LOCKOUT_STORAGE_KEY,
      String(deadline)
    );

    setNow(Date.now());
    setLockedUntil(deadline);
    setPassword("");
    setError("");
  }

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>
  ) {
    event.preventDefault();

    if (loading || isLocked) return;

    setLoading(true);
    setError("");

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: username.trim(),
          password,
        }),
      });

      if (response.status === 429) {
        const retryAfterHeader =
          response.headers.get("Retry-After");

        const parsedSeconds = Number(retryAfterHeader);

        const retrySeconds =
          retryAfterHeader &&
          Number.isFinite(parsedSeconds) &&
          parsedSeconds > 0
            ? parsedSeconds
            : 60;

        activateLockout(retrySeconds);
        return;
      }

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error(
            "اسم المستخدم أو كلمة المرور غير صحيحة"
          );
        }

        if (response.status === 422) {
          throw new Error(
            "يرجى التأكد من البيانات المدخلة"
          );
        }

        throw new Error(
          "تعذر تسجيل الدخول. حاول مرة أخرى."
        );
      }

      sessionStorage.removeItem(LOCKOUT_STORAGE_KEY);
      setLockedUntil(0);
      setPassword("");
      await onLogin();
    } catch (err) {
      setError(
        err instanceof TypeError
          ? "تعذر الاتصال بالخادم. تأكد من تشغيل FastAPI."
          : err instanceof Error
            ? err.message
            : "حدث خطأ غير متوقع"
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="login-page">
      <div className="login-container">
        <section className="brand-panel">
          <div className="brand">
            <div className="brand-icon">⬡</div>
            <div>
              <h2>حِصن | HISN</h2>
              <span>SECURE WEB GATEWAY</span>
            </div>
          </div>

          <div className="brand-content">
            <div className="security-icon">🛡</div>
            <h1>منصة حِصن للأمن السيبراني</h1>
            <p>
              مراقبة الأنشطة الشبكية، واكتشاف التهديدات،
              وتحليل الأحداث الأمنية من خلال منصة موحدة.
            </p>

            <div className="security-label">
              ● SECURE ADMINISTRATION PORTAL
            </div>
          </div>

          <div className="brand-footer">
            HISN Security Engine
          </div>
        </section>

        <section className="form-panel" dir="rtl">
          <div className="form-header">
            <h2>مرحبًا بعودتك</h2>
            <p>سجّل الدخول للوصول إلى لوحة تحكم حِصن</p>
          </div>

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="username">
                اسم المستخدم
              </label>

              <input
                id="username"
                type="text"
                placeholder="أدخل اسم المستخدم"
                autoComplete="username"
                value={username}
                onChange={(event) =>
                  setUsername(event.target.value)
                }
                disabled={loading || isLocked}
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="password">
                كلمة المرور
              </label>

              <div className="password-field">
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="أدخل كلمة المرور"
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) =>
                    setPassword(event.target.value)
                  }
                  disabled={loading || isLocked}
                  required
                />

                <button
                  type="button"
                  className="toggle-password"
                  onClick={() =>
                    setShowPassword(!showPassword)
                  }
                  disabled={loading || isLocked}
                >
                  {showPassword ? "إخفاء" : "إظهار"}
                </button>
              </div>
            </div>

            {isLocked && (
              <div
                className="login-lockout"
                role="alert"
                aria-live="polite"
              >
                <strong>تم إيقاف تسجيل الدخول مؤقتًا</strong>

                <p>
                  تم تجاوز الحد المسموح لمحاولات
                  تسجيل الدخول الفاشلة.
                </p>

                <p>
                  يمكنك المحاولة مجددًا بعد:
                </p>

                <div className="lockout-timer">
                  {String(
                    Math.floor(remainingSeconds / 60)
                  ).padStart(2, "0")}
                  :
                  {String(
                    remainingSeconds % 60
                  ).padStart(2, "0")}
                </div>
              </div>
            )}

            {error && !isLocked && (
              <p className="login-error" role="alert">
                {error}
              </p>
            )}

            <button
              className="login-button"
              type="submit"
              disabled={loading || isLocked}
            >
              {isLocked
                ? `الحساب مقفل (${remainingSeconds} ثانية)`
                : loading
                  ? "جارٍ التحقق..."
                  : "تسجيل الدخول"}
            </button>
          </form>

          <div className="form-footer">
            الوصول مخصص لمسؤولي النظام المصرح لهم فقط
          </div>
        </section>
      </div>
    </main>
  );
}

export default LoginPage;
