import { useEffect, useState } from "react";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import "./App.css";

type CurrentUser = { id: number; username: string; role: "admin" | "viewer" };
function csrfToken(): string {
  return document.cookie.split("; ").find((part) => part.startsWith("hisn_csrf="))?.slice("hisn_csrf=".length) ?? "";
}
export default function App() {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [checking, setChecking] = useState(true);
  const [error, setError] = useState("");
  async function refreshUser(): Promise<void> {
    const response = await fetch("/api/users/me", { credentials: "same-origin", cache: "no-store" });
    if (!response.ok) throw new Error("تعذر التحقق من جلسة المستخدم");
    const data: CurrentUser = await response.json();
    if (!Number.isInteger(data.id) || typeof data.username !== "string" || !["admin", "viewer"].includes(data.role)) {
      throw new Error("بيانات المستخدم غير صالحة");
    }
    setUser(data);
  }
  useEffect(() => {
    let mounted = true;
    fetch("/api/users/me", { credentials: "same-origin", cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) return null;
        return (await response.json()) as CurrentUser;
      })
      .then((data) => {
        if (mounted && data && Number.isInteger(data.id) && ["admin", "viewer"].includes(data.role)) setUser(data);
      })
      .catch(() => { if (mounted) setError("تعذر الاتصال بالخادم"); })
      .finally(() => { if (mounted) setChecking(false); });
    return () => { mounted = false; };
  }, []);
  async function handleLogin() {
    setChecking(true);
    setError("");
    try { await refreshUser(); }
    catch (err) { setUser(null); setError(err instanceof Error ? err.message : "فشل التحقق من الحساب"); }
    finally { setChecking(false); }
  }
  async function handleLogout() {
    try {
      const response = await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrfToken() } });
      if (!response.ok) throw new Error("فشل إنهاء الجلسة على الخادم");
      setUser(null);
      setError("");
    } catch (err) { setError(err instanceof Error ? err.message : "تعذر تسجيل الخروج"); }
  }
  if (checking) return <main className="auth-loading" dir="rtl"><h2>حِصن | HISN</h2><p>جارٍ التحقق من الجلسة...</p></main>;
  if (!user) return <>{error && <p className="auth-error" role="alert" dir="rtl">{error}</p>}<LoginPage onLogin={handleLogin} /></>;
  return <>{error && <p className="auth-error" role="alert" dir="rtl">{error}</p>}<DashboardPage user={user} onLogout={handleLogout} /></>;
}
