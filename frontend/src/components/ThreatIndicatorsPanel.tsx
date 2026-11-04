import { useEffect, useState } from "react";

type Indicator = {
  indicator_id: number;
  indicator_type: string;
  indicator_value: string;
  source_name: string;
  confidence_level: "LOW" | "MEDIUM" | "HIGH";
  is_active: boolean;
  expires_at: string | null;
};

type SearchResult = {
  total: number;
  limit: number;
  offset: number;
  items: Indicator[];
};

const PAGE_SIZE = 25;

function csrfToken() {
  const item = document.cookie
    .split("; ")
    .find(x => x.startsWith("hisn_csrf="));

  return item
    ? decodeURIComponent(item.substring("hisn_csrf=".length))
    : "";
}

function formatDate(value: string | null) {
  if (!value) return "غير محدد";
  const d = new Date(value);
  return Number.isNaN(d.getTime())
    ? value
    : new Intl.DateTimeFormat("ar", {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(d);
}

export default function ThreatIndicatorsPanel() {
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [source, setSource] = useState("");
  const [confidence, setConfidence] = useState("");
  const [active, setActive] = useState("");
  const [page, setPage] = useState(0);
  const [refresh, setRefresh] = useState(0);

  const [result, setResult] = useState<SearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState<number | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setSearch(query.trim());
      setPage(0);
    }, 350);
    return () => window.clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    const controller = new AbortController();

    async function load() {
      setLoading(true);
      setError("");

      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(page * PAGE_SIZE),
      });

      if (search) params.set("q", search);
      if (source.trim()) params.set("source", source.trim());
      if (confidence) params.set("confidence", confidence);
      if (active) params.set("active", active);

      try {
        const response = await fetch(
          `/api/threat-indicators/search?${params.toString()}`,
          {
            credentials: "same-origin",
            cache: "no-store",
            signal: controller.signal,
          }
        );

        if (!response.ok) {
          throw new Error(`فشل تحميل المؤشرات: HTTP ${response.status}`);
        }

        const data: SearchResult = await response.json();

        if (!Array.isArray(data.items) ||
            typeof data.total !== "number") {
          throw new Error("استجابة API غير صالحة");
        }

        if (!controller.signal.aborted) setResult(data);
      } catch (err) {
        if (!controller.signal.aborted) {
          setError(err instanceof Error ? err.message : "خطأ غير معروف");
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }

    void load();
    return () => controller.abort();
  }, [search, source, confidence, active, page, refresh]);

  async function toggleIndicator(item: Indicator) {
    const action = item.is_active ? "تعطيل" : "تفعيل";
    if (!window.confirm(`هل تريد ${action} المؤشر ${item.indicator_value}؟`)) {
      return;
    }

    setBusyId(item.indicator_id);
    setError("");

    try {
      const response = await fetch(
        `/api/threat-indicators/${item.indicator_id}`,
        {
          method: "PATCH",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken(),
          },
          body: JSON.stringify({
            is_active: !item.is_active,
            confidence_level: item.confidence_level,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(`فشل تحديث المؤشر: HTTP ${response.status}`);
      }

      setRefresh(x => x + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "فشل التحديث");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <section dir="rtl" className="hisn-threat-panel">
      <div className="hisn-threat-filters">
        <input
          aria-label="بحث المؤشرات"
          placeholder="بحث عن نطاق أو IP"
          value={query}
          onChange={e => setQuery(e.target.value)}
        />

        <select
          aria-label="مصدر المؤشر"
          value={source}
          onChange={e => { setSource(e.target.value); setPage(0); }}
        >
          <option value="">جميع المصادر</option>
          <option value="ThreatFox">ThreatFox</option>
          <option value="HISN_TEST">HISN_TEST</option>
        </select>

        <select
          aria-label="مستوى الثقة"
          value={confidence}
          onChange={e => { setConfidence(e.target.value); setPage(0); }}
        >
          <option value="">جميع مستويات الثقة</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>

        <select
          aria-label="حالة المؤشر"
          value={active}
          onChange={e => { setActive(e.target.value); setPage(0); }}
        >
          <option value="">جميع الحالات</option>
          <option value="true">نشط</option>
          <option value="false">معطل</option>
        </select>
      </div>

      <div className="hisn-threat-toolbar">
        <strong>
          إجمالي النتائج: {result?.total ?? "—"}
        </strong>
        <button type="button" onClick={() => setRefresh(x => x + 1)}>
          تحديث
        </button>
      </div>

      {loading && <p role="status">جارٍ تحميل المؤشرات...</p>}
      {error && <p role="alert" className="hisn-error">{error}</p>}

      <div className="hisn-table-wrap">
        <table className="hisn-table">
          <thead>
            <tr>
              <th>المؤشر</th>
              <th>النوع</th>
              <th>المصدر</th>
              <th>الثقة</th>
              <th>الحالة</th>
              <th>الصلاحية</th>
              <th>الإجراء</th>
            </tr>
          </thead>
          <tbody>
            {(result?.items ?? []).map(item => (
              <tr key={item.indicator_id}>
                <td className="hisn-indicator-value" dir="ltr">
                  {item.indicator_value}
                </td>
                <td>{item.indicator_type}</td>
                <td>{item.source_name}</td>
                <td>
                  <span className={`hisn-confidence ${item.confidence_level}`}>
                    {item.confidence_level}
                  </span>
                </td>
                <td>{item.is_active ? "نشط" : "معطل"}</td>
                <td>{formatDate(item.expires_at)}</td>
                <td>
                  <button
                    type="button"
                    disabled={busyId !== null}
                    onClick={() => void toggleIndicator(item)}
                  >
                    {busyId === item.indicator_id
                      ? "جارٍ التنفيذ..."
                      : item.is_active ? "تعطيل" : "تفعيل"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {!loading && result?.items.length === 0 &&
          <p>لا توجد مؤشرات مطابقة للبحث.</p>}
      </div>

      <div className="hisn-threat-pagination">
        <button
          type="button"
          disabled={page === 0 || loading}
          onClick={() => setPage(p => Math.max(0, p - 1))}
        >
          السابق
        </button>

        <span>
          الصفحة {page + 1} من{" "}
          {Math.max(1, Math.ceil((result?.total ?? 0) / PAGE_SIZE))}
        </span>

        <button
          type="button"
          disabled={
            loading ||
            !result ||
            (page + 1) * PAGE_SIZE >= result.total
          }
          onClick={() => setPage(p => p + 1)}
        >
          التالي
        </button>
      </div>
    </section>
  );
}
