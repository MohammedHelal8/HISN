import { useCallback, useEffect, useState } from "react";

type ClientRecord = {
  client_ip: string;
  events: number;
  incidents: number;
  last_activity: string | null;
};

type ClientsResponse = {
  total: number;
  clients: ClientRecord[];
  note?: string;
};

export default function ClientSecurityPanel() {
  const [data, setData] = useState<ClientsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");

  const loadClients = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch("/api/clients", {
        credentials: "include",
        headers: { Accept: "application/json" },
        cache: "no-store",
      });

      if (!response.ok) {
        throw new Error(
          response.status === 401
            ? "انتهت الجلسة. سجّل الدخول مجددًا."
            : `فشل تحميل الأجهزة (${response.status})`
        );
      }

      const result: ClientsResponse = await response.json();
      setData(result);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "خطأ غير معروف"
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadClients();
  }, [loadClients]);

  const filtered = (data?.clients ?? []).filter((client) =>
    client.client_ip.toLowerCase().includes(search.toLowerCase())
  );

  const formatDate = (value: string | null) => {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? value
      : date.toLocaleString("ar", {
          dateStyle: "medium",
          timeStyle: "medium",
        });
  };

  return (
    <section dir="rtl" style={{ padding: 20 }}>
      <header
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 16,
          flexWrap: "wrap",
          marginBottom: 20,
        }}
      >
        <div>
          <h2>الأجهزة الطرفية</h2>
          <p>
            الأجهزة التي رصد HISN لها أحداثًا أمنية عبر بوابة الويب
          </p>
        </div>

        <button type="button" onClick={() => void loadClients()}>
          تحديث البيانات
        </button>
      </header>

      {error && <p role="alert" style={{ color: "#dc2626" }}>{error}</p>}

      <div
        style={{
          display: "flex",
          gap: 16,
          marginBottom: 20,
          flexWrap: "wrap",
        }}
      >
        <div>
          <strong>الأجهزة المرصودة: </strong>
          {data?.total ?? 0}
        </div>
        <div>
          <strong>الأحداث الأمنية: </strong>
          {data?.clients.reduce((sum, item) => sum + item.events, 0) ?? 0}
        </div>
      </div>

      <input
        type="search"
        value={search}
        onChange={(event) => setSearch(event.target.value)}
        placeholder="البحث بعنوان IP"
        aria-label="البحث عن جهاز طرفي"
        style={{
          width: "100%",
          maxWidth: 360,
          padding: 10,
          marginBottom: 16,
        }}
      />

      {loading ? (
        <p>جاري تحميل الأجهزة...</p>
      ) : filtered.length === 0 ? (
        <p>
          {data?.total === 0
            ? "لا توجد أحداث أمنية مسجلة لأجهزة طرفية حتى الآن."
            : "لا توجد أجهزة تطابق البحث."}
        </p>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", textAlign: "right" }}>
            <thead>
              <tr>
                <th>عنوان الجهاز</th>
                <th>الأحداث الأمنية</th>
                <th>الحوادث الأمنية</th>
                <th>آخر نشاط</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((client) => (
                <tr key={client.client_ip}>
                  <td dir="ltr">{client.client_ip}</td>
                  <td>{client.events}</td>
                  <td>{client.incidents}</td>
                  <td>{formatDate(client.last_activity)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p style={{ marginTop: 16, opacity: 0.75, fontSize: 13 }}>
        تعرض الصفحة الأجهزة التي لديها أحداث أمنية فقط.
        عنوان IP ليس بالضرورة هوية فريدة ودائمة للجهاز.
      </p>
    </section>
  );
}
