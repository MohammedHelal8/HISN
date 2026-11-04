import { useCallback, useEffect, useState } from "react";

type ClientRecord = {
  client_ip: string;
  first_seen_at: string;
  last_activity: string;
  requests: number;
  last_destination: string | null;
  active_recently: boolean;
  events: number;
  incidents: number;
};
type ClientsResponse = {
  total: number;
  limit: number;
  offset: number;
  clients: ClientRecord[];
  note?: string;
};
const PAGE_SIZE = 100;
export default function ClientSecurityPanel() {
  const [data, setData] = useState<ClientsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const loadClients = useCallback(async () => {
    try {
      const response = await fetch(`/api/clients?limit=${PAGE_SIZE}&offset=${offset}`, {
        credentials: "include", headers: { Accept: "application/json" }, cache: "no-store",
      });
      if (!response.ok) throw new Error(response.status === 401 ? "انتهت الجلسة، سجل الدخول مجددًا." : `خطأ API: ${response.status}`);
      const result: ClientsResponse = await response.json();
      setData(result);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "تعذر تحديث الأجهزة");
    } finally { setLoading(false); }
  }, [offset]);
  useEffect(() => {
    void loadClients();
    const timer = window.setInterval(() => { void loadClients(); }, 5000);
    return () => window.clearInterval(timer);
  }, [loadClients]);
  const filtered = (data?.clients ?? []).filter((item) => item.client_ip.includes(search.trim()));
  const date = (value: string) => new Date(value).toLocaleString("ar", { dateStyle: "medium", timeStyle: "medium" });
  return <section className="dashboard-events" dir="rtl">
    <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
      <div><h2>الأجهزة الطرفية</h2><p>تُكتشف تلقائيًا عند تصفحها عبر E2Guardian، ويتم التحديث كل 5 ثوانٍ.</p></div>
      <button type="button" onClick={() => { setLoading(true); void loadClients(); }}>تحديث الآن</button>
    </header>
    {error && <p role="alert" style={{ color: "#f87171" }}>{error}</p>}
    {loading && <p>جارٍ تحميل الأجهزة...</p>}
    <div className="dashboard-stats">
      <article className="stat-card"><h3>الأجهزة المرصودة</h3><strong>{data?.total ?? 0}</strong></article>
      <article className="stat-card"><h3>نشاط حديث (5 دقائق)</h3><strong>{data?.clients.filter(x => x.active_recently).length ?? 0}</strong></article>
      <article className="stat-card"><h3>الأجهزة ذات الأحداث الأمنية (الصفحة الحالية)</h3><strong>{data?.clients.filter(x => x.events > 0).length ?? 0}</strong></article>
    </div>
    <input type="search" value={search} onChange={e => setSearch(e.target.value)} placeholder="بحث بعنوان IP في الصفحة الحالية" aria-label="بحث عن جهاز" style={{padding:10, width:"100%", maxWidth:370, marginTop:12}} />
    {filtered.length === 0 && !loading && <p>{data?.total ? "لا توجد نتائج في هذه الصفحة." : "لم يُرصد أي جهاز طرفي عبر E2Guardian بعد."}</p>}
    {filtered.length > 0 && <div style={{overflowX:"auto", marginTop:14}}><table style={{width:"100%", textAlign:"right"}}>
      <thead><tr><th>IP</th><th>آخر نشاط</th><th>الحالة</th><th>الطلبات</th><th>الأحداث</th><th>الحوادث</th><th>آخر وجهة</th></tr></thead>
      <tbody>{filtered.map(c => <tr key={c.client_ip}>
        <td dir="ltr">{c.client_ip}</td><td>{date(c.last_activity)}</td>
        <td>{c.active_recently ? "نشط مؤخرًا" : "غير نشط مؤخرًا"}</td>
        <td>{c.requests}</td><td>{c.events}</td><td>{c.incidents}</td>
        <td dir="ltr">{c.last_destination ?? "—"}</td>
      </tr>)}</tbody></table></div>}
    <div style={{display:"flex", gap:12, alignItems:"center", marginTop:16}}>
      <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset-PAGE_SIZE))}>السابق</button>
      <span>{data ? `${data.total === 0 ? 0 : offset + 1}–${Math.min(offset+PAGE_SIZE, data.total)} من ${data.total}` : "—"}</span>
      <button type="button" disabled={!data || offset+PAGE_SIZE >= data.total} onClick={() => setOffset(offset+PAGE_SIZE)}>التالي</button>
    </div>
    <p style={{opacity:.75,fontSize:13}}>الحالة «نشط مؤخرًا» تعني وصول طلب خلال آخر 5 دقائق، ولا تعني أن الجهاز متصل الآن. لا يضمن IP هوية فريدة لجهاز.</p>
  </section>;
}
