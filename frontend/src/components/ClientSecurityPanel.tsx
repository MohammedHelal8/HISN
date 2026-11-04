import { useCallback, useEffect, useState } from "react";

type Client = {
  client_ip: string;
  first_seen_at: string;
  last_activity: string;
  requests: number;
  last_destination: string | null;
  active_recently: boolean;
  events: number;
  incidents: number;
};
type ClientPage = { total: number; clients: Client[]; offset: number; limit: number };
type SecurityEvent = {
  event_id: number; event_type: string; activity_at: string; destination: string;
  detection_rule: string; indicator_id: number | null; evidence: string; incident_ids: number[];
};
type ClientDetails = {
  client: Client; security_events_total: number; security_events: SecurityEvent[];
  request_history_available: boolean; request_history_note: string;
};
type View = "recent" | "all" | "threats";
const PAGE_SIZE = 50;
const fmt = (v: string | null) => v ? new Date(v).toLocaleString("ar", { dateStyle: "medium", timeStyle: "medium" }) : "—";

export default function ClientSecurityPanel() {
  const [view, setView] = useState<View>("recent");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<ClientPage | null>(null);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [details, setDetails] = useState<ClientDetails | null>(null);
  const [detailsOffset, setDetailsOffset] = useState(0);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const params = new URLSearchParams({ view, q: search.trim(), offset: String(offset), limit: String(PAGE_SIZE) });
      const response = await fetch(`/api/clients?${params}`, { credentials: "include", cache: "no-store", signal });
      if (!response.ok) throw new Error(`تعذر تحميل الأجهزة (${response.status})`);
      const result: ClientPage = await response.json();
      if (!signal?.aborted) { setData(result); setError(""); }
    } catch (e) {
      if (!signal?.aborted) setError(e instanceof Error ? e.message : "تعذر تحديث الأجهزة");
    } finally { if (!signal?.aborted) setLoading(false); }
  }, [view, search, offset]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    void load(controller.signal);
    const timer = window.setInterval(() => void load(controller.signal), 5000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [load]);

  useEffect(() => {
    if (!selectedIp) { setDetails(null); return; }
    const controller = new AbortController();
    async function getDetails() {
      try {
        const response = await fetch(`/api/clients/${encodeURIComponent(selectedIp!)}?offset=${detailsOffset}&limit=${PAGE_SIZE}`, {
          credentials: "include", cache: "no-store", signal: controller.signal
        });
        if (!response.ok) throw new Error(`تعذر تحميل تفاصيل الجهاز (${response.status})`);
        const body: ClientDetails = await response.json();
        if (!controller.signal.aborted) { setDetails(body); setError(""); }
      } catch (e) {
        if (!controller.signal.aborted) setError(e instanceof Error ? e.message : "خطأ في تفاصيل الجهاز");
      }
    }
    void getDetails();
    const timer = window.setInterval(() => void getDetails(), 5000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [selectedIp, detailsOffset]);

  return <section className="dashboard-events" dir="rtl">
    <header style={{display:"flex", justifyContent:"space-between", alignItems:"center", gap:12, flexWrap:"wrap"}}>
      <div><h2>مراقبة الأجهزة الطرفية</h2><p>اكتشاف تلقائي من E2Guardian وتحديث كل 5 ثوانٍ.</p></div>
      <button type="button" onClick={() => { void load(); }}>تحديث الآن</button>
    </header>
    {error && <p role="alert" style={{color:"#f87171"}}>{error}</p>}
    <div style={{display:"flex", flexWrap:"wrap", gap:8, margin:"16px 0"}}>
      {([ ["recent", "نشطة مؤخرًا"], ["all", "جميع الأجهزة"], ["threats", "ذات أحداث أمنية"] ] as const).map(([key, label]) =>
        <button key={key} type="button" aria-pressed={view===key} onClick={() => { setView(key); setOffset(0); }}
          className={view === key ? "active" : ""}>{label}</button>)}
    </div>
    <label htmlFor="client-search">بحث بعنوان IP</label>
    <div><input id="client-search" type="search" value={search} onChange={e=> {setSearch(e.target.value); setOffset(0);}}
      placeholder="عنوان IP" style={{width:"100%", maxWidth:340, padding:10, margin:"8px 0 16px"}} /></div>
    {loading && <p>جارٍ تحميل الأجهزة...</p>}
    <p>الأجهزة المطابقة: <strong>{data?.total ?? 0}</strong></p>
    {!loading && (data?.clients.length ?? 0) === 0 && <p>لا توجد أجهزة مطابقة. تظهر الأجهزة بعد مرور طلبات عبر E2Guardian.</p>}
    {(data?.clients.length ?? 0) > 0 && <div style={{overflowX:"auto"}}><table style={{width:"100%", textAlign:"right"}}>
      <thead><tr><th>الجهاز</th><th>الحالة</th><th>الطلبات</th><th>الأحداث</th><th>الحوادث</th><th>آخر نشاط</th><th>تفاصيل</th></tr></thead>
      <tbody>{data?.clients.map(c => <tr key={c.client_ip}>
        <td dir="ltr">{c.client_ip}</td><td>{c.active_recently ? "نشط مؤخرًا" : "غير نشط مؤخرًا"}</td>
        <td>{c.requests}</td><td>{c.events}</td><td>{c.incidents}</td><td>{fmt(c.last_activity)}</td>
        <td><button type="button" onClick={() => {setSelectedIp(c.client_ip); setDetailsOffset(0);}}>عرض التفاصيل</button></td>
      </tr>)}</tbody></table></div>}
    <div style={{display:"flex", gap:10, alignItems:"center", marginTop:12}}>
      <button type="button" disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-PAGE_SIZE))}>السابق</button>
      <span>{data ? `${data.total===0 ? 0 : offset+1}–${Math.min(offset+PAGE_SIZE,data.total)} من ${data.total}` : "—"}</span>
      <button type="button" disabled={!data || offset+PAGE_SIZE>=data.total} onClick={()=>setOffset(offset+PAGE_SIZE)}>التالي</button>
    </div>
    {selectedIp && <section className="dashboard-events" style={{marginTop:24}} aria-label="تفاصيل الجهاز">
      <header style={{display:"flex", justifyContent:"space-between", alignItems:"center"}}>
        <h3>تفاصيل الجهاز <span dir="ltr">{selectedIp}</span></h3>
        <button type="button" onClick={()=>{setSelectedIp(null);setDetails(null);}}>إغلاق</button>
      </header>
      {!details && <p>جارٍ تحميل التفاصيل...</p>}
      {details && <>
        <p>أول ظهور: {fmt(details.client.first_seen_at)} | آخر نشاط: {fmt(details.client.last_activity)}</p>
        <p>عدد الطلبات: {details.client.requests} | الأحداث الأمنية: {details.client.events} | الحوادث: {details.client.incidents}</p>
        <p>آخر وجهة مسجلة: <span dir="ltr">{details.client.last_destination ?? "—"}</span></p>
        <h4>الخط الزمني للأحداث الأمنية</h4>
        <p style={{opacity:0.8}}>الجدول التالي للأحداث الأمنية المسجلة فقط؛ لا تتوفر تفاصيل طلبات الويب السليمة تاريخيًا في التخزين الحالي.</p>
        {details.security_events.length===0 ? <p>لا توجد أحداث أمنية مسجلة لهذا الجهاز.</p> :
        <div style={{overflowX:"auto"}}><table style={{width:"100%", textAlign:"right"}}><thead><tr>
          <th>الوقت</th><th>النوع</th><th>الوجهة</th><th>قاعدة الكشف</th><th>الحوادث المرتبطة</th><th>الأدلة</th>
        </tr></thead><tbody>{details.security_events.map(e=><tr key={e.event_id}>
          <td>{fmt(e.activity_at)}</td><td dir="ltr">{e.event_type}</td><td dir="ltr">{e.destination}</td>
          <td dir="ltr">{e.detection_rule}</td><td>{e.incident_ids.join(", ") || "—"}</td>
          <td><details><summary>عرض الدليل</summary><pre style={{maxWidth:320,whiteSpace:"pre-wrap",overflowWrap:"anywhere"}}>{e.evidence}</pre></details></td>
        </tr>)}</tbody></table></div>}
        <div style={{display:"flex",gap:8,marginTop:12}}>
          <button disabled={detailsOffset===0} onClick={()=>setDetailsOffset(Math.max(0,detailsOffset-PAGE_SIZE))}>الأحداث السابقة</button>
          <span>{details.security_events_total} حدثًا</span>
          <button disabled={detailsOffset+PAGE_SIZE>=details.security_events_total} onClick={()=>setDetailsOffset(detailsOffset+PAGE_SIZE)}>المزيد</button>
        </div>
      </>}
    </section>}
    <p style={{fontSize:13,opacity:.7,marginTop:18}}>«نشط مؤخرًا» يعني نشاطًا عبر البوابة خلال 5 دقائق؛ لا يثبت الاتصال اللحظي. عنوان IP ليس دائمًا معرّفًا فريدًا لجهاز.</p>
  </section>;
}
