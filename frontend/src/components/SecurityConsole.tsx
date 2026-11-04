import ThreatIndicatorsPanel from "./ThreatIndicatorsPanel";
import { useEffect, useState } from 'react';
import IncidentDetails from './IncidentDetails';

type Row = Record<string, unknown>;
type AdminTab = 'events' | 'incidents' | 'threats' | 'decisions' | 'rules' | 'squid' | 'e2guardian' | 'audit' | 'users' | 'settings' | 'exceptions';
type Props = { tab: AdminTab };

function csrf(): string { return decodeURIComponent(document.cookie.split('; ').find(x => x.startsWith('hisn_csrf='))?.split('=').slice(1).join('=') ?? ''); }
async function request(path: string, method = 'GET', body?: object): Promise<unknown> {
  const response = await fetch(`/api/${path}`, {
    credentials: 'same-origin', cache: 'no-store', method,
    headers: { ...(method !== 'GET' ? { 'X-CSRF-Token': csrf() } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const value: unknown = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof value === 'object' && value && 'detail' in value ? String((value as Row).detail) : `HTTP ${response.status}`;
    throw new Error(message);
  }
  return value;
}
const routes: Partial<Record<AdminTab, string>> = {
  events: 'security/events', incidents: 'security/incidents', 
  decisions: 'security/decisions', audit: 'security/audit', users: 'administration/users',
  rules: 'security/rules', settings: 'security/rules', exceptions: 'security/exceptions',
  squid: 'services/squid/logs', e2guardian: 'services/e2guardian/logs',
};
const titles: Record<AdminTab, string> = {
  events: 'الأحداث الأمنية', incidents: 'الحوادث الأمنية', threats: 'مؤشرات التهديدات',
  decisions: 'قرارات الحجب والتنبيه', rules: 'قواعد الكشف', squid: 'إدارة Squid',
  e2guardian: 'إدارة E2Guardian', audit: 'سجل التدقيق', users: 'المستخدمون والجلسات',
  settings: 'إعدادات النظام', exceptions: 'الاستثناءات',
};
const excluded = new Set(['password_hash', 'csrf_hash', 'token_hash']);
function valueText(v: unknown): string {
  if (v == null) return '—';
  if (typeof v === 'object') return JSON.stringify(v);
  if (typeof v === 'boolean') return v ? 'نعم' : 'لا';
  return String(v);
}
function DataTable({ rows }: { rows: Row[] }) {
  if (!rows.length) return <p>لا توجد سجلات مخزنة لعرضها.</p>;
  const columns = Object.keys(rows[0]).filter(x => !excluded.has(x));
  return <div className="hisn-table-wrap"><table className="hisn-table"><thead><tr>{columns.map(key => <th key={key}>{key}</th>)}</tr></thead>
    <tbody>{rows.map((row, i) => <tr key={String(row.event_id ?? row.indicator_id ?? row.incident_id ?? row.session_id ?? i)}>
      {columns.map(key => <td key={key}>{valueText(row[key])}</td>)}</tr>)}</tbody></table></div>;
}
function isRows(v: unknown): v is Row[] { return Array.isArray(v) && v.every(x => typeof x === 'object' && x !== null); }
function isRow(v: unknown): v is Row { return Boolean(v && typeof v === 'object' && !Array.isArray(v)); }

export default function SecurityConsole({ tab }: Props) {
  const [rows, setRows] = useState<Row[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<number | null>(null);
  const [extra, setExtra] = useState<Row[]>([]);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [kind, setKind] = useState<'DOMAIN' | 'IP'>('DOMAIN');
  const [target, setTarget] = useState('');
  const [source, setSource] = useState('');
  const [confidence, setConfidence] = useState<'LOW' | 'MEDIUM' | 'HIGH'>('LOW');
  const [preview, setPreview] = useState('');
  const [previewResult, setPreviewResult] = useState<unknown>(null);
  useEffect(() => { setOffset(0); setRows([]); setSelectedIncident(null); setError(''); setNotice(''); }, [tab]);
  useEffect(() => {
    let alive = true;
    async function load() {
      setLoading(true); setError('');
      try {
        const path = routes[tab];
        if (!path) { if (alive) { setRows([]); setExtra([]); } return; }
        const paged = ['events', 'incidents', 'decisions', 'audit', 'exceptions'].includes(tab);
        const query = paged ? `?limit=30&offset=${offset}` : '';
        const response = await request(`${path}${query}`);
        if (alive) setRows(isRows(response) ? response : isRow(response) ? [response] : []);
        if (tab === 'users') {
          const sessions = await request('administration/sessions');
          if (alive) setExtra(isRows(sessions) ? sessions : []);
        }
      } catch (e) { if (alive) setError(e instanceof Error ? e.message : 'تعذر استرجاع البيانات'); }
      finally { if (alive) setLoading(false); }
    }
    void load();
    return () => { alive = false; };
  }, [tab, offset, refresh]);
  async function act(fn: () => Promise<unknown>, question?: string) {
    if (question && !window.confirm(question)) return;
    setNotice(''); setError('');
    try { await fn(); setNotice('تم تنفيذ الطلب لدى الخادم. تحقق من الحالة الفعلية للأنظمة.'); setRefresh(x => x + 1); }
    catch (e) { setError(e instanceof Error ? e.message : 'فشل الطلب'); }
  }
  const service = tab === 'squid' || tab === 'e2guardian' ? tab : null;
  return <section className="dashboard-events" dir="rtl">
    <h2>{titles[tab]}</h2>
    {loading && <p role="status">جارٍ جلب البيانات من الخادم...</p>}
    {error && <p role="alert" className="hisn-error">{error}</p>}
    {notice && <p role="status" className="hisn-notice">{notice}</p>}
    {service && <>
      <p>حالة الخدمة الحية تظهر في شاشة المراقبة. السجلات أدناه تعرض الوجهات دون المسارات السرية؛ العمليات مقيدة بإعدادات الخادم، ونجاح الأمر لا يضمن صحة الخدمة.</p>
      <div className="hisn-actions">{(['start', 'stop', 'restart', 'reload'] as const).map(action =>
        <button type="button" key={action} onClick={() => void act(() => request(`services/${service}/${action}`, 'POST'), `هل تريد تنفيذ ${action} لخدمة ${service}؟`)}>{action}</button>)}</div>
    </>}
    {tab === 'threats' && <form className="hisn-form" onSubmit={e => {e.preventDefault(); void act(() => request('threat-indicators', 'POST', {indicator_type: kind, indicator_value: target, source_name: source, confidence_level: confidence})); }}>
      <label>نوع المؤشر <select value={kind} onChange={e => setKind(e.target.value as 'IP' | 'DOMAIN')}><option>DOMAIN</option><option>IP</option></select></label>
      <label>الوجهة <input required value={target} onChange={e => setTarget(e.target.value)} placeholder="example.org" /></label>
      <label>المصدر <input required value={source} onChange={e => setSource(e.target.value)} placeholder="Verified feed" /></label>
      <label>الثقة <select value={confidence} onChange={e => setConfidence(e.target.value as 'LOW' | 'MEDIUM' | 'HIGH')}><option>LOW</option><option>MEDIUM</option><option>HIGH</option></select></label>
      <button type="submit">إضافة مؤشر</button>
    </form>}
    {tab === 'exceptions' && <form className="hisn-form" onSubmit={e => { e.preventDefault(); void act(() => request('security/exceptions', 'POST', {target_type: kind, target_value: target})); }}>
      <label>النوع <select value={kind} onChange={e => setKind(e.target.value as 'IP' | 'DOMAIN')}><option>DOMAIN</option><option>IP</option></select></label>
      <label>الوجهة المسموحة <input required value={target} onChange={e => setTarget(e.target.value)} /></label>
      <button type="submit">إضافة استثناء</button>
    </form>}
    {tab === 'rules' && <p>القواعد المعروضة هي إعدادات الكشف المفعّلة. تغييرها يتم عبر إعدادات بيئة التشغيل ويحتاج إعادة تشغيل الخدمة.</p>}
    {tab === 'settings' && <p>قيم إعدادات تشغيل آمنة فقط؛ لا تُعرض كلمات المرور أو أسرار قواعد البيانات من هذه الواجهة.</p>}
    {tab === 'events' && <form className="hisn-form" onSubmit={e => { e.preventDefault(); void act(async () => {setPreviewResult(await request('security/preview', 'POST', {destination: preview}));}); }}>
      <label>اختبار قرار مؤشر (دون حجب) <input value={preview} required onChange={e => setPreview(e.target.value)} placeholder="https://example.org/path" /></label><button type="submit">فحص</button></form>}
    {previewResult != null && tab === 'events' && <pre className="hisn-result">{JSON.stringify(previewResult, null, 2)}</pre>}
    {tab === 'threats' && <ThreatIndicatorsPanel />}
    {routes[tab] && <DataTable rows={rows} />}
    {tab === 'incidents' && selectedIncident !== null && <IncidentDetails incidentId={selectedIncident} onClose={() => setSelectedIncident(null)} />}
    {tab === 'incidents' && <div className="hisn-actions">{rows.map(x =>
      <button type="button" key={`details-${String(x.incident_id)}`} onClick={() => setSelectedIncident(Number(x.incident_id))}>تفاصيل الحادث {String(x.incident_id)}</button>
    )}</div>}
    {tab === 'incidents' && <div className="hisn-actions">{rows.filter(x => x.status !== 'CLOSED').map(x =>
      <button type="button" key={String(x.incident_id)} onClick={() => void act(() => request(`security/incidents/${x.incident_id}`, 'PATCH', {status: 'CLOSED'}), 'هل تريد إغلاق هذه الحادثة؟')}>إغلاق الحادثة {String(x.incident_id)}</button>)}</div>}
    {['events', 'incidents', 'decisions', 'audit', 'exceptions'].includes(tab) && <div className="hisn-actions"><button type="button" disabled={offset === 0} onClick={() => setOffset(x => Math.max(0, x - 30))}>السابق</button><span>السجلات {offset + 1}–{offset + rows.length}</span><button type="button" disabled={rows.length < 30} onClick={() => setOffset(x => x + 30)}>التالي</button></div>}
    {tab === 'users' && <><h3>جلسات الدخول (مدة بالثواني)</h3><DataTable rows={extra} />
      <div className="hisn-actions">{extra.filter(x => x.active === true).map(x => <button type="button" key={String(x.session_id)} onClick={() => void act(() => request(`administration/sessions/${x.session_id}/revoke`, 'POST'), 'هل تريد إبطال هذه الجلسة؟')}>إنهاء الجلسة {String(x.session_id)}</button>)}</div></>}
    <div className="hisn-actions"><button type="button" onClick={() => setRefresh(x => x + 1)}>تحديث البيانات</button></div>
  </section>;
}
