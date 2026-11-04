import { useEffect, useState } from 'react';
type Counts = { events: number; incidents: number; indicators: number; decisions: number; exceptions: number };
export default function SecuritySummary() {
  const [data, setData] = useState<Counts | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/security/summary', {credentials: 'same-origin', cache: 'no-store', signal: controller.signal})
      .then(r => {if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json() as Promise<Counts>;})
      .then(setData).catch(e => {if (!controller.signal.aborted) setError(String(e));});
    return () => controller.abort();
  }, []);
  const items = data ? [['الأحداث',data.events], ['الحوادث', data.incidents], ['المؤشرات', data.indicators],
                        ['القرارات',data.decisions], ['الاستثناءات',data.exceptions]] as const : [];
  return <section className="dashboard-events"><h2>إحصائيات الأمن المسجلة</h2>
    {error && <p role="alert" className="hisn-error">فشل جلب الإحصائيات: {error}</p>}
    {!data && !error && <p>جارٍ قراءة قاعدة البيانات...</p>}
    <div className="dashboard-stats">{items.map(([name, value]) =>
      <article className="stat-card" key={name}><h3>{name}</h3><strong>{value}</strong></article>)}</div>
  </section>;
}
