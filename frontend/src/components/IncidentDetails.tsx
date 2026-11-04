import { useEffect, useState } from "react";

type Decision = {
  action_id: number;
  target_value: string;
  decision_reason: string | null;
  execution_status: string;
  requested_at: string | null;
  executed_at: string | null;
  verified_at: string | null;
  error_message: string | null;
  enforcement_verified: boolean;
};
type Indicator = {
  indicator_id: number;
  indicator_value: string;
  source_name: string;
  confidence_level: string;
};
type SecurityEvent = {
  event_id: number;
  event_type: string;
  activity_at: string;
  client_ip: string | null;
  destination: string | null;
  detection_rule: string | null;
  evidence: string | null;
  indicator: Indicator | null;
  decisions: Decision[];
};
type Details = {
  incident: {
    incident_id: number;
    incident_title: string;
    status: string;
    correlation_rule: string;
    created_at: string;
    updated_at: string;
    closed_at: string | null;
  };
  event_count: number;
  events: SecurityEvent[];
};

const fmt = (date: string | null | undefined) => {
  if (!date) return "—";
  const d = new Date(date);
  return Number.isNaN(d.getTime()) ? date : new Intl.DateTimeFormat("ar", {
    dateStyle: "medium", timeStyle: "short"
  }).format(d);
};

export default function IncidentDetails({ incidentId, onClose }: {
  incidentId: number;
  onClose: () => void;
}) {
  const [data, setData] = useState<Details | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setData(null);
    fetch(`/api/security/incidents/${incidentId}/details`, {
      credentials: "same-origin", cache: "no-store", signal: controller.signal
    }).then(async r => {
      if (!r.ok) throw new Error(`تعذر عرض تفاصيل الحادث: HTTP ${r.status}`);
      return await r.json() as Details;
    }).then(value => { if (!controller.signal.aborted) setData(value); })
      .catch(e => { if (!controller.signal.aborted) setError(String(e)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [incidentId]);

  return <section className="hisn-incident-details" dir="rtl" aria-label="تفاصيل الحادث الأمني">
    <button type="button" onClick={onClose}>العودة إلى الحوادث</button>
    {loading && <p role="status">جارٍ تحميل تفاصيل الحادث...</p>}
    {error && <p role="alert" className="hisn-error">{error}</p>}
    {data && <>
      <h3>الحادث #{data.incident.incident_id}: {data.incident.incident_title}</h3>
      <p>الحالة: <strong>{data.incident.status}</strong> | عدد الأحداث: {data.event_count}</p>
      <p>قاعدة الربط: <code>{data.incident.correlation_rule}</code></p>
      <p>الإنشاء: <time>{fmt(data.incident.created_at)}</time> | آخر تحديث: <time>{fmt(data.incident.updated_at)}</time> | الإغلاق: <time>{fmt(data.incident.closed_at)}</time></p>
      {data.events.length === 0 && <p>لا توجد أحداث مرتبطة بهذا الحادث.</p>}
      {data.events.map(event => <article key={event.event_id} className="hisn-incident-event">
        <h4>الحدث #{event.event_id} — {event.event_type}</h4>
        <p>وقت النشاط: {fmt(event.activity_at)} | قاعدة الكشف: <code>{event.detection_rule ?? "—"}</code></p>
        <p>الجهاز: <code dir="ltr">{event.client_ip ?? "—"}</code> | الوجهة: <code dir="ltr">{event.destination ?? "—"}</code></p>
        {event.indicator && <p>مؤشر التهديد: <code dir="ltr">{event.indicator.indicator_value}</code> | المصدر: {event.indicator.source_name} | الثقة: <strong>{event.indicator.confidence_level}</strong></p>}
        <details><summary>دليل الاكتشاف</summary><pre className="hisn-incident-evidence" dir="ltr">{event.evidence || "لا يوجد دليل مسجل"}</pre></details>
        <h5>قرارات الاستجابة</h5>
        {event.decisions.length === 0 ? <p>لا توجد قرارات مسجلة.</p> :
          <div className="hisn-table-wrap"><table className="hisn-table"><thead><tr>
            <th>القرار</th><th>السبب</th><th>التحقق من التنفيذ</th><th>الوقت</th>
          </tr></thead><tbody>{event.decisions.map(d => <tr key={d.action_id}>
            <td><code>{d.execution_status}</code></td>
            <td>{d.decision_reason ?? "—"}{d.error_message ? ` — ${d.error_message}` : ""}</td>
            <td>{d.execution_status === "ALERT_ONLY" ? "تنبيه فقط؛ لا يوجد حجب" : d.enforcement_verified ? "وقت تحقق مسجل" : "غير متحقق منه"}</td>
            <td>{fmt(d.executed_at ?? d.requested_at)}</td>
          </tr>)}</tbody></table></div>}
      </article>)}
    </>}
  </section>;
}
