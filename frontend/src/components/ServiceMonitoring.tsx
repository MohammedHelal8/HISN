
import type { MonitoringOverview } from "../types/monitoring";

type Props = {
  systems: MonitoringOverview["systems"];
};

const labels: Record<string, string> = {
  healthy: "سليم",
  degraded: "يعمل مع مشكلة",
  running: "قيد التشغيل",
  stopped: "متوقف",
  unavailable: "غير متاح للتحقق",
  unknown: "غير معروف",
};

export default function ServiceMonitoring({
  systems,
}: Props) {
  const services = [
    { name: "HISN", data: systems.hisn },
    { name: "Squid", data: systems.squid },
    { name: "E2Guardian", data: systems.e2guardian },
  ];

  return (
    <section className="dashboard-events">
      <h2>تفاصيل حالة الأنظمة</h2>

      <div className="dashboard-stats">
        {services.map(({ name, data }) => (
          <article className="stat-card" key={name}>
            <h3>{name}</h3>

            <strong>
              {labels[data.status] ?? "غير معروف"}
            </strong>

            {data.unit && <p>الخدمة: {data.unit}</p>}

            {data.api && (
              <p>API: {data.api}</p>
            )}

            {data.database && (
              <p>PostgreSQL: {data.database}</p>
            )}

            {data.active_state && (
              <p>systemd: {data.active_state}</p>
            )}

            {data.sub_state && (
              <p>الحالة الفرعية: {data.sub_state}</p>
            )}

            {data.reason && (
              <p>السبب: {data.reason}</p>
            )}
          </article>
        ))}
      </div>
    </section>
  );
}
