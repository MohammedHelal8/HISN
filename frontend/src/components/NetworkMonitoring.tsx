
import type { NetworkInfo } from "../types/monitoring";

type Props = {
  network: NetworkInfo;
};

function formatRate(value: number | null): string {
  if (value === null || !Number.isFinite(value)) {
    return "بانتظار القراءة التالية";
  }

  if (value < 1024) {
    return `${value.toFixed(0)} B/s`;
  }

  if (value < 1024 ** 2) {
    return `${(value / 1024).toFixed(2)} KB/s`;
  }

  return `${(value / (1024 ** 2)).toFixed(2)} MB/s`;
}

export default function NetworkMonitoring({
  network,
}: Props) {
  return (
    <section className="dashboard-events">
      <h2>واجهات الشبكة المكتشفة تلقائيًا</h2>

      <p>
        الواجهات المختارة لحساب السرعة:{" "}
        {network.selected_interfaces.length > 0
          ? network.selected_interfaces.join("، ")
          : "لم تُكتشف واجهة مناسبة"}
      </p>

      <div className="dashboard-stats">
        {network.interfaces.map((item) => (
          <article className="stat-card" key={item.name}>
            <h3>{item.name}</h3>

            <p>
              الحالة: {item.is_up ? "نشطة" : "متوقفة"}
            </p>

            <p>
              المسار الافتراضي:{" "}
              {item.is_default_route ? "نعم" : "لا"}
            </p>

            <p>
              الإرسال:{" "}
              {formatRate(item.upload_bytes_per_second)}
            </p>

            <p>
              الاستقبال:{" "}
              {formatRate(item.download_bytes_per_second)}
            </p>

            <p>
              سرعة الربط المعلنة:{" "}
              {item.speed_mbps > 0
                ? `${item.speed_mbps} Mbps`
                : "غير معروفة"}
            </p>
          </article>
        ))}
      </div>

      {network.interfaces.length === 0 && (
        <p>لم تُكتشف واجهات شبكة مناسبة للمراقبة.</p>
      )}
    </section>
  );
}
