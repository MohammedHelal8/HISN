
import type { DiskInfo } from "../types/monitoring";

type Props = {
  disks: DiskInfo[];
};

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return "غير متاح";

  const gb = bytes / (1024 ** 3);
  return `${gb.toFixed(2)} GB`;
}

export default function DiskMonitoring({ disks }: Props) {
  return (
    <section className="dashboard-events">
      <h2>الأقراص المكتشفة تلقائيًا</h2>

      {disks.length === 0 ? (
        <p>لم يتم اكتشاف أقراص قابلة للمراقبة.</p>
      ) : (
        <div className="dashboard-stats">
          {disks.map((disk) => (
            <article
              className="stat-card"
              key={`${disk.device ?? ""}-${disk.path}`}
            >
              <h3>{disk.path}</h3>

              <strong>
                {disk.usage_percent.toFixed(1)}%
              </strong>

              <progress
                value={disk.usage_percent}
                max={100}
                style={{ width: "100%" }}
              />

              <p>المستخدم: {formatBytes(disk.used_bytes)}</p>
              <p>المتاح: {formatBytes(disk.free_bytes)}</p>
              <p>الإجمالي: {formatBytes(disk.total_bytes)}</p>

              {disk.filesystem && (
                <p>نظام الملفات: {disk.filesystem}</p>
              )}
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
