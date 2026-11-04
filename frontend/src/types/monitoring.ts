
export interface DiskInfo {
  path: string;
  device?: string;
  filesystem?: string;
  usage_percent: number;
  total_bytes: number;
  used_bytes: number;
  free_bytes: number;
}

export interface NetworkInterface {
  name: string;
  is_up: boolean;
  speed_mbps: number;
  is_default_route: boolean;
  upload_bytes_per_second: number | null;
  download_bytes_per_second: number | null;
  total_sent_bytes: number;
  total_received_bytes: number;
  addresses_detected: number;
}

export interface NetworkInfo {
  status: string;
  selection: string;
  upload_bytes_per_second: number | null;
  download_bytes_per_second: number | null;
  total_sent_bytes: number | null;
  total_received_bytes: number | null;
  interfaces: NetworkInterface[];
  selected_interfaces: string[];
}

export interface ServiceInfo {
  status: string;
  reason?: string;
  source?: string;
  unit?: string;
  api?: string;
  database?: string;
  load_state?: string;
  active_state?: string;
  sub_state?: string;
  checked_units?: string[];
}

export interface MonitoringOverview {
  timestamp: string;
  host_os: string;
  resources: {
    cpu: {
      usage_percent: number;
      logical_cores: number | null;
    };
    memory: {
      usage_percent: number;
      total_bytes: number;
      used_bytes: number;
      available_bytes: number;
    };
    disk: DiskInfo;
    disks: DiskInfo[];
    network: NetworkInfo;
  };
  systems: {
    hisn: ServiceInfo;
    squid: ServiceInfo;
    e2guardian: ServiceInfo;
  };
}
