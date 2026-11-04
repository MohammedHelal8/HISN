
import os
import platform
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from app.core.database import check_database_connection


_LOCK = threading.Lock()
_NETWORK_SAMPLES = {}

VIRTUAL_FILESYSTEMS = {
    "proc", "sysfs", "devtmpfs", "devpts",
    "tmpfs", "cgroup", "cgroup2", "overlay",
    "squashfs", "autofs", "mqueue", "tracefs",
    "debugfs", "securityfs", "pstore",
    "fusectl", "configfs", "ramfs",
}

SERVICE_CANDIDATES = {
    "squid": ("squid.service", "squid3.service"),
    "e2guardian": ("e2guardian.service",),
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def disk_to_dict(path, usage):
    return {
        "path": path,
        "usage_percent": usage.percent,
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
    }


def get_disks():
    """Discover local mounted filesystems without fixed drive names."""
    found = []
    seen = set()

    for partition in psutil.disk_partitions(all=False):
        if partition.fstype.lower() in VIRTUAL_FILESYSTEMS:
            continue

        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except (OSError, PermissionError):
            continue

        if usage.total <= 0:
            continue

        # Avoid duplicate reports for the same mounted filesystem.
        identity = (
            partition.device,
            partition.mountpoint,
        )
        if identity in seen:
            continue

        seen.add(identity)

        found.append({
            **disk_to_dict(partition.mountpoint, usage),
            "device": partition.device,
            "filesystem": partition.fstype,
        })

    return found


def get_hisn_disk():
    """Measure the filesystem containing the installed HISN code."""
    project_path = Path(__file__).resolve().parents[2]
    usage = psutil.disk_usage(str(project_path))

    return disk_to_dict(str(project_path), usage)


def linux_default_interfaces():
    """Read the Linux IPv4 default route without external commands."""
    interfaces = set()

    try:
        with open(
            "/proc/net/route",
            encoding="ascii",
        ) as route_file:
            next(route_file, None)

            for line in route_file:
                fields = line.split()

                if len(fields) < 8:
                    continue

                interface = fields[0]
                destination = fields[1]
                flags = int(fields[3], 16)

                if destination == "00000000" and flags & 1:
                    interfaces.add(interface)

    except (OSError, ValueError):
        pass

    return interfaces


def get_network():
    """Sample interface counters using monotonic elapsed time."""
    global _NETWORK_SAMPLES

    counters = psutil.net_io_counters(pernic=True) or {}
    stats = psutil.net_if_stats()
    addresses = psutil.net_if_addrs()

    is_linux = platform.system() == "Linux"
    default_interfaces = (
        linux_default_interfaces() if is_linux else set()
    )

    current_time = time.monotonic()
    interfaces = []
    new_samples = {}

    with _LOCK:
        previous_samples = _NETWORK_SAMPLES

        for name, counter in counters.items():
            info = stats.get(name)

            if not info or not info.isup:
                continue

            if is_linux:
                # Exclude loopback and Linux virtual devices.
                physical = Path(
                    "/sys/class/net", name, "device"
                ).exists()

                if not physical:
                    continue
            else:
                # Windows remains a development environment.
                if "loopback" in name.lower():
                    continue

            upload = None
            download = None

            previous = previous_samples.get(name)

            if previous is not None:
                previous_time, previous_sent, previous_recv = previous
                elapsed = current_time - previous_time

                sent_delta = counter.bytes_sent - previous_sent
                recv_delta = counter.bytes_recv - previous_recv

                if (
                    elapsed > 0
                    and sent_delta >= 0
                    and recv_delta >= 0
                ):
                    upload = sent_delta / elapsed
                    download = recv_delta / elapsed

            new_samples[name] = (
                current_time,
                counter.bytes_sent,
                counter.bytes_recv,
            )

            interfaces.append({
                "name": name,
                "is_up": True,
                "speed_mbps": info.speed,
                "is_default_route": name in default_interfaces,
                "upload_bytes_per_second": (
                    round(upload, 2) if upload is not None else None
                ),
                "download_bytes_per_second": (
                    round(download, 2) if download is not None else None
                ),
                "total_sent_bytes": counter.bytes_sent,
                "total_received_bytes": counter.bytes_recv,
                "addresses_detected": len(addresses.get(name, [])),
            })

        _NETWORK_SAMPLES = new_samples

    # On Linux, default-route interfaces are preferred.
    # Other physical interfaces remain visible in the details.
    if is_linux:
        selected = [
            item for item in interfaces
            if item["is_default_route"]
        ]
        selection = "linux_default_route"
    else:
        selected = interfaces
        selection = "windows_active_non_loopback"

    rates_available = (
        bool(selected)
        and all(
            item["upload_bytes_per_second"] is not None
            and item["download_bytes_per_second"] is not None
            for item in selected
        )
    )

    return {
        "status": (
            "available" if selected else "unavailable"
        ),
        "selection": selection,
        "upload_bytes_per_second": (
            round(sum(
                item["upload_bytes_per_second"]
                for item in selected
            ), 2)
            if rates_available else None
        ),
        "download_bytes_per_second": (
            round(sum(
                item["download_bytes_per_second"]
                for item in selected
            ), 2)
            if rates_available else None
        ),
        "total_sent_bytes": (
            sum(item["total_sent_bytes"] for item in selected)
            if selected else None
        ),
        "total_received_bytes": (
            sum(item["total_received_bytes"] for item in selected)
            if selected else None
        ),
        "interfaces": interfaces,
        "selected_interfaces": [
            item["name"] for item in selected
        ],
    }


def get_system_resources():
    memory = psutil.virtual_memory()
    disk = get_hisn_disk()

    return {
        "cpu": {
            "usage_percent": psutil.cpu_percent(interval=0.2),
            "logical_cores": psutil.cpu_count(logical=True),
        },
        "memory": {
            "usage_percent": memory.percent,
            "total_bytes": memory.total,
            "available_bytes": memory.available,
            "used_bytes": memory.used,
        },
        "disk": disk,
        "disks": get_disks(),
        "network": get_network(),
    }


def query_systemd(unit):
    """Query a known service unit without shell execution."""
    try:
        result = subprocess.run(
            [
                "systemctl", "show", unit,
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--no-pager",
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )

    except (OSError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    properties = {}

    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            properties[key] = value

    return properties


def check_linux_service(service_name):
    """Keep compatibility with existing monitoring tests."""
    if platform.system() != "Linux":
        return {
            "status": "unavailable",
            "reason": "Local systemd monitoring requires Linux",
            "source": "systemd",
        }

    if not shutil.which("systemctl"):
        return {
            "status": "unavailable",
            "reason": "systemctl is not installed",
            "source": "systemd",
        }

    properties = query_systemd(service_name)

    if properties is None:
        return {
            "status": "unavailable",
            "reason": "Unable to query local systemd",
            "source": "systemd",
        }

    load_state = properties.get("LoadState")
    active_state = properties.get("ActiveState")
    sub_state = properties.get("SubState")

    if load_state != "loaded":
        status = "unavailable"
    elif active_state == "active":
        status = "running"
    elif active_state in ("inactive", "failed"):
        status = "stopped"
    else:
        status = "unknown"

    return {
        "status": status,
        "load_state": load_state,
        "active_state": active_state,
        "sub_state": sub_state,
        "source": "systemd",
        "unit": service_name,
    }


def discover_service(name):
    candidates = SERVICE_CANDIDATES[name]

    if platform.system() != "Linux":
        return check_linux_service(candidates[0])

    for candidate in candidates:
        result = check_linux_service(candidate)

        if result.get("load_state") == "loaded":
            return result

        # Query errors must not be mistaken for a missing unit.
        if result.get("reason") == "Unable to query local systemd":
            return result

    return {
        "status": "unavailable",
        "reason": "No known systemd service unit was found",
        "source": "systemd",
        "checked_units": list(candidates),
    }


def get_hisn_status():
    try:
        database_ok = check_database_connection()
    except Exception:
        database_ok = False

    return {
        "status": "healthy" if database_ok else "degraded",
        "api": "running",
        "database": (
            "connected" if database_ok else "unavailable"
        ),
    }


def get_monitoring_overview():
    return {
        "timestamp": utc_now(),
        "host_os": platform.system(),
        "resources": get_system_resources(),
        "systems": {
            "hisn": get_hisn_status(),
            "squid": discover_service("squid"),
            "e2guardian": discover_service("e2guardian"),
        },
    }
