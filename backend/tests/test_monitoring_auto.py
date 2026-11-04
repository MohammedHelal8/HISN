
from types import SimpleNamespace
from unittest.mock import patch

from app.services import monitoring_service as monitoring


def test_disk_detection():
    disks = monitoring.get_disks()

    assert isinstance(disks, list)

    for disk in disks:
        assert disk["total_bytes"] > 0
        assert 0 <= disk["usage_percent"] <= 100


def test_hisn_disk_is_detected():
    disk = monitoring.get_hisn_disk()

    assert disk["total_bytes"] > 0
    assert disk["path"]


def test_linux_service_running():
    properties = {
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
    }

    with (
        patch.object(
            monitoring.platform,
            "system",
            return_value="Linux",
        ),
        patch.object(
            monitoring.shutil,
            "which",
            return_value="/usr/bin/systemctl",
        ),
        patch.object(
            monitoring,
            "query_systemd",
            return_value=properties,
        ),
    ):
        result = monitoring.check_linux_service(
            "squid.service"
        )

    assert result["status"] == "running"


def test_linux_service_stopped():
    properties = {
        "LoadState": "loaded",
        "ActiveState": "failed",
        "SubState": "failed",
    }

    with (
        patch.object(
            monitoring.platform,
            "system",
            return_value="Linux",
        ),
        patch.object(
            monitoring.shutil,
            "which",
            return_value="/usr/bin/systemctl",
        ),
        patch.object(
            monitoring,
            "query_systemd",
            return_value=properties,
        ),
    ):
        result = monitoring.check_linux_service(
            "e2guardian.service"
        )

    assert result["status"] == "stopped"


def test_linux_service_not_installed():
    properties = {
        "LoadState": "not-found",
        "ActiveState": "inactive",
        "SubState": "dead",
    }

    with (
        patch.object(
            monitoring.platform,
            "system",
            return_value="Linux",
        ),
        patch.object(
            monitoring.shutil,
            "which",
            return_value="/usr/bin/systemctl",
        ),
        patch.object(
            monitoring,
            "query_systemd",
            return_value=properties,
        ),
    ):
        result = monitoring.check_linux_service(
            "squid.service"
        )

    assert result["status"] == "unavailable"


def test_network_counter_reset():
    network_info = SimpleNamespace(
        isup=True,
        speed=1000,
    )

    first = SimpleNamespace(
        bytes_sent=10000,
        bytes_recv=20000,
    )

    reset = SimpleNamespace(
        bytes_sent=100,
        bytes_recv=200,
    )

    with (
        patch.object(
            monitoring.platform,
            "system",
            return_value="Windows",
        ),
        patch.object(
            monitoring.psutil,
            "net_if_stats",
            return_value={"Ethernet": network_info},
        ),
        patch.object(
            monitoring.psutil,
            "net_if_addrs",
            return_value={},
        ),
        patch.object(
            monitoring.psutil,
            "net_io_counters",
            side_effect=[
                {"Ethernet": first},
                {"Ethernet": reset},
            ],
        ),
        patch.object(
            monitoring.time,
            "monotonic",
            side_effect=[100.0, 105.0],
        ),
    ):
        monitoring._NETWORK_SAMPLES = {}

        monitoring.get_network()
        result = monitoring.get_network()

    assert result["upload_bytes_per_second"] is None
    assert result["download_bytes_per_second"] is None


def test_network_speed_calculation():
    network_info = SimpleNamespace(
        isup=True,
        speed=1000,
    )

    first = SimpleNamespace(
        bytes_sent=1000,
        bytes_recv=2000,
    )

    second = SimpleNamespace(
        bytes_sent=6000,
        bytes_recv=12000,
    )

    with (
        patch.object(
            monitoring.platform,
            "system",
            return_value="Windows",
        ),
        patch.object(
            monitoring.psutil,
            "net_if_stats",
            return_value={"Ethernet": network_info},
        ),
        patch.object(
            monitoring.psutil,
            "net_if_addrs",
            return_value={},
        ),
        patch.object(
            monitoring.psutil,
            "net_io_counters",
            side_effect=[
                {"Ethernet": first},
                {"Ethernet": second},
            ],
        ),
        patch.object(
            monitoring.time,
            "monotonic",
            side_effect=[100.0, 105.0],
        ),
    ):
        monitoring._NETWORK_SAMPLES = {}

        first_result = monitoring.get_network()
        second_result = monitoring.get_network()

    assert first_result["upload_bytes_per_second"] is None
    assert second_result["upload_bytes_per_second"] == 1000.0
    assert second_result["download_bytes_per_second"] == 2000.0
