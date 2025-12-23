import time

from scanner.monitors.fs_monitor import FileSystemMonitor
from scanner.monitors.network_monitor import NetworkMonitor


def test_network_monitor_summary_has_connections_when_disabled():
    monitor = NetworkMonitor(target_pid=0, enabled=False)
    monitor.start()
    monitor.stop()

    summary = monitor.get_summary()

    assert summary["status"] == "disabled"
    assert "connections" in summary
    assert summary["connections"] == []


def test_filesystem_monitor_captures_created_file(tmp_path):
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir()

    monitor = FileSystemMonitor(
        sample_path="dummy",
        monitor_dirs=[str(watch_dir)],
        timeout=4
    )

    monitor.start()
    created_file = watch_dir / "test.txt"
    created_file.write_text("hello")

    # Allow monitor loop to detect the new file
    time.sleep(2.5)
    monitor.stop()

    summary = monitor.get_summary()

    assert summary["files_created"] >= 1
    assert any(str(created_file) in path for path in summary["created_files"])
    assert summary["events"]

