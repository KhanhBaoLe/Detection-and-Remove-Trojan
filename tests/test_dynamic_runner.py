import os

import scanner.dynamic_runner as dynamic_runner


def test_dynamic_runner_handles_not_executable(monkeypatch, tmp_path):
    sample = tmp_path / "fake.exe"
    sample.write_text("not-a-valid-executable")

    monkeypatch.setattr(dynamic_runner, "DYNAMIC_SANDBOX_DIR", str(tmp_path))

    def raise_oserror(*args, **kwargs):
        err = OSError("not executable")
        err.winerror = 216
        raise err

    monkeypatch.setattr(dynamic_runner.subprocess, "Popen", raise_oserror)

    runner = dynamic_runner.DynamicRunner(timeout_seconds=1, use_firewall_guard=False)
    result = runner.run_sample(str(sample))

    assert result.status == "skipped"
    assert result.reason == "not_executable"
    assert result.exit_code == -216
    assert os.path.basename(result.sample_path) == "fake.exe"


def _stub_monitors(monkeypatch):
    class DummyMonitor:
        def __init__(self, *args, **kwargs):
            self.pid = kwargs.get("pid", 0)

        def start(self):
            return None

        def stop(self):
            return None

        def get_summary(self):
            return {}

        def get_records(self):
            return []

    monkeypatch.setattr(dynamic_runner, "ProcessMonitor", DummyMonitor)
    monkeypatch.setattr(dynamic_runner, "FileSystemMonitor", DummyMonitor)
    monkeypatch.setattr(dynamic_runner, "NetworkMonitor", DummyMonitor)


def _stub_process(monkeypatch):
    class DummyProcess:
        pid = 1111

        def wait(self, timeout=None):
            return 0

        def kill(self):
            return None

    monkeypatch.setattr(dynamic_runner.subprocess, "Popen", lambda *args, **kwargs: DummyProcess())


def test_dynamic_runner_skips_guard_when_disabled(monkeypatch, tmp_path):
    sample = tmp_path / "guard_disabled.exe"
    sample.write_text("fake-binary")

    monkeypatch.setattr(dynamic_runner, "DYNAMIC_SANDBOX_DIR", str(tmp_path))
    _stub_monitors(monkeypatch)
    _stub_process(monkeypatch)

    applied = {"called": False}

    class TrackingGuard:
        def __init__(self, *args, **kwargs):
            applied["init"] = True

        def apply(self):
            applied["called"] = True

        def remove(self):
            applied["removed"] = True

    monkeypatch.setattr(dynamic_runner, "SandboxNetworkGuard", TrackingGuard)

    runner = dynamic_runner.DynamicRunner(timeout_seconds=1, use_firewall_guard=False)
    result = runner.run_sample(str(sample))

    assert result.status == "completed"
    assert applied["called"] is False
    assert runner.network_guard is None


def test_dynamic_runner_respects_config_guard_flag(monkeypatch, tmp_path):
    sample = tmp_path / "guard_config.exe"
    sample.write_text("fake-binary")

    monkeypatch.setattr(dynamic_runner, "DYNAMIC_SANDBOX_DIR", str(tmp_path))
    monkeypatch.setattr(dynamic_runner, "DYNAMIC_FIREWALL_GUARD_ENABLED", False)
    _stub_monitors(monkeypatch)
    _stub_process(monkeypatch)

    applied = {"called": False}

    class TrackingGuard:
        def __init__(self, *args, **kwargs):
            applied["init"] = True

        def apply(self):
            applied["called"] = True

        def remove(self):
            applied["removed"] = True

    monkeypatch.setattr(dynamic_runner, "SandboxNetworkGuard", TrackingGuard)

    runner = dynamic_runner.DynamicRunner(timeout_seconds=1)
    result = runner.run_sample(str(sample))

    assert result.status == "completed"
    assert applied["called"] is False
    assert runner.network_guard is None

