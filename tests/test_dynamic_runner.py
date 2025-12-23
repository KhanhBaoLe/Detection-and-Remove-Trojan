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

    runner = dynamic_runner.DynamicRunner(timeout_seconds=1)
    result = runner.run_sample(str(sample))

    assert result.status == "skipped"
    assert result.reason == "not_executable"
    assert result.exit_code == -216
    assert os.path.basename(result.sample_path) == "fake.exe"

