import os
import threading
import time
from datetime import datetime


class FileSystemMonitor:
    def __init__(self, sample_path, monitor_dirs=None, timeout=30):
        self.sample_path = sample_path
        self.monitor_dirs = monitor_dirs or [
            os.path.expandvars("%APPDATA%"),
            os.path.expandvars("%TEMP%")
        ]
        self.timeout = timeout
        self.running = False
        self.monitor_thread = None

        self.initial_state = {}
        self.file_events = []

    # =============================
    # START / STOP
    # =============================
    def start(self):
        self._capture_initial_state()
        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )
        self.monitor_thread.start()

    def stop(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)

    # =============================
    # INITIAL SNAPSHOT
    # =============================
    def _capture_initial_state(self):
        for monitor_dir in self.monitor_dirs:
            if not os.path.exists(monitor_dir):
                continue

            for root, _, files in os.walk(monitor_dir):
                for f in files:
                    path = os.path.join(root, f)
                    try:
                        stat = os.stat(path)
                        self.initial_state[path] = {
                            "mtime": stat.st_mtime,
                            "size": stat.st_size
                        }
                    except:
                        continue

    # =============================
    # MONITOR LOOP
    # =============================
    def _monitor_loop(self):
        start_time = time.time()

        while self.running:
            if time.time() - start_time > self.timeout:
                break

            for monitor_dir in self.monitor_dirs:
                if not os.path.exists(monitor_dir):
                    continue

                for root, _, files in os.walk(monitor_dir):
                    for f in files:
                        path = os.path.join(root, f)
                        try:
                            stat = os.stat(path)
                            mtime = stat.st_mtime
                            size = stat.st_size

                            if path not in self.initial_state:
                                self.file_events.append({
                                    "timestamp": datetime.now().isoformat(),
                                    "event_type": "created",
                                    "file_path": path,
                                    "size": size
                                })
                                self.initial_state[path] = {
                                    "mtime": mtime,
                                    "size": size
                                }

                            elif self.initial_state[path]["mtime"] != mtime:
                                self.file_events.append({
                                    "timestamp": datetime.now().isoformat(),
                                    "event_type": "modified",
                                    "file_path": path,
                                    "size": size
                                })
                                self.initial_state[path]["mtime"] = mtime

                        except:
                            continue

            time.sleep(2)

    # =============================
    # SAFE OUTPUT
    # =============================
    def get_records(self):
        return self.file_events

    def get_summary(self):
        if not self.file_events:
            return {
                "status": "no_fs_activity",
                "total_events": 0,
                "files_created": 0,
                "files_modified": 0,
                "created_files": [],
                "modified_files": []
            }

        created = []
        modified = []

        for e in self.file_events:
            if not isinstance(e, dict):
                continue

            if e.get("event_type") == "created":
                created.append(e.get("file_path"))
            elif e.get("event_type") == "modified":
                modified.append(e.get("file_path"))

        return {
            "status": "ok",
            "total_events": len(self.file_events),
            "files_created": len(created),
            "files_modified": len(modified),
            "created_files": created[:20],
            "modified_files": modified[:20]
        }
