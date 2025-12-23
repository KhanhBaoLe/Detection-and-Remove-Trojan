from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import (
    Base, ScanHistory, TrojanDetection, SignatureDB, BehaviourPattern,
    Whitelist, DynamicRun, BehaviorSample
)
from datetime import datetime
import sys
import os
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import DATABASE_PATH, SIGNATURE_DIR, SIGNATURE_HASH_ALGO


class DatabaseManager:
    def __init__(self):
        self.engine = create_engine(f"sqlite:///{DATABASE_PATH}")
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        self._populate_initial_data()

    # INITIAL DATA
    def _populate_initial_data(self):
        if self.session.query(SignatureDB).count() == 0:
            self.session.add_all([
                SignatureDB(
                    signature_hash="5d41402abc4b2a76b9719d911017c592",
                    trojan_name="Trojan.Generic.Test",
                    description="Test trojan signature",
                    threat_level="high"
                )
            ])

        if self.session.query(BehaviourPattern).count() == 0:
            self.session.add_all([
                BehaviourPattern(
                    pattern_name="Registry Modification",
                    pattern_type="registry",
                    pattern_value="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    severity_score=7.5
                ),
                BehaviourPattern(
                    pattern_name="Process Injection",
                    pattern_type="api",
                    pattern_value="WriteProcessMemory",
                    severity_score=6.0
                ),
                BehaviourPattern(
                    pattern_name="Network Beacon",
                    pattern_type="network",
                    pattern_value="http://",
                    severity_score=4.0
                ),
                BehaviourPattern(
                    pattern_name="Powershell Encoded",
                    pattern_type="powershell",
                    pattern_value="PowerShell -enc",
                    severity_score=5.0
                )
            ])

        self.session.commit()

        # Load external signature bundles (if any)
        self.sync_signature_dir()
        # Load external behaviour pattern bundles (if any)
        self.sync_behaviour_patterns()

    def sync_signature_dir(self):
        """
        Import signatures from files in SIGNATURE_DIR.
        Format per line: hash,trojan_name,threat_level
        """
        if not os.path.isdir(SIGNATURE_DIR):
            return

        added = 0
        for fname in os.listdir(SIGNATURE_DIR):
            if not fname.lower().endswith((".txt", ".sig", ".csv")):
                continue
            path = os.path.join(SIGNATURE_DIR, fname)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = [p.strip() for p in line.split(",")]
                        if len(parts) < 2:
                            continue
                        signature_hash = parts[0].lower()
                        trojan_name = parts[1] or "Unknown"
                        threat_level = parts[2] if len(parts) > 2 else "high"

                        if not signature_hash:
                            continue
                        if self.session.query(SignatureDB).filter_by(
                            signature_hash=signature_hash
                        ).first():
                            continue

                        self.session.add(SignatureDB(
                            signature_hash=signature_hash,
                            trojan_name=trojan_name,
                            threat_level=threat_level
                        ))
                        added += 1
                self.session.commit()
            except Exception:
                self.session.rollback()
                continue

        if added:
            print(f"✅ Synced {added} signatures from {SIGNATURE_DIR}")

    def sync_behaviour_patterns(self):
        """
        Import behaviour patterns from JSON bundles in SIGNATURE_DIR.
        Expected schema: list of dicts with keys
        pattern_name, pattern_type, pattern_value, severity_score, is_active
        """
        bundle_path = os.path.join(SIGNATURE_DIR, "behaviour_patterns.json")
        if not os.path.isfile(bundle_path):
            return

        added = 0
        try:
            with open(bundle_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, list):
                    return

            for pattern in data:
                name = (pattern.get("pattern_name") or "").strip()
                if not name:
                    continue

                existing = self.session.query(BehaviourPattern)\
                    .filter_by(pattern_name=name)\
                    .first()
                if existing:
                    continue

                self.session.add(BehaviourPattern(
                    pattern_name=name,
                    pattern_type=pattern.get("pattern_type", "generic"),
                    pattern_value=pattern.get("pattern_value", ""),
                    severity_score=pattern.get("severity_score", 5.0),
                    is_active=pattern.get("is_active", True)
                ))
                added += 1

            self.session.commit()
        except Exception:
            self.session.rollback()
            return

        if added:
            print(f"✅ Synced {added} behaviour patterns from {bundle_path}")

    # BASIC SCAN METHODS
    def add_scan(self, scan_type, scan_path):
        scan = ScanHistory(scan_type=scan_type, scan_path=scan_path)
        self.session.add(scan)
        self.session.commit()
        return scan.id

    def update_scan(self, scan_id, **kwargs):
        scan = self.session.query(ScanHistory).filter_by(id=scan_id).first()
        if scan:
            for k, v in kwargs.items():
                setattr(scan, k, v)
            self.session.commit()

    # DYNAMIC ANALYSIS
    def add_dynamic_run(self, scan_id, sample_path, timeout=30):
        run = DynamicRun(
            scan_id=scan_id,
            sample_path=sample_path,
            timeout_seconds=timeout,
            status="running"
        )
        self.session.add(run)
        self.session.commit()
        return run.id

    
    def add_behavior_sample(self, dynamic_run_id, execution_result):
        behavior_data = execution_result.to_dict()

        def safe_first(lst):
            if isinstance(lst, list) and len(lst) > 0 and isinstance(lst[0], dict):
                return lst[0]
            return {}

        process_summary = safe_first(behavior_data.get("process_summary"))
        fs_summary = safe_first(behavior_data.get("fs_summary"))
        network_summary = safe_first(behavior_data.get("network_summary"))

        network_indicators = (
            network_summary.get("connections")
            or network_summary.get("remote_hosts", [])
        )

        note_payload = {
            "status": behavior_data.get("status"),
            "reason": behavior_data.get("reason"),
            "sandbox_dir": behavior_data.get("sandbox_dir")
        }

        sample = BehaviorSample(
            dynamic_run_id=dynamic_run_id,

            process_tree=json.dumps(process_summary.get("child_processes", [])),
            cpu_peak=process_summary.get("max_cpu_percent", 0),
            memory_peak=process_summary.get("max_memory_mb", 0),

            files_created=json.dumps(fs_summary.get("created_files", [])),
            files_modified=json.dumps(fs_summary.get("modified_files", [])),

            network_indicators=json.dumps(network_indicators),
            notes=json.dumps(note_payload),

            threat_score=self._calculate_threat_score(
                process_summary,
                fs_summary,
                network_summary
            )
        )

        self.session.add(sample)
        self.session.commit()
        return sample

    # THREAT SCORE
    def _calculate_threat_score(self, process, fs, network):
        score = 0.0

        if process.get("child_processes"):
            score += 20

        score += min(len(fs.get("created_files", [])) * 5, 30)

        if fs.get("modified_files"):
            score += 15

        connections = network.get("connections") or network.get("remote_hosts")
        if connections:
            score += 25

        return min(score, 100)

    # CLEANUP
    def update_dynamic_run(self, run_id, **kwargs):
        run = self.session.query(DynamicRun).filter_by(id=run_id).first()
        if run:
            for k, v in kwargs.items():
                setattr(run, k, v)
            self.session.commit()

    def get_statistics(self):
        """Lấy thống kê tổng quan cho GUI"""
        total_scans = self.session.query(ScanHistory).count()
        total_threats = self.session.query(TrojanDetection).count()
        critical_threats = self.session.query(TrojanDetection).filter_by(
            threat_level='critical'
        ).count()

        return {
            'total_scans': total_scans,
            'total_threats': total_threats,
            'critical_threats': critical_threats
        }

    def get_removed_count(self):
        """Count files in quarantine directory"""
        try:
            quarantine_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'quarantine', 'quarantined'
            )
            if os.path.exists(quarantine_path):
                return len([f for f in os.listdir(quarantine_path) 
                        if os.path.isfile(os.path.join(quarantine_path, f))])
            return 0
        except Exception:
            return 0
        
    def get_all_scans(self, limit=None):
        query = self.session.query(ScanHistory)\
            .order_by(ScanHistory.id.desc())

        if limit is not None:
            query = query.limit(limit)

        return query.all()   # ⚠️ TRẢ VỀ ORM OBJECT


    def get_detections_by_scan(self, scan_id):
        return self.session.query(TrojanDetection)\
                        .filter_by(scan_id=scan_id)\
                        .all()



        # ===== STATIC / SIGNATURE =====
    def add_detection(self, scan_id, file_path, file_hash,
                    trojan_name, detection_method, threat_level):
        detection = TrojanDetection(
            scan_id=scan_id,
            file_path=file_path,
            file_hash=file_hash,
            trojan_name=trojan_name,
            detection_method=detection_method,
            threat_level=threat_level
        )
        self.session.add(detection)
        self.session.commit()
        return detection.id

    def check_signature(self, file_hash):
        return self.session.query(SignatureDB)\
            .filter_by(signature_hash=file_hash)\
            .first()

    # ===== WHITELIST =====
    def is_whitelisted(self, file_hash):
        return self.session.query(Whitelist)\
            .filter_by(file_hash=file_hash)\
            .first() is not None

    def add_to_whitelist(self, file_hash, file_path):
        wl = Whitelist(
            file_hash=file_hash,
            file_path=file_path
        )
        self.session.add(wl)
        self.session.commit()

    # ===== QUARANTINE / REMOVAL =====
    def mark_as_removed(self, detection_id):
        detection = self.session.query(TrojanDetection)\
            .filter_by(id=detection_id)\
            .first()
        if detection:
            detection.status = "removed"
            detection.is_removed = True
            detection.is_quarantined = True
            self.session.commit()
            return True
        return False

    # ===== DYNAMIC VIEW =====
    def get_dynamic_run(self, run_id):
        return self.session.query(DynamicRun)\
            .filter_by(id=run_id)\
            .first()

    def get_behavior_samples(self, dynamic_run_id):
        return self.session.query(BehaviorSample)\
            .filter_by(dynamic_run_id=dynamic_run_id)\
            .all()


    def close(self):
        self.session.close()
