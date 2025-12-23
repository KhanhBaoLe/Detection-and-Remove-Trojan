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
from config.settings import DATABASE_PATH


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
                )
            ])

        self.session.commit()

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

        sample = BehaviorSample(
            dynamic_run_id=dynamic_run_id,

            process_tree=json.dumps(process_summary.get("child_processes", [])),
            cpu_peak=process_summary.get("max_cpu_percent", 0),
            memory_peak=process_summary.get("max_memory_mb", 0),

            files_created=json.dumps(fs_summary.get("created_files", [])),
            files_modified=json.dumps(fs_summary.get("modified_files", [])),

            network_indicators=json.dumps(
                network_summary.get("connections", [])
            ),

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

        if network.get("connections"):
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
