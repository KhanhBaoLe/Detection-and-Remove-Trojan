from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from database.models import (
    Base, ScanHistory, TrojanDetection, SignatureDB, BehaviourPattern,
    Whitelist, DynamicRun, BehaviorSample
)
from datetime import datetime
import os
import json
from config.settings import DATABASE_PATH, SIGNATURE_DIR, SIGNATURE_HASH_ALGO

class DatabaseManager:
    def __init__(self):
        self.engine = create_engine(f"sqlite:///{DATABASE_PATH}")
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        self._populate_initial_data()

    def _populate_initial_data(self):
        # Tạo dữ liệu mẫu nếu DB trống
        if self.session.query(SignatureDB).count() == 0:
            # Thêm EICAR signature test
            self.session.add(SignatureDB(
                signature_hash="44d88612fea8a8f36de82e1278abb02f", # EICAR MD5
                trojan_name="EICAR-Test-File",
                description="Standard Antivirus Test File",
                threat_level="high"
            ))
            self.session.commit()

        if self.session.query(BehaviourPattern).count() == 0:
            patterns = [
                ("Reverse Shell", "string", "cmd.exe", 8.0),
                ("PowerShell Encoded", "string", "powershell -enc", 9.0),
                ("Keylogger Hook", "string", "SetWindowsHookEx", 7.0),
            ]
            for name, ptype, val, score in patterns:
                self.session.add(BehaviourPattern(
                    pattern_name=name, pattern_type=ptype, 
                    pattern_value=val, severity_score=score
                ))
            self.session.commit()

    # ===== SCAN MANAGEMENT =====
    def add_scan(self, scan_type, scan_path):
        scan = ScanHistory(scan_type=scan_type, scan_path=scan_path)
        self.session.add(scan)
        self.session.commit()
        return scan.id

    def update_scan(self, scan_id, **kwargs):
        scan = self.session.query(ScanHistory).filter_by(id=scan_id).first()
        if scan:
            for key, value in kwargs.items():
                setattr(scan, key, value)
            self.session.commit()

    def get_all_scans(self, limit=50):
        return self.session.query(ScanHistory).order_by(ScanHistory.start_time.desc()).limit(limit).all()

    def get_statistics(self):
        total_scans = self.session.query(ScanHistory).count()
        total_threats = self.session.query(TrojanDetection).count()
        return {"total_scans": total_scans, "total_threats_found": total_threats}

    def get_removed_count(self):
        return self.session.query(TrojanDetection).filter_by(is_removed=True).count()

    # ===== DETECTION MANAGEMENT =====
    def add_detection(self, scan_id, file_path, file_hash, trojan_name, detection_method, threat_level):
        # Tránh trùng lặp trong cùng 1 lần scan
        exists = self.session.query(TrojanDetection).filter_by(
            scan_id=scan_id, file_path=file_path, trojan_name=trojan_name
        ).first()
        
        if not exists:
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

    def get_detections_by_scan(self, scan_id):
        return self.session.query(TrojanDetection).filter_by(scan_id=scan_id).all()

    def get_active_detections_by_scan(self, scan_id):
        return self.session.query(TrojanDetection).filter_by(
            scan_id=scan_id, is_removed=False, is_quarantined=False
        ).all()

    def mark_as_quarantined(self, detection_id, quarantine_path):
        det = self.session.query(TrojanDetection).filter_by(id=detection_id).first()
        if det:
            det.is_quarantined = True
            det.is_removed = True
            self.session.commit()

    # ===== SIGNATURE & WHITELIST =====
    def is_whitelisted(self, file_hash):
        return self.session.query(Whitelist).filter_by(file_hash=file_hash).first() is not None

    def check_signature(self, file_hash):
        return self.session.query(SignatureDB).filter_by(signature_hash=file_hash).first()

    def sync_signature_dir(self):
        pass

    # ===== DYNAMIC ANALYSIS =====
    def add_dynamic_run(self, scan_id, sample_path, timeout):
        run = DynamicRun(scan_id=scan_id, sample_path=sample_path, timeout_seconds=timeout)
        self.session.add(run)
        self.session.commit()
        return run.id

    def update_dynamic_run(self, run_id, **kwargs):
        run = self.session.query(DynamicRun).filter_by(id=run_id).first()
        if run:
            for key, value in kwargs.items():
                setattr(run, key, value)
            if 'status' in kwargs and kwargs['status'] in ['completed', 'failed']:
                run.end_time = datetime.now()
            self.session.commit()

    def add_behavior_sample(self, run_id, result_obj, score_data=None):
        import json
        summary = result_obj.to_dict()
        
        # Helper để lấy phần tử đầu tiên của list summary
        def get_data(key):
            items = summary.get(key, [])
            return items[0] if items else {}

        proc = get_data('process_summary')
        fs = get_data('fs_summary')
        net = get_data('network_summary')
        reg = get_data('registry_summary')
        
        score = 0
        if score_data:
            score = score_data.get('threat_score', 0)

        sample = BehaviorSample(
            dynamic_run_id=run_id,
            process_tree=json.dumps(proc.get('processes', [])),
            cpu_peak=0, 
            memory_peak=proc.get('max_memory_mb', 0),
            files_created=json.dumps(fs.get('created_files', [])),
            files_modified=json.dumps(fs.get('modified_files', [])),
            registry_changes=json.dumps(reg.get('persistence_changes', [])),
            network_indicators=json.dumps(net.get('traffic_log', [])),
            threat_score=score
        )
        self.session.add(sample)
        self.session.commit()
        return sample

    def get_all_dynamic_runs(self, limit=20):
        return self.session.query(DynamicRun).order_by(DynamicRun.start_time.desc()).limit(limit).all()

    def get_behavior_samples(self, run_id):
        return self.session.query(BehaviorSample).filter_by(dynamic_run_id=run_id).all()