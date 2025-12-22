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
from utils.logger import setup_logger
logger = setup_logger("DB")
class DatabaseManager:
    def __init__(self):
        self.engine = create_engine(f'sqlite:///{DATABASE_PATH}')
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        self._populate_initial_data()
    
    def _populate_initial_data(self):
        """Thêm dữ liệu mẫu nếu database trống"""
        if self.session.query(SignatureDB).count() == 0:
            signatures = [
                SignatureDB(signature_hash="5d41402abc4b2a76b9719d911017c592", 
                        trojan_name="Trojan.Generic.Test", 
                        description="Test trojan signature",
                        threat_level="high"),
                SignatureDB(signature_hash="098f6bcd4621d373cade4e832627b4f6",
                        trojan_name="Trojan.Downloader.Agent",
                        description="Downloads malicious payload",
                        threat_level="critical"),
            ]
            self.session.add_all(signatures)
        
        if self.session.query(BehaviourPattern).count() == 0:
            patterns = [
                BehaviourPattern(pattern_name="Registry Modification",
                            pattern_type="registry",
                            pattern_value="HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
                            severity_score=7.5),
                BehaviourPattern(pattern_name="Suspicious Network Activity",
                            pattern_type="network",
                            pattern_value="Unknown outbound connections",
                            severity_score=8.0),
            ]
            self.session.add_all(patterns)
        
        self.session.commit()
    
    def add_scan(self, scan_type, scan_path):
        try:
            scan = ScanHistory(scan_type=scan_type, scan_path=scan_path)
            self.session.add(scan)
            self.session.commit()
            logger.info(f"New scan added | type={scan_type} path={scan_path}")
            return scan.id
        except Exception as e:
            logger.exception("Failed to add scan")
            self.session.rollback()
            raise

    
    def update_scan(self, scan_id, **kwargs):
        scan = self.session.query(ScanHistory).filter_by(id=scan_id).first()
        if scan:
            for key, value in kwargs.items():
                setattr(scan, key, value)
            self.session.commit()
    
    def add_detection(self, scan_id, file_path, file_hash, trojan_name, detection_method, threat_level):
        detection = TrojanDetection(
            scan_id=scan_id, file_path=file_path, file_hash=file_hash,
            trojan_name=trojan_name, detection_method=detection_method,
            threat_level=threat_level
        )
        self.session.add(detection)
        self.session.commit()
        return detection.id
    
    def mark_as_removed(self, detection_id):
        """Đánh dấu threat đã bị xóa"""
        detection = self.session.query(TrojanDetection).filter_by(id=detection_id).first()
        if detection:
            detection.is_removed = True
            detection.is_quarantined = True
            self.session.commit()
            return True
        return False
    
    def get_removed_count(self):
        """Đếm số threats đã bị xóa"""
        return self.session.query(TrojanDetection).filter_by(is_removed=True).count()
    
    def get_all_scans(self, limit=50):
        return self.session.query(ScanHistory).order_by(ScanHistory.start_time.desc()).limit(limit).all()
    
    def get_detections_by_scan(self, scan_id):
        return self.session.query(TrojanDetection).filter_by(scan_id=scan_id).all()
    
    def check_signature(self, file_hash):
        return self.session.query(SignatureDB).filter_by(signature_hash=file_hash).first()
    
    def is_whitelisted(self, file_hash=None, file_path=None):
        query = self.session.query(Whitelist)

        if file_hash:
            query = query.filter_by(file_hash=file_hash)

        if file_path:
            query = query.filter_by(file_path=file_path)

        return query.first() is not None
        
    def add_whitelist(self, value):
        exists = self.session.query(Whitelist)\
            .filter(
                (Whitelist.file_hash == value) |
                (Whitelist.file_path == value)
            ).first()

        if exists:
            return False

        wl = Whitelist(
            file_hash=value if len(value) == 32 else None,
            file_path=value if len(value) != 32 else None
        )
        self.session.add(wl)
        self.session.commit()
        return True

    
    def get_statistics(self):
        total_scans = self.session.query(ScanHistory).count()
        total_threats = self.session.query(TrojanDetection).count()
        critical_threats = self.session.query(TrojanDetection).filter_by(threat_level='critical').count()
        return {
            'total_scans': total_scans,
            'total_threats': total_threats,
            'critical_threats': critical_threats
        }

    
    # ===== DYNAMIC ANALYSIS METHODS =====
    
    def add_dynamic_run(self, scan_id, sample_path, timeout=30):
        """Thêm dynamic run record"""
        run = DynamicRun(
            scan_id=scan_id,
            sample_path=sample_path,
            timeout_seconds=timeout,
            status='running'
        )
        self.session.add(run)
        self.session.commit()
        return run.id
    
    def add_behavior_sample(self, dynamic_run_id, execution_result):
        """Thêm behavior sample từ execution result"""
        behavior_data = execution_result.to_dict()
        
        # Tích hợp dữ liệu
        process_summary = behavior_data.get('process_summary', [{}])[0]
        fs_summary = behavior_data.get('fs_summary', [{}])[0]
        network_summary = behavior_data.get('network_summary', [{}])[0]
        
        sample = BehaviorSample(
            dynamic_run_id=dynamic_run_id,
            process_tree=json.dumps(process_summary.get('child_processes', [])),
            cpu_peak=process_summary.get('max_cpu_percent', 0),
            memory_peak=process_summary.get('max_memory_mb', 0),
            files_created=json.dumps(fs_summary.get('created_files', [])),
            files_modified=json.dumps(fs_summary.get('modified_files', [])),
            network_indicators=json.dumps(network_summary.get('connections', [])),
            threat_score=self._calculate_threat_score(process_summary, fs_summary, network_summary)
        )
        
        self.session.add(sample)
        self.session.commit()
        return sample
    
    def _calculate_threat_score(self, process_info, fs_info, network_info):
        """Tính điểm đe dọa từ hành vi"""
        score = 0.0
        
        # Quá trình con
        if process_info.get('child_processes'):
            score += 20
        
        # Số file tạo
        files_created = len(fs_info.get('created_files', []))
        score += min(files_created * 5, 30)
        
        # Sửa registry
        if fs_info.get('modified_files'):
            score += 15
        
        # Network activity
        if network_info.get('connections'):
            score += 25
        
        return min(score, 100)
    
    def get_dynamic_run(self, run_id):
        """Lấy dynamic run"""
        return self.session.query(DynamicRun).filter_by(id=run_id).first()
    
    def get_behavior_samples(self, dynamic_run_id):
        """Lấy behavior samples"""
        return self.session.query(BehaviorSample).filter_by(
            dynamic_run_id=dynamic_run_id
        ).all()
    
    def update_dynamic_run(self, run_id, **kwargs):
        """Cập nhật dynamic run"""
        run = self.session.query(DynamicRun).filter_by(id=run_id).first()
        if run:
            for key, value in kwargs.items():
                setattr(run, key, value)
            self.session.commit()
    

    def mark_as_quarantined(self, detection_id, new_path):
        detection = self.session.query(TrojanDetection).filter_by(id=detection_id).first()
        if detection:
            detection.is_quarantined = True
            detection.file_path = new_path
            self.session.commit()

    def remove_detection(self, detection_id):
        detection = self.session.query(TrojanDetection)\
            .filter_by(id=detection_id)\
            .first()

        if not detection:
            return False

        self.session.delete(detection)
        self.session.commit()
        return True

    def list_detections(
        self,
        scan_id=None,
        quarantined=None,
        threat_level=None,
        detection_method=None
    ):
        query = self.session.query(TrojanDetection)

        if scan_id is not None:
            query = query.filter_by(scan_id=scan_id)

        if quarantined is not None:
            query = query.filter_by(is_quarantined=quarantined)

        if threat_level:
            query = query.filter_by(threat_level=threat_level)

        if detection_method:
            query = query.filter_by(detection_method=detection_method)

        return query.all()


    def get_active_detections_by_scan(self, scan_id):
        return self.session.query(TrojanDetection)\
            .filter_by(scan_id=scan_id, is_quarantined=False)\
            .all()


    def close(self):
        self.session.close()