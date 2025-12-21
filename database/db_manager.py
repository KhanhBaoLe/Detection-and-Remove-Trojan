from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base, ScanHistory, TrojanDetection, SignatureDB, BehaviourPattern, Whitelist
from datetime import datetime
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import DATABASE_PATH

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
    
    def is_whitelisted(self, file_hash):
        return self.session.query(Whitelist).filter_by(file_hash=file_hash).first() is not None
    
    def add_to_whitelist(self, file_hash, file_path):
        whitelist = Whitelist(file_hash=file_hash, file_path=file_path)
        self.session.add(whitelist)
        self.session.commit()
    
    def get_statistics(self):
        total_scans = self.session.query(ScanHistory).count()
        total_threats = self.session.query(TrojanDetection).count()
        critical_threats = self.session.query(TrojanDetection).filter_by(threat_level='critical').count()
        return {
            'total_scans': total_scans,
            'total_threats': total_threats,
            'critical_threats': critical_threats
        }
    
    def close(self):
        self.session.close()