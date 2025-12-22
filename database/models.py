from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

Base = declarative_base()

class ScanHistory(Base):
    __tablename__ = 'scan_history'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_type = Column(String(50), nullable=False)
    scan_path = Column(Text, nullable=False)
    start_time = Column(DateTime, default=datetime.now)
    end_time = Column(DateTime)
    files_scanned = Column(Integer, default=0)
    threats_found = Column(Integer, default=0)
    status = Column(String(20), default='running')
    
    detections = relationship("TrojanDetection", back_populates="scan")
    dynamic_runs = relationship("DynamicRun", back_populates="scan")

class TrojanDetection(Base):
    __tablename__ = 'trojan_detection'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scan_history.id'))
    file_path = Column(Text, nullable=False)
    file_hash = Column(String(64))
    trojan_name = Column(String(100))
    detection_method = Column(String(50))
    threat_level = Column(String(20))
    detected_at = Column(DateTime, default=datetime.now)
    is_quarantined = Column(Boolean, default=False)
    is_removed = Column(Boolean, default=False)
    
    scan = relationship("ScanHistory", back_populates="detections")

class SignatureDB(Base):
    __tablename__ = 'signature_db'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    signature_hash = Column(String(64), unique=True, nullable=False)
    trojan_name = Column(String(100), nullable=False)
    description = Column(Text)
    threat_level = Column(String(20))
    added_date = Column(DateTime, default=datetime.now)

class BehaviourPattern(Base):
    __tablename__ = 'behaviour_patterns'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    pattern_name = Column(String(100), nullable=False)
    pattern_type = Column(String(50))
    pattern_value = Column(Text)
    severity_score = Column(Float)
    is_active = Column(Boolean, default=True)

class Whitelist(Base):
    __tablename__ = 'whitelist'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    file_hash = Column(String(64), unique=True)
    file_path = Column(Text)
    added_at = Column(DateTime, default=datetime.now)

# ===== DYNAMIC ANALYSIS MODELS =====

class DynamicRun(Base):
    __tablename__ = 'dynamic_runs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scan_history.id'), nullable=True)
    sample_path = Column(Text, nullable=False)
    start_time = Column(DateTime, default=datetime.now)
    end_time = Column(DateTime)
    timeout_seconds = Column(Integer, default=30)
    exit_code = Column(Integer)
    duration = Column(Float)
    status = Column(String(20), default='running')  # running, completed, failed
    
    behaviors = relationship("BehaviorSample", back_populates="dynamic_run")
    scan = relationship("ScanHistory", back_populates="dynamic_runs")

class BehaviorSample(Base):
    __tablename__ = 'behavior_samples'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    dynamic_run_id = Column(Integer, ForeignKey('dynamic_runs.id'))
    
    # Process behavior
    process_tree = Column(Text)  # JSON - danh sách processes tạo ra
    cpu_peak = Column(Float, default=0)  # Peak CPU usage
    memory_peak = Column(Float, default=0)  # Peak memory usage MB
    
    # File system behavior
    files_created = Column(Text)  # JSON - danh sách files tạo
    files_modified = Column(Text)  # JSON - danh sách files sửa
    registry_changes = Column(Text)  # JSON - registry modifications
    
    # Network behavior
    network_indicators = Column(Text)  # JSON - IPs, domains, ports
    dns_queries = Column(Text)  # JSON - DNS lookups
    
    # Summary
    threat_score = Column(Float, default=0)  # 0-100
    detected_at = Column(DateTime, default=datetime.now)
    notes = Column(Text)
    
    dynamic_run = relationship("DynamicRun", back_populates="behaviors")