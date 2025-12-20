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