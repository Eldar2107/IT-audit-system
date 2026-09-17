import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
Base = declarative_base()

# 1. Kateqoriyalar cədvəli (Məsələn: Web Security, Cryptography)
class VulnCategory(Base):
    __tablename__ = 'vuln_categories'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    
    vulnerabilities = relationship("Vulnerability", back_populates="category")

# 2. Zəifliklər/Tapşırıqlar cədvəli (Restorandakı menyu məhsullarının yerinə)
class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False)
    cvss_score = Column(Float, nullable=False)  # Təhlükə balı
    category_id = Column(Integer, ForeignKey('vuln_categories.id'))
    
    category = relationship("VulnCategory", back_populates="vulnerabilities")
    audit_logs = relationship("AuditLog", back_populates="vulnerability")

# 3. Audit və Test Qeydləri cədvəli (Restorandakı sifarişlərin yerinə)
class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'))
    tested_count = Column(Integer, nullable=False)  # Test sayı
    scanned_at = Column(DateTime, default=datetime.utcnow)
    
    vulnerability = relationship("Vulnerability", back_populates="audit_logs")

def setup_cyber_db():
    Base.metadata.create_all(engine)
    print("Kiberbəhlükəsizlik cədvəlləri uğurla quruldu ✓")

if __name__ == "__main__":
    setup_cyber_db()