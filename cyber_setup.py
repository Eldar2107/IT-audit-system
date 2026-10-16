import os
import tempfile
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, DateTime
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.pool import StaticPool
from datetime import datetime

load_dotenv()

# Streamlit secrets və ya mühit dəyişənlərindən DATABASE_URL oxunması
DATABASE_URL = None
try:
    import streamlit as st
    if hasattr(st, "secrets") and "DATABASE_URL" in st.secrets:
        DATABASE_URL = st.secrets["DATABASE_URL"]
except Exception:
    pass

if not DATABASE_URL:
    DATABASE_URL = os.getenv("DATABASE_URL")

# Cloud PostgreSQL üçün URI uyğunlaşdırması (postgres:// -> postgresql://)
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Streamlit Cloud mühitində (məsələn /mount qovluğunda) localhost PostgreSQL işləmir
is_cloud = os.path.exists("/mount") or os.getenv("STREAMLIT_SERVER_PORT") is not None

def get_engine():
    global DATABASE_URL
    
    # Əgər cloud mühitidirsə və ya DATABASE_URL localhost-dursa, birbaşa SQLite-a keç
    if is_cloud and DATABASE_URL and ("localhost" in DATABASE_URL or "127.0.0.1" in DATABASE_URL):
        DATABASE_URL = None

    if DATABASE_URL:
        try:
            test_engine = create_engine(DATABASE_URL, pool_pre_ping=True)
            with test_engine.connect() as conn:
                pass
            return test_engine
        except Exception:
            pass
    
    # Streamlit Cloud-da /mount qovluğu read-only ola bildiyi üçün bazanı /tmp (tempdir) içində saxlayırıq
    try:
        tmp_dir = tempfile.gettempdir()
        db_path = os.path.join(tmp_dir, "cyber_audit.db")
        DATABASE_URL = f"sqlite:///{db_path}"
        return create_engine(
            DATABASE_URL, 
            connect_args={"check_same_thread": False}
        )
    except Exception:
        # Ən pis halda in-memory SQLite bazası (hər zaman 100% işləyir)
        DATABASE_URL = "sqlite:///:memory:"
        return create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )

engine = get_engine()
Session = sessionmaker(bind=engine)
Base = declarative_base()

def get_session():
    global Session
    return Session()

def get_db_type():
    global DATABASE_URL
    if DATABASE_URL and "postgresql" in str(DATABASE_URL):
        return "PostgreSQL"
    return "SQLite (Cloud Rejimi)"

# 1. Kateqoriyalar cədvəli
class VulnCategory(Base):
    __tablename__ = 'vuln_categories'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    
    vulnerabilities = relationship("Vulnerability", back_populates="category")

# 2. Zəifliklər cədvəli
class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False)
    cvss_score = Column(Float, nullable=False)
    category_id = Column(Integer, ForeignKey('vuln_categories.id'))
    
    category = relationship("VulnCategory", back_populates="vulnerabilities")
    audit_logs = relationship("AuditLog", back_populates="vulnerability")

# 3. Audit və Test Qeydləri cədvəli
class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'))
    tested_count = Column(Integer, nullable=False)
    scanned_at = Column(DateTime, default=datetime.utcnow)
    
    vulnerability = relationship("Vulnerability", back_populates="audit_logs")

def setup_cyber_db():
    global engine, Session, DATABASE_URL
    try:
        Base.metadata.create_all(engine)
    except Exception:
        # Hər hansı fayl yazma / icazə xətası olarsa, dərhal in-memory bazaya keçid
        DATABASE_URL = "sqlite:///:memory:"
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )
        Session = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)

    session = Session()
    try:
        # Əgər baza boşdursa, nümayiş üçün ilkin nümunə məlumatları əlavə edirik
        if session.query(VulnCategory).count() == 0:
            c_web = VulnCategory(name="Web Security")
            c_crypto = VulnCategory(name="Cryptography")
            c_net = VulnCategory(name="Network Security")
            c_cloud = VulnCategory(name="Cloud Security")
            session.add_all([c_web, c_crypto, c_net, c_cloud])
            session.commit()

            v1 = Vulnerability(title="SQL Injection (Login Bypass)", cvss_score=9.8, category=c_web)
            v2 = Vulnerability(title="Weak RSA Key Generation", cvss_score=7.5, category=c_crypto)
            v3 = Vulnerability(title="Cross-Site Scripting (Stored XSS)", cvss_score=7.2, category=c_web)
            v4 = Vulnerability(title="Open SSH Port Without MFA", cvss_score=6.8, category=c_net)
            session.add_all([v1, v2, v3, v4])
            session.commit()

            log1 = AuditLog(vulnerability=v1, tested_count=5)
            log2 = AuditLog(vulnerability=v2, tested_count=3)
            log3 = AuditLog(vulnerability=v3, tested_count=7)
            session.add_all([log1, log2, log3])
            session.commit()
    except Exception as e:
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    setup_cyber_db()
    print("Kiberbəhlükəsizlik cədvəlləri uğurla quruldu ✓")