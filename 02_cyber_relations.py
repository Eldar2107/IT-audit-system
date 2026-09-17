import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from cyber_setup import VulnCategory, Vulnerability, AuditLog, DATABASE_URL

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

print("--- 1. Kateqoriyaya görə zəifliklər (category.vulnerabilities) ---")
category = session.query(VulnCategory).filter_by(name="Web Security").first()
if category:
    print(f"Kateqoriya: {category.name}")
    for v in category.vulnerabilities:
        print(f"  - Zəiflik: {v.title} (CVSS: {v.cvss_score})")

print("\n--- 2. Audit logunun yaradılması və əlaqə zənciri ---")
# Web Security kateqoriyasından bir zəiflik tapırıq
sqli = session.query(Vulnerability).filter_by(title="SQL Injection (Login Bypass)").first()

if sqli:
    # Yeni audit logu əlavə edirik (restorandakı sifariş əlavə etməyin analoqu)
    new_log = AuditLog(vulnerability=sqli, tested_count=4)
    session.add(new_log)
    session.commit()
    print("Yeni audit logu əlavə edildi ✓")

print("\n--- 3. Logdan kateqoriyaya keçid zənciri (log.vulnerability.category) ---")
logs = session.query(AuditLog).all()
for l in logs:
    print(f"Log ID: {l.id} | Zəiflik: {l.vulnerability.title} | Test Sayı: {l.tested_count} | Kateqoriya: {l.vulnerability.category.name}")

session.close()