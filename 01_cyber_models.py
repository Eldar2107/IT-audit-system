import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from cyber_setup import VulnCategory, Vulnerability, AuditLog, DATABASE_URL

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

print("--- 1. Kateqoriya və Zəifliklərin Əlavə Edilməsi ---")
cat_web = VulnCategory(name="Web Security")
cat_crypto = VulnCategory(name="Cryptography")

vuln1 = Vulnerability(title="SQL Injection (Login Bypass)", cvss_score=9.8, category=cat_web)
vuln2 = Vulnerability(title="Weak RSA Key Generation", cvss_score=7.5, category=cat_crypto)

session.add_all([cat_web, cat_crypto, vuln1, vuln2])
session.commit()
print("Zəifliklər bazaya yazıldı ✓")

print("\n--- 2. Bazadakı Zəifliklərin Oxunması ---")
vulns = session.query(Vulnerability).all()
for v in vulns:
    print(f"Tapşırıq: {v.title}, CVSS: {v.cvss_score}, Kateqoriya ID: {v.category_id}")

session.close()