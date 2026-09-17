import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker, selectinload
from cyber_setup import VulnCategory, Vulnerability, AuditLog, DATABASE_URL

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

print("--- 1. Aggregate Sorğular (SUM, AVG) ---")
# Ümumi test sayı və orta CVSS balı
total_tests = session.query(func.sum(AuditLog.tested_count)).scalar()
avg_cvss = session.query(func.avg(Vulnerability.cvss_score)).scalar()

print(f"Ümumi aparılan test sayı: {total_tests}")
print(f"Orta CVSS təhlükə balı: {round(avg_cvss, 2) if avg_cvss else 0}")

print("\n--- 2. JOIN Sorğusu (Kateqoriyalara görə zəiflik sayı) ---")
results = session.query(
    VulnCategory.name, 
    func.count(Vulnerability.id)
).join(Vulnerability).group_by(VulnCategory.name).all()

for cat_name, count in results:
    print(f"Kateqoriya: {cat_name} | Zəiflik sayı: {count}")

print("\n--- 3. N+1 Problemi və selectinload ilə həlli ---")
# selectinload() hər kateqoriya üçün tək-tək SQL sorğu getməsinin qarşısını alır
categories = session.query(VulnCategory).options(selectinload(VulnCategory.vulnerabilities)).all()

for cat in categories:
    print(f"\nKateqoriya: {cat.name}")
    for v in cat.vulnerabilities:
        print(f"   -> Tapşırıq: {v.title} (CVSS: {v.cvss_score})")

session.close()
