import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from cyber_setup import Vulnerability, AuditLog, DATABASE_URL

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

print("--- Ssenari 1: Uğurlu Tranzaksiya (Commit) ---")
try:
    # Kriptoqrafiya zəifliyini tapırıq
    crypto_vuln = session.query(Vulnerability).filter_by(title="Weak RSA Key Generation").first()
    if crypto_vuln:
        log = AuditLog(vulnerability=crypto_vuln, tested_count=2)
        session.add(log)
        session.commit()
        print("Uğurlu audit bazaya yazıldı və commit olundu ✓")
except Exception as e:
    session.rollback()
    print(f"Xəta baş verdi, rollback olundu: {e}")

print("\n--- Ssenari 2: Uğursuz Tranzaksiya və Rollback ---")
try:
    # Qəsdən mövcud olmayan zəiflik ID-si (8888) ilə audit log əlavə etməyə çalışırıq
    bad_log = AuditLog(vulnerability_id=8888, tested_count=1)
    session.add(bad_log)
    
    # Burada Foreign Key xətası baş verəcək
    session.commit()
    print("Bu sətrə heç vaxt çatmamalıdır.")
except Exception as e:
    session.rollback()
    print(f"Xəta aşkarlandı! Tranzaksiya ləğv edildi (Rollback işə düşdü) ✓")
    print(f"Xəta detalları: {e}")

session.close()