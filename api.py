import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from cyber_setup import VulnCategory, Vulnerability, DATABASE_URL

load_dotenv()
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

app = FastAPI(title="Cybersecurity Vulnerability API", version="1.0")

# Pydantic sxemi (Gələn məlumatların doğrulanması üçün)
class VulnCreate(BaseModel):
    title: str
    cvss_score: float
    category_id: int

@app.get("/")
def home():
    return {"message": "Kiberbəhlükəsizlik Zəiflikləri API-nə xoş gəlmisiniz! 🚀"}

@app.get("/vulnerabilities")
def get_vulnerabilities():
    session = Session()
    vulns = session.query(Vulnerability).all()
    result = []
    for v in vulns:
        result.append({
            "id": v.id,
            "title": v.title,
            "cvss_score": v.cvss_score,
            "category_id": v.category_id
        })
    session.close()
    return result

@app.post("/vulnerabilities")
def create_vulnerability(vuln: VulnCreate):
    session = Session()
    try:
        new_vuln = Vulnerability(
            title=vuln.title,
            cvss_score=vuln.cvss_score,
            category_id=vuln.category_id
        )
        session.add(new_vuln)
        session.commit()
        session.refresh(new_vuln)
        session.close()
        return {"status": "success", "message": f"'{vuln.title}' uğurla əlavə olundu!", "id": new_vuln.id}
    except Exception as e:
        session.rollback()
        session.close()
        raise HTTPException(status_code=400, detail=str(e))