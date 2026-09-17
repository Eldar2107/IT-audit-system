# 🛡️ CyberSecurity Vulnerability & Audit Management System
# 🛡️ Kiberbəhlükəsizlik Zəiflikləri və Audit İdarəetmə Sistemi

[English](#english) | [Azərbaycan dilində](#azerbaycan-dilində)

---

<a name="english"></a>
## 🇬🇧 English

A modular backend architecture and management system built with **Python**, **SQLAlchemy ORM**, and **PostgreSQL**, designed to track cybersecurity vulnerabilities, CVSS risk scores, and audit test logs. The project also features an interactive web dashboard built with **Streamlit** and a REST API powered by **FastAPI**.

### 🚀 Tech Stack
* **Language:** Python
* **Database & ORM:** PostgreSQL, SQLAlchemy, Psycopg2
* **Web Frameworks:** Streamlit (Dashboard), FastAPI (REST API)
* **Configuration:** python-dotenv

### 📂 Project Structure
* `cyber_setup.py`: Database schema and model definitions (`VulnCategory`, `Vulnerability`, `AuditLog`).
* `01_cyber_models.py`: Data insertion and CRUD operations.
* `02_cyber_relations.py`: ORM relationship mapping and foreign key interactions.
* `03_cyber_transaction.py`: ACID compliance verification (Commit & Rollback handling).
* `04_cyber_analysis.py`: Aggregate queries (`SUM`, `AVG`), `JOIN` operations, and N+1 performance optimization using `selectinload`.
* `app.py`: Interactive Streamlit web interface.
* `api.py`: FastAPI REST endpoints (`GET`, `POST`).

---

<a name="azerbaycan-dilində"></a>
## 🇦🇿 Azərbaycan dilində

**Python**, **SQLAlchemy ORM** və **PostgreSQL** istifadə edərək sıfırdan qurulmuş; kiberbəhlükəsizlik zəifliklərini, CVSS risk ballarını və audit test qeydlərini idarə edən modul arxitekturalı sistem. Layihə həmçinin **Streamlit** ilə interaktiv veb panelə və **FastAPI** üzərindən işləyən REST API-yə malikdir.

### 🚀 Texnologiya Yığını
* **Dil:** Python
* **Baza və ORM:** PostgreSQL, SQLAlchemy, Psycopg2
* **Veb Çərçivələr:** Streamlit (İdarəetmə paneli), FastAPI (REST API)
* **Konfiqurasiya:** python-dotenv

### 📂 Layihənin Strukturu
* `cyber_setup.py`: Verilənlər bazası sxemi və modellər (`VulnCategory`, `Vulnerability`, `AuditLog`).
* `01_cyber_models.py`: Məlumatların əlavə edilməsi və əsas CRUD əməliyyatları.
* `02_cyber_relations.py`: Obyektlər arası əlaqə zəncirləri və xarici açar (Foreign Key) qarşılıqlı təsiri.
* `03_cyber_transaction.py`: ACID uyğunluğunun yoxlanılması (`Commit` və `Rollback` mexanizmi).
* `04_cyber_analysis.py`: Aqreqat sorğular (`SUM`, `AVG`), `JOIN` əməliyyatları və `selectinload` ilə N+1 optimizasiyası.
* `app.py`: Streamlit interaktiv veb interfeysi.
* `api.py`: FastAPI REST xidməti (`GET`, `POST` sorğuları).

---