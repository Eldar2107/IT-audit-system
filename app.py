import streamlit as st
import pandas as pd
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from cyber_setup import VulnCategory, Vulnerability, AuditLog, DATABASE_URL

# Verilənlər bazası bağlantısı
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

st.title("🛡️ Kiberbəhlükəsizlik Zəiflikləri və Audit İdarəetmə Paneli")
st.sidebar.header("Naviqasiya")

# Sidebar menyusu
menu = st.sidebar.radio("Seçim et:", ["Zəifliklər", "Yeni Zəiflik Əlavə Et", "Audit Logları və Analitika"])

if menu == "Zəifliklər":
    st.subheader("📋 Bazadakı Mövcud Zəifliklər")
    
    # Bazadan məlumatları çəkirik
    vulns = session.query(Vulnerability).all()
    data = []
    for v in vulns:
        data.append({
            "ID": v.id,
            "Başlıq": v.title,
            "CVSS Ballı": v.cvss_score,
            "Kateqoriya": v.category.name if v.category else "Digər"
        })
    
    df = pd.DataFrame(data)
    st.dataframe(df, use_container_width=True)

elif menu == "Yeni Zəiflik Əlavə Et":
    st.subheader("➕ Yeni Zəiflik Qeydiyyatı")
    
    with st.form("vuln_form"):
        title = st.text_input("Zəiflik Başlığı (Məsələn: XSS Vulnerability)")
        cvss = st.number_input("CVSS Təhlükə Ballı", min_value=0.0, max_value=10.0, value=5.0)
        
        # Kateqoriyaları seçmək üçün bazadan çəkirik
        categories = session.query(VulnCategory).all()
        cat_dict = {c.name: c.id for c in categories}
        selected_cat_name = st.selectbox("Kateqoriya", list(cat_dict.keys()))
        
        submitted = st.form_submit_button("Bazaya Əlavə Et")
        
        if submitted and title:
            new_vuln = Vulnerability(
                title=title, 
                cvss_score=cvss, 
                category_id=cat_dict[selected_cat_name]
            )
            session.add(new_vuln)
            session.commit()
            st.success(f"'{title}' uğurla əlavə olundu! 🎉")

elif menu == "Audit Logları və Analitika":
    st.subheader("📊 Audit Hesabatları və Test Sayları")
    
    total_tests = session.query(func.sum(AuditLog.tested_count)).scalar() or 0
    avg_cvss = session.query(func.avg(Vulnerability.cvss_score)).scalar() or 0
    
    col1, col2 = st.columns(2)
    col1.metric("Ümumi Test Sayı", total_tests)
    col2.metric("Orta CVSS Ballı", round(avg_cvss, 2))
    
    st.markdown("---")
    st.subheader("📜 Aparılan Auditlərin Siyahısı")
    
    logs = session.query(AuditLog).all()
    log_data = []
    for l in logs:
        log_data.append({
            "Log ID": l.id,
            "Zəiflik": l.vulnerability.title,
            "Test Sayı": l.tested_count,
            "Tarix": l.scanned_at
        })
    
    if log_data:
        df_logs = pd.DataFrame(log_data)
        st.dataframe(df_logs, use_container_width=True)
    else:
        st.info("Hələ heç bir audit logu qeydə alınmayıb.")

session.close()