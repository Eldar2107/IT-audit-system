import streamlit as st
import pandas as pd
from sqlalchemy import func
from cyber_setup import (
    VulnCategory, 
    Vulnerability, 
    AuditLog, 
    Session, 
    setup_cyber_db,
    DATABASE_URL
)

# Səhifə konfiqurasiyası
st.set_page_config(
    page_title="CyberSecurity Audit Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Bazanı və cədvəlləri hazır vəziyyətə gətiririk
setup_cyber_db()

session = Session()

st.title("🛡️ Kiberbəhlükəsizlik Zəiflikləri və Audit İdarəetmə Paneli")
st.markdown("Kiber zəifliklərin qeydiyyatı, CVSS risk təhlili və audit testlərinin monitorinq sistemi.")

st.sidebar.header("Naviqasiya")
menu = st.sidebar.radio("Bölməni seçin:", ["📋 Zəifliklər Siyahısı", "➕ Yeni Zəiflik Əlavə Et", "📊 Audit Analitikası"])

# Baza növünü göstərən bildiriş
db_type = "PostgreSQL" if "postgresql" in str(DATABASE_URL) else "SQLite (Cloud Demo Rejimi)"
st.sidebar.caption(f"Verilənlər Bazası: **{db_type}**")

if menu == "📋 Zəifliklər Siyahısı":
    st.subheader("📋 Bazadakı Mövcud Zəifliklər")
    
    vulns = session.query(Vulnerability).all()
    data = []
    for v in vulns:
        # Risk dərəcəsi təyini
        risk_level = "Kritik 🔴" if v.cvss_score >= 9.0 else ("Yüksək 🟠" if v.cvss_score >= 7.0 else "Orta 🟡")
        data.append({
            "ID": v.id,
            "Başlıq": v.title,
            "CVSS Balı": v.cvss_score,
            "Risk Dərəcəsi": risk_level,
            "Kateqoriya": v.category.name if v.category else "Digər"
        })
    
    if data:
        df = pd.DataFrame(data)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("Hələ ki heç bir zəiflik qeydə alınmayıb.")

elif menu == "➕ Yeni Zəiflik Əlavə Et":
    st.subheader("➕ Yeni Zəiflik Qeydiyyatı")
    
    categories = session.query(VulnCategory).all()
    cat_dict = {c.name: c.id for c in categories}
    
    with st.form("vuln_form", clear_on_submit=True):
        title = st.text_input("Zəiflik Başlığı (Məsələn: Broken Access Control)")
        cvss = st.slider("CVSS Təhlükə Balı", min_value=0.0, max_value=10.0, value=5.0, step=0.1)
        selected_cat_name = st.selectbox("Kateqoriya", list(cat_dict.keys()) if cat_dict else ["Ümumi"])
        
        submitted = st.form_submit_button("Bazaya Əlavə Et")
        
        if submitted:
            if not title.strip():
                st.error("Zəhmət olmasa zəiflik başlığını qeyd edin!")
            else:
                cat_id = cat_dict.get(selected_cat_name)
                new_vuln = Vulnerability(
                    title=title.strip(), 
                    cvss_score=cvss, 
                    category_id=cat_id
                )
                session.add(new_vuln)
                session.commit()
                st.success(f"'{title}' uğurla əlavə olundu! 🎉")
                st.rerun()

elif menu == "📊 Audit Analitikası":
    st.subheader("📊 Audit Hesabatları və Təhlükəsizlik Statistikası")
    
    total_tests = session.query(func.sum(AuditLog.tested_count)).scalar() or 0
    avg_cvss = session.query(func.avg(Vulnerability.cvss_score)).scalar() or 0
    total_vulns = session.query(Vulnerability).count()
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Ümumi Zəiflik Sayı", total_vulns)
    col2.metric("Ümumi Audit Test Sayı", total_tests)
    col3.metric("Orta CVSS Balı", round(avg_cvss, 2))
    
    st.markdown("---")
    st.subheader("📜 Aparılan Audit Testlərinin Tarixçəsi")
    
    logs = session.query(AuditLog).all()
    log_data = []
    for l in logs:
        log_data.append({
            "Log ID": l.id,
            "Zəiflik": l.vulnerability.title if l.vulnerability else "Bilinmir",
            "Test Sayı": l.tested_count,
            "Tarix": l.scanned_at.strftime("%Y-%m-%d %H:%M") if l.scanned_at else "—"
        })
    
    if log_data:
        df_logs = pd.DataFrame(log_data)
        st.dataframe(df_logs, use_container_width=True)
    else:
        st.info("Hələ heç bir audit logu qeydə alınmayıb.")

session.close()