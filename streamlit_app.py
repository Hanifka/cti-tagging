import streamlit as st
import requests
import pandas as pd
import time

# Konfigurasi Halaman
# Konfigurasi Halaman
st.set_page_config(page_title="AbuseIPDB Bulk Checker", page_icon="🛡️")

# Custom CSS untuk Footer
st.markdown("""
    <style>
    .footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        background-color: transparent;
        color: grey;
        text-align: center;
        padding: 10px;
        font-size: 12px;
    }
    </style>
    <div class="footer">
        <p>© 2026 Hanifka. Developed for Security Operations.</p>
    </div>
    """, unsafe_allow_html=True)

st.title("🛡️ AbuseIPDB Bulk Checker")
st.markdown("Masukkan daftar IP (satu per baris) untuk mengecek skor reputasi secara massal.")

# Sidebar untuk API Key
with st.sidebar:
    st.header("Konfigurasi")
    api_key = st.text_input("AbuseIPDB API Key", type="password")
    st.info("Dapatkan API Key di [AbuseIPDB](https://www.abuseipdb.com/account/api)")
    max_age = st.slider("Max Age (Hari)", 30, 365, 90)

# Input Area
raw_ips = st.text_area("Paste Daftar IP di sini:", height=200, placeholder="1.1.1.1\n8.8.8.8")

if st.button("Mulai Scanning"):
    if not api_key:
        st.error("Silakan masukkan API Key terlebih dahulu!")
    elif not raw_ips.strip():
        st.warning("Daftar IP kosong.")
    else:
        # Parsing IP
        ip_list = [ip.strip() for ip in raw_ips.splitlines() if ip.strip()]
        total_ips = len(ip_list)
        
        results = []
        progress_bar = st.progress(0)
        status_text = st.empty()

        ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Key': api_key, 'Accept': 'application/json'}

        for i, ip in enumerate(ip_list):
            status_text.text(f"Memproses {i+1}/{total_ips}: {ip}")
            
            params = {'ipAddress': ip, 'maxAgeInDays': str(max_age)}
            
            try:
                response = requests.get(ABUSEIPDB_API_URL, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json().get('data')
                    results.append({
                        "IP Address": data.get('ipAddress'),
                        "Confidence Score": f"{data.get('abuseConfidenceScore')}%",
                        "Country": data.get('countryCode'),
                        "ISP": data.get('isp'),
                        "Domain": data.get('domain'),
                        "Total Reports": data.get('totalReports')
                    })
                elif response.status_code == 429:
                    st.error("Rate limit tercapai! Gunakan akun premium atau tunggu beberapa saat.")
                    break
                else:
                    st.warning(f"Gagal mengecek {ip}: Status {response.status_code}")
            
            except Exception as e:
                st.error(f"Error pada {ip}: {str(e)}")

            # Update Progress
            progress_bar.progress((i + 1) / total_ips)
            time.sleep(0.5) # Delay kecil untuk stabilitas UI

        # Tampilkan Hasil
        if results:
            df = pd.DataFrame(results)
            st.success(f"Selesai! Berhasil memproses {len(results)} IP.")
            
            # Tampilkan Tabel
            st.dataframe(df, use_container_width=True)

            # Fitur Download
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download Hasil sebagai CSV",
                data=csv,
                file_name="abuseipdb_results.csv",
                mime="text/csv",
            )
