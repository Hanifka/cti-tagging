import streamlit as st
import requests
import pandas as pd
import urllib3
import time
from pycti import OpenCTIApiClient

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="SOC IP Reputation Checker",
    page_icon="🛡️",
    layout="wide"
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# FOOTER
# ============================================================
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
<p>© 2026 Hanifka — SOC Automation</p>
</div>
""", unsafe_allow_html=True)

# ============================================================
# TITLE
# ============================================================
st.title("🛡️ SOC IP Reputation Checker")
st.markdown("Pilih sumber intel: **OpenCTI**, **AbuseIPDB**, atau **keduanya**")

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.header("🔐 Configuration")

    use_opencti = st.checkbox("Use OpenCTI", value=True)
    use_abuseipdb = st.checkbox("Use AbuseIPDB", value=False)

    st.divider()

    if use_opencti:
        opencti_url = st.text_input(
            "OpenCTI URL",
            "https://cti-socfs.visionet.co.id"
        )
        opencti_token = st.text_input(
            "OpenCTI Token",
            type="password"
        )

    if use_abuseipdb:
        abuse_api_key = st.text_input(
            "AbuseIPDB API Key",
            type="password"
        )
        max_age = st.slider("Max Age (days)", 30, 365, 90)

# ============================================================
# INPUT
# ============================================================
raw_ips = st.text_area(
    "📥 Paste IP list (one per line)",
    height=220,
    placeholder="1.1.1.1\n8.8.8.8"
)

# ============================================================
# OPENCTI QUERY
# ============================================================
QUERY_REPUTATION = """
query GetIPReputation($filters: FilterGroup) {
  stixCyberObservables(filters: $filters) {
    edges {
      node {
        observable_value
        x_opencti_score
        objectLabel {
          value
        }
      }
    }
  }
}
"""

# ============================================================
# OPENCTI LOOKUP (SAFE DEFAULT)
# ============================================================
def opencti_lookup(client, ip):
    result = {
        "cti_score": None,
        "cti_label": None,
        "cti_status": "NOT_FOUND"
    }

    variables = {
        "filters": {
            "mode": "and",
            "filters": [
                {"key": "value", "values": [ip], "operator": "eq"},
                {"key": "entity_type", "values": ["IPv4-Addr"], "operator": "eq"}
            ],
            "filterGroups": []
        }
    }

    try:
        r = client.query(QUERY_REPUTATION, variables)
        edges = r["data"]["stixCyberObservables"]["edges"]

        if not edges:
            return result

        node = edges[0]["node"]
        score = node.get("x_opencti_score") or 0
        label = node["objectLabel"]["value"] if node.get("objectLabel") else None

        result["cti_score"] = score
        result["cti_label"] = label
        result["cti_status"] = (
            "CLEAN" if score < 40
            else "SUSPICIOUS" if score < 80
            else "MALICIOUS"
        )
        return result

    except Exception as e:
        result["cti_status"] = "ERROR"
        result["cti_label"] = str(e)
        return result

# ============================================================
# ABUSEIPDB LOOKUP (SAFE DEFAULT)
# ============================================================
def abuseipdb_lookup(ip):
    result = {
        "abuse_score": None,
        "country": None,
        "isp": None,
        "total_reports": None
    }

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": abuse_api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": str(max_age)}

        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code != 200:
            return result

        d = r.json()["data"]
        result.update({
            "abuse_score": d.get("abuseConfidenceScore"),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "total_reports": d.get("totalReports")
        })
        return result

    except:
        return result

# ============================================================
# MAIN
# ============================================================
if st.button("🚀 Start Scan"):
    if not raw_ips.strip():
        st.warning("IP list is empty")
        st.stop()

    if use_opencti and not opencti_token:
        st.error("OpenCTI token required")
        st.stop()

    if use_abuseipdb and not abuse_api_key:
        st.error("AbuseIPDB API key required")
        st.stop()

    ip_list = [i.strip() for i in raw_ips.splitlines() if i.strip()]
    rows = []

    if use_opencti:
        client = OpenCTIApiClient(
            opencti_url,
            opencti_token,
            ssl_verify=False
        )

    progress = st.progress(0)
    status = st.empty()

    for i, ip in enumerate(ip_list):
        status.text(f"Processing {i+1}/{len(ip_list)} → {ip}")
        row = {"ip": ip}

        if use_opencti:
            row.update(opencti_lookup(client, ip))
        else:
            row.update({
                "cti_score": None,
                "cti_label": None,
                "cti_status": "DISABLED"
            })

        if use_abuseipdb:
            row.update(abuseipdb_lookup(ip_
