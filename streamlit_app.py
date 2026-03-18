import streamlit as st
import requests
import pandas as pd
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="SOC IP Reputation Checker",
    page_icon="🛡️",
    layout="wide"
)

# ============================================================
# TITLE
# ============================================================
st.title("🛡️ SOC IP Reputation Checker")
st.markdown("Pilih sumber intel: **OpenCTI** atau **AbuseIPDB**")

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.header("🔐 Configuration")

    use_opencti = st.checkbox("Use OpenCTI", value=False)
    use_abuseipdb = st.checkbox("Use AbuseIPDB", value=False)

    st.divider()

    opencti_url = None
    opencti_token = None

    if use_opencti:
        st.subheader("OpenCTI")
        opencti_url = st.text_input(
            "OpenCTI URL",
            placeholder="https://opencti.your-org.local"
        )
        opencti_token = st.text_input(
            "OpenCTI Token",
            type="password"
        )

    if use_abuseipdb:
        st.subheader("AbuseIPDB")
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
# OPENCTI LOOKUP (HTTP / CURL STYLE)
# ============================================================
def opencti_lookup(ip):
    result = {
        "cti_score": None,
        "cti_label": None,
        "cti_status": "NOT_FOUND"
    }

    try:
        url = f"{opencti_url}/graphql"

        headers = {
            "Authorization": f"Bearer {opencti_token}",
            "Content-Type": "application/json"
        }

        payload = {
            "query": QUERY_REPUTATION,
            "variables": {
                "filters": {
                    "mode": "and",
                    "filters": [
                        {"key": "value", "values": [ip], "operator": "eq"},
                        {"key": "entity_type", "values": ["IPv4-Addr"], "operator": "eq"}
                    ],
                    "filterGroups": []
                }
            }
        }

        r = requests.post(url, json=payload, headers=headers, verify=False, timeout=10)

        if r.status_code != 200:
            result["cti_status"] = "ERROR"
            result["cti_label"] = f"HTTP {r.status_code}"
            return result

        data = r.json()
        edges = data.get("data", {}).get("stixCyberObservables", {}).get("edges", [])

        if not edges:
            return result

        node = edges[0]["node"]
        score = node.get("x_opencti_score") or 0
        label = node.get("objectLabel", {}).get("value")

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
# ABUSEIPDB LOOKUP
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

    ip_list = [i.strip() for i in raw_ips.splitlines() if i.strip()]
    rows = []

    # Validate OpenCTI config
    if use_opencti:
        if not opencti_url or not opencti_token:
            st.error("OpenCTI URL & Token required")
            st.stop()

    progress = st.progress(0)
    status = st.empty()

    for i, ip in enumerate(ip_list):
        status.text(f"Processing {i+1}/{len(ip_list)} → {ip}")

        row = {"ip": ip}

        # OpenCTI
        if use_opencti:
            row.update(opencti_lookup(ip))
        else:
            row.update({
                "cti_score": None,
                "cti_label": None,
                "cti_status": "DISABLED"
            })

        # AbuseIPDB
        if use_abuseipdb:
            row.update(abuseipdb_lookup(ip))
        else:
            row.update({
                "abuse_score": None,
                "country": None,
                "isp": None,
                "total_reports": None
            })

        rows.append(row)
        progress.progress((i + 1) / len(ip_list))
        time.sleep(0.1)

    df = pd.DataFrame(rows)

    st.success(f"✅ Completed: {len(df)} IP processed")
    st.dataframe(df, use_container_width=True)

    st.download_button(
        "📥 Download CSV",
        df.to_csv(index=False).encode("utf-8"),
        "ip_reputation.csv",
        "text/csv"
    )
