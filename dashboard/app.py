import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import os, time

LOG_FILE = "logs/alerts.csv"

st.set_page_config(
    page_title="TCP Attack Detector",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ TCP Attack Detection Dashboard")
st.caption(f"Last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def load_data():
    if not os.path.isfile(LOG_FILE):
        return pd.DataFrame(columns=
            ['timestamp','attack_type','severity','src_ip','dst_ip','port','detail'])
    return pd.read_csv(LOG_FILE, parse_dates=['timestamp'])

df = load_data()

# ── Top metrics ────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
col1.metric('Total Alerts', len(df))
col2.metric('Unique Attackers', df['src_ip'].nunique() if len(df) else 0)
col3.metric('High Severity', len(df[df['severity']=='HIGH']) if len(df) else 0)
col4.metric('Attack Types', df['attack_type'].nunique() if len(df) else 0)

st.divider()

if len(df) == 0:
    st.info("No alerts yet. Start the sniffer and run some attacks.")
else:
    # ── Charts ──────────────────────────────────────────
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Attack Type Distribution")
        fig = px.pie(df, names='attack_type', title='',
                     color_discrete_sequence=px.colors.qualitative.Set2)
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.subheader("Alerts Over Time")
        df['minute'] = pd.to_datetime(df['timestamp']).dt.floor('1min')
        timeline = df.groupby('minute').size().reset_index(name='count')
        fig2 = px.line(timeline, x='minute', y='count',
                       labels={"minute": "Time", "count": "Alerts"})
        st.plotly_chart(fig2, use_container_width=True)

    # ── Top attacker IPs ────────────────────────────────
    st.subheader("Top Attacker IPs")
    top_ips = df['src_ip'].value_counts().head(10).reset_index()
    top_ips.columns = ['IP Address', 'Alert Count']
    fig3 = px.bar(top_ips, x='IP Address', y='Alert Count',
                  color='Alert Count', color_continuous_scale='Reds')
    st.plotly_chart(fig3, use_container_width=True)

    # ── Severity breakdown ──────────────────────────────
    st.subheader("Severity Breakdown")
    sev = df['severity'].value_counts().reset_index()
    sev.columns = ['Severity', 'Count']
    colors = {'HIGH': '#e74c3c', 'MEDIUM': '#f39c12', 'LOW': '#2ecc71'}
    fig4 = px.bar(sev, x='Severity', y='Count',
                  color='Severity',
                  color_discrete_map=colors)
    st.plotly_chart(fig4, use_container_width=True)

    # ── Raw alert log ────────────────────────────────────
    st.subheader("Alert Log")
    st.dataframe(df.sort_values('timestamp', ascending=False).head(100),
                 use_container_width=True)

# Auto-refresh every 5 seconds
st.markdown('---')
if st.button('Refresh Now'):
    st.rerun()
time.sleep(5)
st.rerun()
