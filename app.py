import streamlit as st
import requests
import json
import os

DEFAULT_URL = "http://127.0.0.1:8000/predict"
API_URL = os.environ.get("API_URL", DEFAULT_URL)

st.set_page_config(page_title="NIDS Detector", layout="wide")
st.title("🛡️ Network Intrusion Detection System")
st.markdown("Predict whether network traffic is **Benign** or **Malicious**.")

def get_prediction(payload):
    try:
        with st.spinner("Analyzing traffic..."):
            response = requests.post(API_URL, json=payload)
            if response.status_code == 200:
                result = response.json().get('prediction', 'Unknown')
                if result.lower() == "benign":
                    st.success(f"Result: {result}")
                else:
                    st.error(f"Alert: {result} Detected!")
            else:
                st.error(f"API Error: {response.status_code} - {response.text}")
    except Exception as e:
        st.error(f"Connection Error: {e}")

tab1, tab2 = st.tabs(["📝 Manual Input", "💻 JSON Payload"])

with tab1:
    st.header("Enter Network Flow Details")
    with st.form("manual_form"):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            dst_port = st.number_input("Dst Port", value=80)
            protocol = st.number_input("Protocol (6=TCP, 17=UDP)", value=6)
            flow_duration = st.number_input("Flow Duration", value=1)
            tot_fwd_pkts = st.number_input("Tot Fwd Pkts", value=1)
            
        with col2:
            fwd_pkt_len_max = st.number_input("Fwd Pkt Len Max", value=0)
            flow_byts_s = st.number_input("Flow Byts/s", value=0.0)
            flow_pkts_s = st.number_input("Flow Pkts/s", value=0.0)
            init_fwd_win_byts = st.number_input("Init Fwd Win Byts", value=0)

        with col3:
            syn_flag = st.number_input("SYN Flag Cnt", value=0)
            ack_flag = st.number_input("ACK Flag Cnt", value=0)
            pst_flag = st.number_input("PSH Flag Cnt", value=0)
            rst_flag = st.number_input("RST Flag Cnt", value=0)

        st.info("Note: For brevity, only key features are shown. Ensure all 70+ features are mapped in your final dictionary.")
        
        submit_manual = st.form_submit_button("Analyze Traffic")
        
        if submit_manual:
            payload = {
                "Dst Port": dst_port, "Protocol": protocol, "Flow Duration": flow_duration,
                "Tot Fwd Pkts": tot_fwd_pkts, "Fwd Pkt Len Max": fwd_pkt_len_max,
            }
            get_prediction(payload)

with tab2:
    st.header("Raw JSON Input")
    st.markdown("Paste the JSON object for the network flow below:")
    
    default_json = {
        "Dst Port": 80, "Protocol": 6, "Flow Duration": 50000, 
        "Tot Fwd Pkts": 5, "Tot Bwd Pkts": 3, "TotLen Fwd Pkts": 100
    }
    
    json_input = st.text_area("JSON Payload", value=json.dumps(default_json, indent=4), height=400)
    
    if st.button("Send JSON Request"):
        try:
            payload = json.loads(json_input)
            get_prediction(payload)
        except json.JSONDecodeError:
            st.error("Invalid JSON format. Please check your syntax.")