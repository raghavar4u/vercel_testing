import streamlit as st
import pandas as pd
import numpy as np
import datetime
import altair as alt # Import altair for charting

def data_ingestion_monitoring():
    st.header("Data Ingestion Monitoring")
    st.write("Monitor the status and performance of data ingestion pipelines.")
    st.info("Placeholder for data ingestion metrics, logs, and alerts.")

    # st.markdown("""
    # - **Ingestion Rate:** Current rate of data intake.
    # - **Error Rate:** Percentage of failed ingestion attempts.
    # - **Latency:** Time taken for data to be ingested.
    # - **Source Status:** Connectivity and health of data sources.
    # - **Recent Ingestion Jobs:** Table showing recent jobs, status, and duration.
    # """)

    # Create dummy data for various log counts over time
    time_series_data = pd.DataFrame({
        "Date": pd.to_datetime([datetime.date.today() - datetime.timedelta(days=i) for i in range(7)][::-1]),
        "VPN Counts": np.random.randint(1000, 5000, 7),
        "AD-DNS Counts": np.random.randint(5000, 15000, 7),
        "Domain Controller Logs Count": np.random.randint(2000, 8000, 7),
        "Zeek Logs Ingestion Counts": np.random.randint(1500, 6000, 7)
    })
    time_series_data = time_series_data.set_index("Date")

    # Display current counts using columns for a "tag" like appearance
    st.markdown("#### Current Ingestion Counts")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="VPN Counts", value=f"{time_series_data['VPN Counts'].iloc[-1]:,}")
    with col2:
        st.metric(label="AD-DNS Counts", value=f"{time_series_data['AD-DNS Counts'].iloc[-1]:,}")
    with col3:
        st.metric(label="Domain Controller Logs", value=f"{time_series_data['Domain Controller Logs Count'].iloc[-1]:,}")
    with col4:
        st.metric(label="Zeek Logs", value=f"{time_series_data['Zeek Logs Ingestion Counts'].iloc[-1]:,}")

    st.markdown("#### Ingestion Trends Over Time")
    st.line_chart(time_series_data)
    
    # Display general ingestion metrics
    st.line_chart({"Ingestion Rate": [100, 120, 110, 130, 125], "Error Rate": [5, 3, 4, 2, 1]})

    st.subheader("Specific Log Ingestion Counts")


def infra_monitoring():
    st.header("Infrastructure Monitoring")
    st.write("Overview of the underlying infrastructure health and performance.")
    st.info("Placeholder for server metrics, network status, and resource utilization.")

    # Create dummy data for time-based metrics
    time_range = 7 # days
    dates = [datetime.date.today() - datetime.timedelta(days=i) for i in range(time_range)][::-1]

    # CPU and Memory Usage over time
    st.subheader("Server Resource Utilization Over Time")
    server_metrics_data = pd.DataFrame({
        "Date": pd.to_datetime(dates),
        "CPU Usage (%)": np.random.randint(40, 90, time_range),
        "Memory Usage (%)": np.random.randint(30, 80, time_range)
    })
    server_metrics_data = server_metrics_data.set_index("Date")
    st.line_chart(server_metrics_data)

    # Kafka related information
    st.subheader("Kafka Monitoring")
    # st.markdown("""
    # - **Messages Pushed:** Number of messages successfully sent to Kafka topics.
    # - **Consumer Lag:** Delay between the latest message and the last consumed message.
    # - **Broker Health:** Status of Kafka brokers.
    # """)
    kafka_data = pd.DataFrame({
        "Date": pd.to_datetime(dates),
        "Messages Pushed (per min)": np.random.randint(10000, 50000, time_range),
        "Consumer Lag (seconds)": np.random.randint(1, 10, time_range)
    })
    kafka_data = kafka_data.set_index("Date")
    st.line_chart(kafka_data)

    col_k1, col_k2 = st.columns(2)
    with col_k1:
        st.metric(label="Current Messages Pushed (last min)", value=f"{kafka_data['Messages Pushed (per min)'].iloc[-1]:,}")
    with col_k2:
        st.metric(label="Current Consumer Lag (seconds)", value=f"{kafka_data['Consumer Lag (seconds)'].iloc[-1]}s")


    # Database related memory and usage
    st.subheader("Database Monitoring")
    st.markdown("""
    - **DB Memory Usage:** Memory consumed by database processes.
    - **Active Connections:** Number of active database connections.
    - **Query Performance:** Average query execution time.
    """)
    db_data = pd.DataFrame({
        "Date": pd.to_datetime(dates),
        "DB Memory Usage (GB)": np.random.uniform(2, 10, time_range).round(1),
        "Active Connections": np.random.randint(50, 500, time_range)
    })
    db_data = db_data.set_index("Date")
    st.line_chart(db_data)

    col_d1, col_d2 = st.columns(2)
    with col_d1:
        st.metric(label="Current DB Memory Usage", value=f"{db_data['DB Memory Usage (GB)'].iloc[-1]:.1f} GB")
    with col_d2:
        st.metric(label="Current Active Connections", value=f"{db_data['Active Connections'].iloc[-1]}")


def indexed_data_management():
    st.header("Indexed Data Management")
    st.write("Manage and monitor the status of indexed data.")
    st.info("Placeholder for index health, data volume, and search performance.")
    # st.markdown("""
    # - **Index Size:** Total volume of indexed data.
    # - **Indexing Lag:** Delay between data ingestion and indexing.
    # - **Search Latency:** Time taken for search queries to return results.
    # - **Index Health:** Status of individual indices (e.g., green, yellow, red).
    # - **Data Retention Policies:** Information on data lifecycle management.
    # """)
    st.metric(label="Total Indexed Documents", value="1.2 Billion")
    st.metric(label="Indexing Lag (minutes)", value="5")

    st.subheader("Structured Parsed Data Lookup")

    # Dummy data for different log types
    def generate_vpn_data(num_rows=5):
        data = {
            "Timestamp": [datetime.datetime.now() - datetime.timedelta(minutes=i) for i in range(num_rows)],
            "User": [f"user_{np.random.randint(1, 20)}" for _ in range(num_rows)],
            "Source_IP": [f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}" for _ in range(num_rows)],
            "Destination_IP": [f"10.0.{np.random.randint(1, 10)}.{np.random.randint(1, 255)}" for _ in range(num_rows)],
            "Duration_Sec": np.random.randint(60, 3600, num_rows),
            "Status": np.random.choice(["Connected", "Disconnected", "Failed"], num_rows)
        }
        return pd.DataFrame(data)

    def generate_domain_controller_data(num_rows=5):
        data = {
            "Timestamp": [datetime.datetime.now() - datetime.timedelta(minutes=i) for i in range(num_rows)],
            "Event_ID": np.random.choice([4624, 4625, 4768, 4769], num_rows),
            "Account_Name": [f"account_{np.random.randint(1, 50)}" for _ in range(num_rows)],
            "Logon_Type": np.random.choice(["Interactive", "Network", "Service"], num_rows),
            "Source_Workstation": [f"WS{np.random.randint(100, 999)}" for _ in range(num_rows)],
            "Status": np.random.choice(["Success", "Failure"], num_rows)
        }
        return pd.DataFrame(data)

    def generate_zeek_data(num_rows=5):
        data = {
            "Timestamp": [datetime.datetime.now() - datetime.timedelta(minutes=i) for i in range(num_rows)],
            "UID": [f"C{np.random.randint(10000, 99999)}" for _ in range(num_rows)],
            "ID_Orig_H": [f"172.16.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}" for _ in range(num_rows)],
            "ID_Resp_H": [f"8.8.8.{np.random.randint(1, 255)}" for _ in range(num_rows)],
            "Service": np.random.choice(["dns", "http", "ssl", "ssh"], num_rows),
            "Duration": np.random.uniform(0.1, 10.0, num_rows).round(2)
        }
        return pd.DataFrame(data)

    def generate_haproxy_data(num_rows=5):
        data = {
            "Timestamp": [datetime.datetime.now() - datetime.timedelta(minutes=i) for i in range(num_rows)],
            "Frontend": [f"frontend_{np.random.randint(1, 5)}" for _ in range(num_rows)],
            "Backend": [f"backend_{np.random.randint(1, 10)}" for _ in range(num_rows)],
            "Server": [f"server_{np.random.randint(1, 20)}" for _ in range(num_rows)],
            "Client_IP": [f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}" for _ in range(num_rows)],
            "Response_Time_ms": np.random.randint(10, 1000, num_rows),
            "Status_Code": np.random.choice([200, 302, 404, 500], num_rows)
        }
        return pd.DataFrame(data)

    def generate_ad_dns_data(num_rows=5):
        data = {
            "Timestamp": [datetime.datetime.now() - datetime.timedelta(minutes=i) for i in range(num_rows)],
            "Query_Name": [f"host{np.random.randint(1, 50)}.example.com" for _ in range(num_rows)],
            "Query_Type": np.random.choice(["A", "AAAA", "PTR", "MX"], num_rows),
            "Client_IP": [f"10.10.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}" for _ in range(num_rows)],
            "Response_Code": np.random.choice(["NOERROR", "NXDOMAIN", "SERVFAIL"], num_rows)
        }
        return pd.DataFrame(data)

    log_data_sources = {
        "VPN": generate_vpn_data(),
        "Domain Controller": generate_domain_controller_data(),
        "Zeek": generate_zeek_data(),
        "HAProxy": generate_haproxy_data(),
        "AD-DNS": generate_ad_dns_data()
    }

    # Initialize session state for selected log type
    if 'selected_log_type' not in st.session_state:
        st.session_state.selected_log_type = None

    # Buttons for selecting log type
    cols = st.columns(len(log_data_sources))
    for i, (log_type, _) in enumerate(log_data_sources.items()):
        with cols[i]:
            if st.button(log_type, key=f"log_type_button_{log_type}"):
                st.session_state.selected_log_type = log_type

    if st.session_state.selected_log_type:
        selected_df = log_data_sources[st.session_state.selected_log_type]
        st.subheader(f"Showing Data for: {st.session_state.selected_log_type}")

        # Search functionality
        search_query = st.text_input(f"Search in {st.session_state.selected_log_type} data:", key=f"search_{st.session_state.selected_log_type}")

        if search_query:
            # Filter the DataFrame based on the search query across all string columns
            filtered_df = selected_df[
                selected_df.apply(
                    lambda row: row.astype(str).str.contains(search_query, case=False, na=False).any(),
                    axis=1
                )
            ]
            st.dataframe(filtered_df)
            if filtered_df.empty:
                st.warning("No matching records found.")
        else:
            st.dataframe(selected_df)
    else:
        st.info("Click on a data type above to view its structured parsed data.")


def anomaly_detection():
    st.header("Anomaly Detection")
    st.write("Identify unusual patterns and deviations in system behavior.")
    st.info("Placeholder for anomaly alerts, historical anomaly trends, and configuration.")
    # st.markdown("""
    # - **Recent Anomalies:** List of detected anomalies with severity and timestamp.
    # - **Anomaly Trends:** Graph showing frequency and types of anomalies over time.
    # - **Detection Models:** Information on the models used for anomaly detection.
    # - **Alert Configuration:** Settings for anomaly notifications.
    # """)
    st.area_chart({"Metric Value": [10, 12, 11, 15, 50, 13, 14, 16, 15], "Threshold": [20]*9})
    st.warning("Anomaly detected at point 5!")

    st.subheader("Identified Anomalies")

    # Expanded anomaly data with new columns and more scan type variations
    anomaly_data = {
        "Index": ["VPN", "VPN", "DC", "DC", "ZEEK", "ZEEK", "ZEEK", "Firewall", "HA Proxy", "Firewall", "AD-DNS", "VPN", "DC", "HA Proxy"],
        "User": ["user_1", "user_2", "admin_account", "", "guest_user", "dev_user", "scanner_user", "network_user", "app_user", "admin", "dns_user", "user_3", "service_account", "web_user"],
        "Source_IP": ["192.168.1.10", "192.168.1.11", "10.0.0.5", "10.0.0.6", "172.16.0.100", "172.16.0.101", "172.16.0.102", "203.0.113.1", "198.51.100.10", "203.0.113.2", "10.10.10.1", "192.168.1.12", "10.0.0.7", "198.51.100.11"],
        "Source_Name": ["Laptop-User1", "Mobile-User2", "DC-Server-01", "DC-Server-02", "Zeek-Sensor-A", "Zeek-Sensor-B", "Nmap-Host", "Firewall-A", "HAProxy-01", "Firewall-B", "DNS-Client", "Tablet-User3", "Service-Host", "Web-Client"],
        "Destination_IP": ["10.0.1.5", "10.0.1.6", "192.168.10.1", "192.168.10.2", "8.8.8.8", "github.com", "target.com", "internal-app.com", "web-server-01", "external-service.com", "google.com", "vpn-endpoint", "database-server", "api-gateway"],
        "Destination_Name": ["VPN-Server", "VPN-Gateway", "AD-Client-1", "AD-Client-2", "Google-DNS", "GitHub", "Vulnerable-Host", "Internal-Service", "Web-App-Backend", "External-API", "Public-DNS", "VPN-Concentrator", "SQL-DB", "Microservice-API"],
        "Anomaly Type": ["vpn", "vpn", "identity", "identity", "user behavior", "user behavior", "user behavior", "user behavior", "application behavior", "network", "dns", "vpn", "identity", "application behavior"],
        "Scan Type": [
            "vpn_message_anomaly", "vpn_location_change", "identity_logon_failure", "identity_privilege_escalation",
            "data-transfer-download_large", "data-transfer-upload_sensitive", "nmap_scan_internal",
            "connection-rate_spike", "application-access_unusual",
            "port_scan_external", "dns_exfiltration_attempt", "vpn_bruteforce_attack",
            "impossible_travel", "http_flood_attack"
        ]
    }
    df_anomalies = pd.DataFrame(anomaly_data)

    st.markdown("#### Anomaly Details Table")
    st.dataframe(df_anomalies)

    st.markdown("#### Anomaly Type Counts")
    anomaly_type_counts = df_anomalies["Anomaly Type"].value_counts().reset_index()
    anomaly_type_counts.columns = ["Anomaly Type", "Count"]
    st.bar_chart(anomaly_type_counts.set_index("Anomaly Type"))

    st.markdown("#### Scan Type Distribution")
    scan_type_counts = df_anomalies["Scan Type"].value_counts().reset_index()
    scan_type_counts.columns = ["Scan Type", "Count"]
    
    if not scan_type_counts.empty:
        # Create a pie chart using Altair
        chart = alt.Chart(scan_type_counts).mark_arc().encode(
            theta=alt.Theta(field="Count", type="quantitative"),
            color=alt.Color(field="Scan Type", type="nominal", title="Scan Type"),
            order=alt.Order(field="Count", sort="descending"),
            tooltip=["Scan Type", "Count"]
        ).properties(
            title="Distribution of Anomaly Scan Types"
        )
        st.altair_chart(chart, use_container_width=True)
    else:
        st.warning("No scan type data available to display the pie chart.")


def correlation_root_cause_analysis():
    st.header("Correlation & Root Cause Analysis")
    st.write("Analyze relationships between events and pinpoint root causes of issues.")
    
    st.subheader("IP Correlation in Zeek and Domain Controller Logs")
    st.markdown("""
    This section correlates activities across different log sources to identify suspicious patterns related to specific IP addresses.
    """)

    # Dummy data for correlated IPs and their actions
    correlated_ip_data = {
        "Correlated_IP": ["10.0.0.6", "172.16.0.102", "192.168.1.11"],
        "Source_Logs": ["DC, Zeek", "Zeek, Firewall", "VPN, DC"],
        "Connected_To": ["Domain Controller, Internal Share", "External Host, Internal Network", "VPN Gateway, Domain Controller"],
        "Actions_Observed": [
            "Multiple failed login attempts, followed by successful access to sensitive share.",
            "Repeated NMAP scans on internal subnet, large data transfer to external IP.",
            "VPN authentication failures, then account lockout on DC."
        ]
    }
    df_correlated_ips = pd.DataFrame(correlated_ip_data)
    st.dataframe(df_correlated_ips)

    st.subheader("Root Cause Analysis Examples")
    st.markdown("""
    Here are some example root cause analyses based on correlated events:
    """)

    st.markdown("""
    **Scenario 1: Account Lockout Leading to Multiple Connections**
    - **Observed:** IP `192.168.1.11` correlated in VPN and Domain Controller logs. Initial VPN authentication failures, followed by an account lockout on the Domain Controller. Subsequently, multiple connection attempts were observed from the same IP to various internal resources.
    - **Root Cause Analysis:** The user (`user_2`) attempted to log in with an incorrect password multiple times, leading to an account lockout on the Domain Controller. The subsequent multiple connection attempts were likely the user trying to regain access with different credentials or from different applications, unaware of the lockout. This is a user-error driven incident, not a malicious attack, though it could mask one.
    - **Mitigation:** Implement clearer lockout notifications, provide self-service password reset options, and educate users on password best practices.

    **Scenario 2: Suspicious Internal Scanning and Data Transfer**
    - **Observed:** IP `172.16.0.102` correlated in Zeek and Firewall logs. This IP performed multiple NMAP scans on the internal network, followed by a 2GB data download to an external IP.
    - **Root Cause Analysis:** A compromised internal host (`Nmap-Host`) is likely being controlled by an attacker. The NMAP scans indicate reconnaissance, and the large data download suggests data exfiltration. The initial compromise vector needs to be identified (e.g., phishing, unpatched vulnerability).
    - **Mitigation:** Isolate the compromised host, block the external destination IP, perform forensic analysis on the host, and review network segmentation and intrusion detection systems.
    """)
    st.success("Root cause analysis helps in understanding the 'why' behind an incident, enabling effective long-term solutions.")


def user_journey():
    st.header("User Journey")
    st.write("Visualize and analyze user interactions and flows within the application.")

    # Dummy data for user journeys with more detailed events
    user_journeys_data = {
        "user_1": [
            {"phase": "VPN", "events": ["Authenticated and IP assigned 192.168.1.100."]},
            {"phase": "Domain Controller", "events": ["Multiple domain controller authentications happened successfully."]},
            {"phase": "Login", "events": ["Logged in from Location A.", "History: [Location A, Location A]."]},
            {"phase": "Zeek", "events": ["No suspicious port scans detected.", "Multiple downloads performed: `report.pdf`, `data_analysis.xlsx`."]},
            {"phase": "HAProxy", "events": ["Connected to multiple front ends:", " - Tableau.com", " - ITinfra.com"]},
            {"phase": "Endpoints", "events": ["Connected to endpoints: `server_alpha`, `server_beta`."]}
        ],
        "user_2": [
            {"phase": "VPN", "events": ["Authentication failed from IP 203.0.113.50."]},
            {"phase": "Domain Controller", "events": ["Account lockout occurred on domain controller."]},
            {"phase": "Login", "events": ["Login attempt from Location B.", "History: [Location A, Location B - **New Location Detected!**]."]},
            {"phase": "Zeek", "events": ["Port scan detected targeting internal network (10.0.0.0/24).", "Multiple uploads performed: `sensitive_project_docs.zip`."]},
            {"phase": "HAProxy", "events": ["No unusual HAProxy activity detected."]},
            {"phase": "Endpoints", "events": ["Connected to endpoint: `unknown_device_123`."]}
        ],
        "user_3": [
            {"phase": "VPN", "events": ["Authenticated and assigned IP 192.168.1.101."]},
            {"phase": "Domain Controller", "events": ["Successful authentication to multiple services on domain controller."]},
            {"phase": "Login", "events": ["Logged in from Location C.", "History: [Location C]."]},
            {"phase": "Zeek", "events": ["No significant data transfers observed.", "No suspicious port scans detected."]},
            {"phase": "HAProxy", "events": ["Connected to frontend: `internal-app.com`."]},
            {"phase": "Endpoints", "events": ["Connected to endpoint: `dev_machine_05`, `test_server_10`."]}
        ]
    }

    user_names = sorted(list(user_journeys_data.keys()))
    
    # User selection using a dropdown
    selected_user = st.selectbox("Select a User to view their Journey:", [""] + user_names, index=0)

    if selected_user:
        st.subheader(f"Journey for {selected_user}")
        journey_phases = user_journeys_data.get(selected_user, [])

        if journey_phases:
            view_mode = st.radio("Choose View Mode:", ("List View (Markdown)", "Graph View (Vertical Steps)"))

            if view_mode == "List View (Markdown)":
                for phase_info in journey_phases:
                    st.markdown(f"**--- {phase_info['phase']}**")
                    for event in phase_info['events']:
                        st.markdown(f"  - {event}")
            elif view_mode == "Graph View (Vertical Steps)":
                graph_dot = "digraph UserJourney {\n"
                graph_dot += "  rankdir=TB;\n" # Top to Bottom (vertical) layout
                graph_dot += "  node [shape=box, style=filled, fontname=\"Helvetica\", fontsize=12];\n"
                graph_dot += "  edge [color=gray, arrowhead=vee];\n"
                
                previous_node_id = None
                for i, phase_info in enumerate(journey_phases):
                    node_id = f"phase{i}"
                    
                    # Create a multi-line label for the node
                    label_content = f"{phase_info['phase']}"
                    for event in phase_info['events']:
                        # Escape quotes for Graphviz label
                        escaped_event = event.replace('"', '\\"')
                        label_content += f"\\n  - {escaped_event}"
                    
                    # Assign distinct colors based on phase type
                    fill_color = "lightblue"
                    if phase_info["phase"] == "VPN":
                        fill_color = "#ADD8E6" # Light Blue
                    elif phase_info["phase"] == "Domain Controller":
                        fill_color = "#FFD700" # Gold
                    elif phase_info["phase"] == "Login":
                        fill_color = "#90EE90" # Light Green
                    elif phase_info["phase"] == "Zeek":
                        fill_color = "#FFB6C1" # Light Pink
                    elif phase_info["phase"] == "HAProxy":
                        fill_color = "#DDA0DD" # Plum
                    elif phase_info["phase"] == "Endpoints":
                        fill_color = "#FFDAB9" # Peach

                    graph_dot += f'  {node_id} [label="{label_content}", fillcolor="{fill_color}"];\n'
                    
                    if previous_node_id:
                        graph_dot += f"  {previous_node_id} -> {node_id};\n"
                    previous_node_id = node_id
                graph_dot += "}"
                st.graphviz_chart(graph_dot)
        else:
            st.warning("No journey data available for this user.")
    else:
        st.info("Please select a user from the dropdown to view their journey.")


def incident_monitoring():
    st.header("Incident Monitoring")
    st.write("Track and manage ongoing incidents and their resolution status.")
    st.info("Placeholder for active incidents, incident history, and severity levels.")
    # st.markdown("""
    # - **Active Incidents:** List of currently open incidents with status and assignee.
    # - **Incident History:** Archive of past incidents with post-mortem reports.
    # - **Mean Time To Resolution (MTTR):** Average time taken to resolve incidents.
    # - **Severity Trends:** Graph showing incident severity over time.
    # """)
    st.dataframe({"ID": ["INC001", "INC002"], "Severity": ["High", "Medium"], "Status": ["Investigating", "Resolved"], "Assignee": ["Alice", "Bob"]})

def auto_assignments():
    st.header("Auto Assignments")
    st.write("Configure and monitor automated assignment rules for incidents and tasks.")
    st.info("Placeholder for assignment rules, audit logs, and override options.")
    st.markdown("""
    - **Assignment Rules:** List of configured rules (e.g., based on service, severity).
    - **Assignment History:** Log of automated assignments.
    - **Team Rosters:** Management of on-call schedules and team members.
    - **Override Mechanism:** Option to manually reassign tasks.
    """)
    st.code("""
    Rule 1: If severity is 'High' and service is 'Payment Gateway', assign to 'Payments Team'.
    Rule 2: If keyword 'Database' is present, assign to 'DBA Team'.
    """)

def suggestion_for_issue():
    st.header("Suggestion for Issue")
    st.write("Receive AI-driven suggestions for resolving identified issues.")
    
    st.subheader("Resolution Steps for 'Account Compromised' and 'High Application Access Rate' Incidents")

    st.markdown("#### Historical Steps Performed by Other System Analysts:")
    st.markdown("""
    - **Account Compromised:**
        - **Immediate Action:** Disable compromised account, revoke all active sessions.
        - **Investigation:** Review recent login history, check for unauthorized access from new IPs/locations.
        - **Forensics:** Analyze logs (authentication, VPN, application) for lateral movement or data exfiltration.
        - **Remediation:** Force password reset, implement MFA if not already in place, notify user.
        - **Post-mortem:** Document findings, update security policies, consider threat intelligence feeds.
    - **High Application Access Rate:**
        - **Immediate Action:** Isolate suspicious IP addresses, rate-limit requests from affected sources.
        - **Investigation:** Identify the source of the high access (legitimate traffic spike, bot, DDoS attempt).
        - **Analysis:** Examine application logs for specific endpoints being targeted, look for error rate increases.
        - **Mitigation:** Deploy WAF rules, adjust load balancer configurations, scale application resources if legitimate.
        - **Monitoring:** Continuously monitor access rates and application performance.
    """)

    st.markdown("#### Suggested Actions to Resolve the Issue:")
    st.markdown("""
    - **For Account Compromise:**
        1. **Confirm Scope:** Verify if other accounts or systems are affected.
        2. **Containment:** Isolate affected systems/networks if lateral movement is suspected.
        3. **Eradication:** Remove any malicious artifacts (e.g., persistent malware, unauthorized configurations).
        4. **Recovery:** Restore services to normal operation, ensuring all vulnerabilities are patched.
        5. **Lessons Learned:** Conduct a thorough review to prevent recurrence.
    - **For High Application Access Rate:**
        1. **Verify Legitimacy:** Determine if the traffic is expected (e.g., marketing campaign, legitimate user surge).
        2. **Implement Throttling:** Apply dynamic or static rate limiting at the edge or application layer.
        3. **Bot Mitigation:** Utilize bot detection and blocking tools.
        4. **Resource Scaling:** If legitimate, scale up infrastructure (servers, database connections) to handle the load.
        5. **Security Review:** Conduct a security audit to identify potential vulnerabilities exploited by the high access.
    """)
    st.info("These suggestions are based on common incident response frameworks and historical data. Always adapt steps to your specific environment and incident details.")


def agentic_ai_chatbot():
    st.header("Agentic AI Chatbot")
    st.write("Interact with an AI assistant for insights, queries, and task automation.")
    st.info("This chatbot can provide summaries and fetch data based on your commands.")
    
    st.markdown("#### Example Commands:")
    st.code("""
- what is the issue with user 1
- fetch all records from user 1
- fetch all anomalies for user 1
- fetch all historical data of user 1
- summarize issue for user 1 and show the issue and resolution
""")

    # Simulate chatbot response for example commands
    user_input = st.text_input("Type your message here...", key="chatbot_input")
    if user_input:
        st.chat_message("user").write(user_input)
        if "what is the issue with user 1" in user_input.lower() or "summarize issue" in user_input.lower():
            st.chat_message("assistant").write("I'm summarizing the issue and fetching relevant data for your request. Please wait a moment...")
            st.chat_message("assistant").write("**Issue Summary for User 1:** User 1 has recently experienced multiple failed VPN authentication attempts from unusual locations, followed by a successful login from a new, previously unseen IP address. This is flagged as an 'impossible travel' anomaly. \n\n**Resolution:** The system has automatically initiated a password reset for user 1 and temporarily disabled VPN access from the new location. Further investigation is recommended to confirm the user's identity and activity.")
        elif "fetch all records from user 1" in user_input.lower():
            st.chat_message("assistant").write("Fetching all records for user 1...")
            st.chat_message("assistant").write("*(Displaying a sample of user 1's records)*\n\n```\nTimestamp: 2025-07-08 10:00:00, Event: VPN Login, Status: Success, IP: 192.168.1.100\nTimestamp: 2025-07-08 10:05:00, Event: Domain Auth, Status: Success\nTimestamp: 2025-07-08 10:15:00, Event: File Download, File: report.pdf\n...\n```")
        elif "fetch all anomalies for user 1" in user_input.lower():
            st.chat_message("assistant").write("Fetching all anomalies for user 1...")
            st.chat_message("assistant").write("*(Displaying a sample of user 1's anomalies)*\n\n```\nAnomaly Type: VPN, Scan Type: vpn_location_change, Source IP: 203.0.113.50\nAnomaly Type: Identity, Scan Type: impossible_travel, Login Location: New York\n...\n```")
        elif "fetch all historical data of user 1" in user_input.lower():
            st.chat_message("assistant").write("Fetching all historical data for user 1...")
            st.chat_message("assistant").write("*(Displaying a comprehensive historical overview for user 1)*\n\n```\nUser Activity History:\n- 2025-07-01: Regular VPN usage from Home\n- 2025-07-05: Access to sensitive documents (normal behavior)\n- 2025-07-07: Multiple failed logins from unknown IP (anomaly detected)\n- 2025-07-08: Successful login from New York (anomaly detected)\n...\n```")
        else:
            st.chat_message("assistant").write(f"I'm sorry, I don't understand '{user_input}'. Please try one of the example commands.")


def database_input():
    st.header("Database Input Configuration")
    st.write("Configure database connection settings.")
    st.info("Placeholder for database connection parameters and testing.")
    st.text_input("Database Host", "localhost")
    st.text_input("Database Port", "5432")
    st.text_input("Database Name", "mydb")
    st.text_input("Username", "user")
    st.text_input("Password", type="password")
    st.button("Test Connection")

def aws_credentials():
    st.header("AWS Credentials Management")
    st.write("Manage AWS access keys and secret keys.")
    st.info("Placeholder for AWS credential input and validation.")
    st.text_input("AWS Access Key ID", "AKIA...")
    st.text_input("AWS Secret Access Key", type="password")
    st.text_input("AWS Region", "us-east-1")
    st.button("Validate Credentials")


st.set_page_config(layout="wide", page_title="AI Powered security monitoring and observability")

st.title("AI Powered security monitoring and observability")

# Define main tab titles
tab_titles = [
    "Data Ingestion Monitoring",
    "Infra Monitoring",
    "Indexed Data Management",
    "Anomaly Detection",
    "Correlation & Root Cause Analysis",
    "User Journey",
    "Incident Monitoring",
    "Auto Assignments",
    "Suggestion for Issue",
    "Agentic AI Chatbot"
]

# Define configuration tab titles
config_titles = [
    "Database Input",
    "AWS Credentials"
]

# Initialize session state for selected tab if not already set
if 'selected_tab' not in st.session_state:
    st.session_state.selected_tab = tab_titles[0] # Set default tab

# --- Sidebar Content ---
# Configuration section at the top
st.sidebar.header("Configuration")
for config_title in config_titles:
    if st.sidebar.button(config_title, key=f"sidebar_tab_{config_title}"):
        st.session_state.selected_tab = config_title

# Add a separator
st.sidebar.markdown("---")

# Main Dashboard Sections
st.sidebar.header("Dashboard Sections")
for tab_title in tab_titles:
    if st.sidebar.button(tab_title, key=f"sidebar_tab_{tab_title}"):
        st.session_state.selected_tab = tab_title

# --- Main Content Area ---
# Display content based on selected tab from session state
if st.session_state.selected_tab == "Data Ingestion Monitoring":
    data_ingestion_monitoring()
elif st.session_state.selected_tab == "Infra Monitoring":
    infra_monitoring()
elif st.session_state.selected_tab == "Indexed Data Management":
    indexed_data_management()
elif st.session_state.selected_tab == "Anomaly Detection":
    anomaly_detection()
elif st.session_state.selected_tab == "Correlation & Root Cause Analysis":
    correlation_root_cause_analysis()
elif st.session_state.selected_tab == "User Journey":
    user_journey()
elif st.session_state.selected_tab == "Incident Monitoring":
    incident_monitoring()
elif st.session_state.selected_tab == "Auto Assignments":
    auto_assignments()
elif st.session_state.selected_tab == "Suggestion for Issue":
    suggestion_for_issue()
elif st.session_state.selected_tab == "Agentic AI Chatbot":
    agentic_ai_chatbot()
elif st.session_state.selected_tab == "Database Input":
    database_input()
elif st.session_state.selected_tab == "AWS Credentials":
    aws_credentials()
