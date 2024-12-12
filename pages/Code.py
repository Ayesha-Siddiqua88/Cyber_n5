import streamlit as st
import pandas as pd
import os
import plotly.express as px
import re
import chardet
from streamlit_option_menu import option_menu
import nmap
import networkx as nx
import matplotlib.pyplot as plt

def parse_log_file(file):
    """Parse the log file into a structured DataFrame."""
    events = []
    current_event = {}

    for line in file:
        line = line.strip()
        if line.startswith("Event["):
            if current_event:  # Save the previous event
                events.append(current_event)
            current_event = {"Event ID": None, "Log Name": None, "Source": None, "Date": None, "Level": None, "Description": None}
        elif line.startswith("Log Name:"):
            current_event["Log Name"] = line.split(": ", 1)[1]
        elif line.startswith("Source:"):
            current_event["Source"] = line.split(": ", 1)[1]
        elif line.startswith("Date:"):
            current_event["Date"] = line.split(": ", 1)[1]
        elif line.startswith("Event ID:"):
            current_event["Event ID"] = line.split(": ", 1)[1]
        elif line.startswith("Level:"):
            current_event["Level"] = line.split(": ", 1)[1]
        elif line.startswith("Description:"):
            current_event["Description"] = line.split(": ", 1)[1]
    if current_event:
        events.append(current_event)
    
    return pd.DataFrame(events)  

def visualize_event_data(df):
    """Visualize event log data."""
    st.subheader("Event Data Overview")

    # Show the raw data
    st.dataframe(df)

    # Visualization 1: Bar chart for Levels
    st.subheader("Event Levels Distribution")
    level_counts = df['Level'].value_counts()
    fig, ax = plt.subplots()
    level_counts.plot(kind='bar', color='skyblue', ax=ax)
    ax.set_title("Distribution of Event Levels")
    ax.set_ylabel("Count")
    ax.set_xlabel("Level")
    st.pyplot(fig)

    # Visualization 2: Pie chart for Sources
    st.subheader("Event Sources Distribution")
    source_counts = df['Source'].value_counts()
    fig, ax = plt.subplots()
    source_counts.plot(kind='pie', autopct='%1.1f%%', startangle=90, ax=ax, colors=plt.cm.Paired(range(len(source_counts))))
    ax.set_ylabel("")  # Remove y-axis label for pie chart
    ax.set_title("Distribution of Event Sources")
    st.pyplot(fig)

    # Visualization 3: Bar chart for Event IDs
    st.subheader("Top Event IDs")
    event_id_counts = df['Event ID'].value_counts().head(10)
    fig, ax = plt.subplots()
    event_id_counts.plot(kind='bar', color='coral', ax=ax)
    ax.set_title("Top 10 Event IDs")
    ax.set_ylabel("Count")
    ax.set_xlabel("Event ID")
    st.pyplot(fig)


def generate_script():
    script = "trail.ps1"

    script_file_path = os.path.join(os.getcwd(), script)

    try:
        # Read the content of the PowerShell script
        with open(script_file_path, "r") as file:
            script_content = file.read()

        # Provide the file for download
        st.download_button(
            label="Download PowerShell Script",
            data=script_content,
            file_name=script,
            mime="text/plain"
        )
    except FileNotFoundError:
        st.error(f"The PowerShell script '{script}' was not found in the project directory.")
    except Exception as e:
        st.error(f"An error occurred: {e}")


def visualize_vulnerability_data(data):
    st.title("Vulnerability Detection Dashboard")

    # Windows Updates: Donut chart
    if "Windows Updates" in data and isinstance(data["Windows Updates"], pd.DataFrame) and not data["Windows Updates"].empty:
        st.subheader("Windows Updates")
        fig = px.pie(data["Windows Updates"], names="HotFixID", title="Windows Updates Status", hole=0.3)
        st.plotly_chart(fig)

    # Antivirus Status: Pie chart
    if "Antivirus Status" in data and isinstance(data["Antivirus Status"], pd.DataFrame) and not data["Antivirus Status"].empty:
        st.subheader("Antivirus Status")
        fig = px.pie(data["Antivirus Status"], names="Antivirus", title="Antivirus Status")
        st.plotly_chart(fig)

    # Open Ports: Bar chart
    if "Open Ports" in data and isinstance(data["Open Ports"], pd.DataFrame) and not data["Open Ports"].empty:
        st.subheader("Open Ports")
        fig = px.bar(data["Open Ports"], x="Port", y="State", title="Open Ports Status")
        st.plotly_chart(fig)

    # Weak Passwords: List with a colored indicator
    if "Weak Passwords" in data and isinstance(data["Weak Passwords"], list) and data["Weak Passwords"]:
        st.subheader("Weak Passwords")
        st.write("The following accounts have weak passwords: ")
        for pwd in data["Weak Passwords"]:
            st.write(f"- {pwd}", color="red")

    # Windows Defender Status: Donut chart
    if "Windows Defender Status" in data and isinstance(data["Windows Defender Status"], pd.DataFrame) and not data["Windows Defender Status"].empty:
        st.subheader("Windows Defender Status")
        fig = px.pie(data["Windows Defender Status"], names="Feature", title="Windows Defender Status", hole=0.3)
        st.plotly_chart(fig)

    # Critical Patches: Bar chart
    if "Critical Patches" in data and isinstance(data["Critical Patches"], pd.DataFrame) and not data["Critical Patches"].empty:
        st.subheader("Critical Patches")
        fig = px.bar(data["Critical Patches"], x="HotFixID", y="Description", title="Critical Patches")
        st.plotly_chart(fig)

    # Outdated Software: Pie chart
    if "Outdated Software" in data and isinstance(data["Outdated Software"], pd.DataFrame) and not data["Outdated Software"].empty:
        st.subheader("Outdated Software")
        fig = px.pie(data["Outdated Software"], names="Name", title="Outdated Software")
        st.plotly_chart(fig)

# Function to process and visualize Network Scanner data
def visualize_network_scan_data(data):
    st.title("Network Scan Dashboard")
    if "Network Scan" in data and isinstance(data["Network Scan"], pd.DataFrame) and not data["Network Scan"].empty:
        st.subheader("Network Scan Results")
        fig = px.pie(data["Network Scan"], names="IP", values="Status", title="Network Status Distribution")
        st.plotly_chart(fig)

# Function to process and visualize System Info Scanner data
def visualize_system_info_data(data):
    st.title("System Info Dashboard")
    if "System Info" in data and isinstance(data["System Info"], pd.DataFrame) and not data["System Info"].empty:
        st.subheader("System Information")
        fig = px.pie(data["System Info"], names="Property", values="Value", title="System Properties Distribution")
        st.plotly_chart(fig)



# Function to detect file encoding and read content
def read_file_with_encoding(file):
    raw_data = file.read()
    detected_encoding = chardet.detect(raw_data)['encoding']  # Detect encoding
    decoded_content = raw_data.decode(detected_encoding, errors="ignore")  # Decode with detected encoding
    return decoded_content


# Helper function to extract sections based on numbered headings
def extract_sections(file_content):
    """Extracts sections from file content using numbered headings."""
    sections = re.split(r"\n(\d+\..+)\n", file_content)
    parsed_data = {}
    for i in range(1, len(sections), 2):
        title = sections[i].strip()
        content = sections[i + 1].strip()
        parsed_data[title] = content
    return parsed_data


# Function to process section data into a DataFrame
def process_section_data(section_content):
    """Converts section content into a DataFrame."""
    lines = section_content.splitlines()
    headers = None
    data = []
    for line in lines:
        if headers is None:
            headers = re.split(r"\s{2,}", line.strip())  # Identify headers
            continue
        row = re.split(r"\s{2,}", line.strip())
        if len(row) == len(headers):
            data.append(row)
    return pd.DataFrame(data, columns=headers) if headers and data else None


# Visualization function to display DataFrame and charts
def visualize_section_data(title, df):
    """Visualizes section data as a table and plots if applicable."""
    st.subheader(title)
    if isinstance(df, pd.DataFrame) and not df.empty:
        st.table(df)
        if "State" in df.columns:
            fig = px.bar(df, x=df.columns[0], y="State", title=f"{title} - State Distribution")
            st.plotly_chart(fig)
        elif "Value" in df.columns:
            fig = px.pie(df, names="Property", values="Value", title=f"{title} - Distribution")
            st.plotly_chart(fig)
    else:
        st.write("No data to display.")


# Function to parse vulnerability output
def parse_vulnerability_output(file_content):
    data = {
        "Windows Updates": [],
        "Antivirus Status": [],
        "Open Ports": [],
        "Weak Passwords": [],
        "Windows Defender Status": [],
        "Critical Patches": [],
        "Outdated Software": [],
    }

    lines = file_content.splitlines()

    for line in lines:
        if "HotFixID" in line:
            parts = line.split(":")
            if len(parts) == 2:
                data["Windows Updates"].append({
                    "HotFixID": parts[1].strip(),
                    "InstalledOn": "N/A"  # Replace with actual date if available
                })
        elif "Antivirus" in line:
            parts = line.split(":")
            if len(parts) == 2:
                data["Antivirus Status"].append({
                    "Antivirus": parts[0].strip(),
                    "State": parts[1].strip()
                })
        elif "Port" in line:
            parts = line.split(":")
            if len(parts) == 2:
                data["Open Ports"].append({
                    "Port": parts[0].strip(),
                    "State": parts[1].strip()
                })
        elif "Weak Password" in line:
            data["Weak Passwords"].append(line.replace("Weak Password:", "").strip())
        elif "Defender" in line:
            parts = line.split(":")
            if len(parts) == 2:
                data["Windows Defender Status"].append({
                    "Feature": parts[0].strip(),
                    "Status": parts[1].strip()
                })
        elif "Patch" in line:
            parts = line.split(":")
            if len(parts) == 2:
                data["Critical Patches"].append({
                    "HotFixID": parts[0].strip(),
                    "Description": parts[1].strip()
                })
        elif "Software" in line:
            parts = line.split(":")
            if len(parts) == 2:
                data["Outdated Software"].append({
                    "Name": parts[0].strip(),
                    "Version": parts[1].strip()
                })

    # Convert lists to DataFrames where appropriate
    for key, value in data.items():
        if isinstance(value, list) and value and isinstance(value[0], dict):
            data[key] = pd.DataFrame(value)

    return data


# Function to process system information content
def process_system_info(file_content):
    data = {"System Info": []}
    lines = file_content.splitlines()
    for line in lines:
        if ":" in line:
            parts = line.split(":")
            if len(parts) == 2:
                data["System Info"].append({"Property": parts[0].strip(), "Value": parts[1].strip()})
    data["System Info"] = pd.DataFrame(data["System Info"])
    return data

def visualize_events(df):
    """Visualize the events in the log file."""
    if df.empty:
        st.warning("No events to display.")
        return

    st.subheader("Event Log Summary")

    # Count events by level
    level_counts = df["Level"].value_counts()
    st.bar_chart(level_counts)

    # Display raw data
    st.subheader("Raw Event Data")
    st.dataframe(df)


# Function to process network scan results
def process_network_scan_results(file_content):
    data = {"Network Scan": []}
    lines = file_content.splitlines()
    for line in lines:
        if "IP" in line or "Status" in line:
            parts = line.split(",")
            if len(parts) == 2:
                data["Network Scan"].append({"IP": parts[0].strip(), "Status": parts[1].strip()})
    data["Network Scan"] = pd.DataFrame(data["Network Scan"])
    return data


# Streamlit app setup
st.set_page_config(page_title="File Scanner App", layout="wide")

# Sidebar with tabs
with st.sidebar:
    st.title("Navigation")
    selected_tab = option_menu("🚥🚥🚥🚥🚥",["Download Script","Vulnerability Scanner", "Network Scanner", "System Info Scanner","Log Monitoring"],default_index=0 )
    st.image("image.jpg")

if selected_tab=="Download Script":
    st.title("📝 Download PowerShell Script")        
    # Provide instructions for running the script
    st.subheader("How to Scan Your System:")
    st.write("""
        1. Open your PowerShell.
        2. Run the script provided below to generate three output files: 
        - `VulnerabilityDetectionOutput.txt`
        - `NetworkScanOutput.txt`
        - `SystemInfoOutput.txt`
        3. Save the output files to your machine.
        4. Upload the corresponding files in the respective scanner sections above to analyze the data.
        """)
    generate_script()
    

elif selected_tab == "Vulnerability Scanner":
        st.title("🔒 Vulnerability Scanner")
        st.write("Drag and drop a `VulnerabilityDetectionOutput.txt` file to scan and visualize vulnerabilities.")

        uploaded_file = st.file_uploader("Upload a TXT file", type="txt")

        if uploaded_file:
            file_content = read_file_with_encoding(uploaded_file)
            parsed_data = parse_vulnerability_output(file_content)
            visualize_vulnerability_data(parsed_data)
        else:
            st.write("Please upload a file to view its content.")


elif selected_tab == "Network Scanner":
        st.title("🌐 Network Scanner")
        st.write("Drag and drop a text file to analyze network-related parameters.")

        uploaded_file = st.file_uploader("Upload a TXT file", type="txt")
        if uploaded_file:
            file_content = read_file_with_encoding(uploaded_file)
            parsed_data = process_network_scan_results(file_content)
            visualize_network_scan_data(parsed_data)
            sections = extract_sections(file_content)
            for title, content in sections.items():
                st.subheader(title)
                df = process_section_data(content)
                if df is not None:
                    st.dataframe(df)
                else:
                    st.text(content)
            st.subheader("Network Topology")
            st.image("network.jpg")
        else:
            st.write("Please upload a file to view its content.")

elif selected_tab == "System Info Scanner":
        st.title("🖥️ System Info Scanner")
        st.write("Drag and drop a `SystemInfo.txt` file to view system information.")

        uploaded_file = st.file_uploader("Upload a TXT file", type="txt")
        if uploaded_file:
            file_content = read_file_with_encoding(uploaded_file)
            processed_data = process_system_info(file_content)
            visualize_system_info_data(processed_data)
            for key, value in processed_data.items():
                st.header(key)
                st.table(value)
        else:
            st.write("Please upload a file to view its content.")

elif selected_tab == "Log Monitoring":
    st.title("📜 Log Monitoring")
    st.write("Drag and drop a `Log.txt` file to monitor and visualize log events.")
    
    # File uploader
    uploaded_file = st.file_uploader("Upload Event Log File (TXT format)", type=["txt"])
    
    if uploaded_file:
        try:
            # Read the content of the uploaded file as a string
            content = uploaded_file.read().decode("utf-8", errors="ignore")
            
            # Display the raw content as it is (exactly as it appears in the file)
            st.subheader("Raw Log Data")
            st.text(content)  # Display the entire log data as plain text
            
            # Optional: You can parse the content if you want to perform any visualizations
            df = parse_log_file(content)
            visualize_events(df)
            
        except Exception as e:
            st.error(f"An error occurred while processing the file: {e}")
    else:
        st.info("Please upload a valid event log file to start visualization.")