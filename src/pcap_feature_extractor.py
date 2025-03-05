"""
Network Traffic Analysis Script
---------------------------------
This script is designed to:

1) Load multiple PCAP files, each representing network traffic data.
2) Extract key numerical features such as packet sizes, timestamps, and transport protocols.
3) Apply a rule-based approach to analyze IP, TCP, and TLS traffic.
4) Compute additional network metrics such as inter-arrival times.
5) Store the results in structured Pandas DataFrames for further analysis.
6) Generate visualizations to understand protocol distribution, packet sizes, and inter-arrival time distributions.

HOW TO RUN:
    Execute the script using Python:
    python network_traffic_analysis.py

ASSUMPTIONS:
- Each PCAP file contains network traffic data that includes IP, TCP, and TLS packets.
- SSL key log files (if available) are stored in a designated folder for decryption.
- The script extracts only non-encrypted metadata from TLS packets.
- The extracted data is structured into tables to facilitate further analysis.
- The script processes multiple files and visualizes network characteristics.
"""


import matplotlib
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np
from matplotlib.ticker import ScalarFormatter

matplotlib.use('TkAgg')

# Path to files
pcap_folder = '../res/pcapfiles/'
ssl_keys_folder = '../res/sslkeys/'

# Storing results
results = {}

# Unique colors for each application
colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

# Function to analyze PCAP file with SSL key

for idx, file in enumerate(os.listdir(pcap_folder)):
    if file.endswith('.pcap') or file.endswith('.pcapng'):
        app_name = file.split('.')[0]
        file_path = os.path.join(pcap_folder, file)
        ssl_key_file = os.path.join(ssl_keys_folder, f"{app_name}.log")

        if os.path.exists(ssl_key_file):
            print(f"✅ Using SSL Key Log: {ssl_key_file} for {app_name}")
        else:
            print(f"⚠️ No SSL Key Log found for {app_name}, running without decryption.")




"""
    Analyzes a PCAP file and extracts key network traffic features.

This function processes a PCAP file, extracting metadata from IP, TCP, and TLS layers. 
If an SSL key log is available, it enables TLS decryption.

**Extracted Features:**
- **IP Layer:** Source/Destination IP, Protocol, Transport, Packet size, Timestamp.
- **TCP Layer:** Source/Destination port, TCP flags.
- **TLS Layer:** Version, Cipher suite, Handshake type, Server Name Indication (SNI).
- **Timing Metrics:** Inter-packet arrival time.

**Parameters:**
- `file_path` (str): Path to the PCAP file.
- `ssl_key_path` (str, optional): Path to the SSL key log file.

**Returns:**
- dict: A dictionary of Pandas DataFrames for IP, TCP, TLS, and inter-arrival time data.
"""
def analyze_pcap(file_path, ssl_key_path=None):
    capture_options = {}
    if ssl_key_path and os.path.exists(ssl_key_path):
        capture_options['override_prefs'] = {'tls.keylog_file': ssl_key_path}

    cap = pyshark.FileCapture(file_path, **capture_options)

    ip_src = []
    ip_dst = []
    protocols = []
    transport_protocols = []
    packet_sizes = []
    packet_timestamps = []

    tcp_src_ports = []
    tcp_dst_ports = []
    tcp_flags = []

    tls_versions = []
    tls_cipher_suites = []
    tls_handshake_types = []
    tls_sni = []

    for packet in cap:
        # A. Extract IP Header Fields
        if 'ip' in packet:
            ip_src.append(packet.ip.src)
            ip_dst.append(packet.ip.dst)
            protocols.append(packet.highest_layer)
            transport_protocols.append(packet.transport_layer)
            packet_sizes.append(int(packet.length))
            packet_timestamps.append(float(packet.sniff_timestamp))
        else:
            ip_src.append(None)
            ip_dst.append(None)
            protocols.append(None)
            transport_protocols.append(None)
            packet_sizes.append(None)
            packet_timestamps.append(None)

        # B. Extract TCP Header Fields
        if 'tcp' in packet:
            tcp_src_ports.append(packet.tcp.srcport)
            tcp_dst_ports.append(packet.tcp.dstport)
            tcp_flags.append(packet.tcp.flags)
        else:
            tcp_src_ports.append(None)
            tcp_dst_ports.append(None)
            tcp_flags.append(None)

        # C. Extract TLS Handshake Fields
        if 'tls' in packet:
            tls_handshake_types.append(getattr(packet.tls, 'handshake_type', None))
            tls_versions.append(getattr(packet.tls, 'record_version', None))
            tls_cipher_suites.append(getattr(packet.tls, 'handshake_ciphersuite', None))
            tls_sni.append(getattr(packet.tls, 'handshake_extensions_server_name', None))
        else:
            tls_handshake_types.append(None)
            tls_versions.append(None)
            tls_cipher_suites.append(None)
            tls_sni.append(None)

    cap.close()

    # Compute inter-packet arrival times (time difference between consecutive packets)
    packet_intervals = np.diff([t for t in packet_timestamps if t is not None])

    return {
        'ip': pd.DataFrame({
            'Source IP': ip_src,
            'Destination IP': ip_dst,
            'Protocol': protocols,
            'Transport': transport_protocols,
            'Packet Size': packet_sizes,
            'Timestamp': packet_timestamps
        }),
        'tcp': pd.DataFrame({
            'Source Port': tcp_src_ports,
            'Destination Port': tcp_dst_ports,
            'TCP Flags': tcp_flags
        }),
        'tls': pd.DataFrame({
            'TLS Version': tls_versions,
            'TLS Cipher Suite': tls_cipher_suites,
            'TLS Handshake Type': tls_handshake_types,
            'Server Name (SNI)': tls_sni
        }),
        'inter_arrival': pd.DataFrame({
            'Interval': packet_intervals
        })
    }


# Process all PCAP files in the specified folder
for idx, file in enumerate(os.listdir(pcap_folder)):
    if file.endswith('.pcap') or file.endswith('.pcapng'):
        app_name = file.split('.')[0]
        file_path = os.path.join(pcap_folder, file)
        ssl_key_file = os.path.join(ssl_keys_folder, f"{app_name}.log")
        results[app_name] = analyze_pcap(file_path, ssl_key_file)


"""
    lots the distribution of the most used IP and transport layer protocols.

This function analyzes network traffic data, counts occurrences of different IP protocols (TCP, UDP, ICMP), 
and visualizes the top 10 most frequent protocols in a grouped bar chart.

**Process:**
1) Extract protocol counts from all analyzed PCAP files.
2) Identify the top 10 most used protocols.
3) Generate a bar chart comparing protocol usage across different applications.

**Returns:**
- A bar chart displaying protocol distribution.
"""
def plot_ip_protocol_distribution():
    plt.figure(figsize=(14, 7))
    protocol_counts = {}

    for app, app_data in results.items():
        protocol_count = app_data['ip']['Protocol'].value_counts()
        transport_count = app_data['ip']['Transport'].value_counts()

        for protocol, count in protocol_count.items():
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + count
        for transport, count in transport_count.items():
            protocol_counts[transport] = protocol_counts.get(transport, 0) + count

    # Extract the top 10 most common protocols
    top_protocols = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_protocols = [p[0] for p in top_protocols]

    bar_width = 0.15
    x = np.arange(len(top_protocols))

    # Plot protocol usage per application
    for idx, (app, app_data) in enumerate(results.items()):
        filtered_data = app_data['ip']['Protocol'].value_counts().reindex(top_protocols, fill_value=0)
        transport_data = app_data['ip']['Transport'].value_counts().reindex(top_protocols, fill_value=0)
        final_data = filtered_data.add(transport_data, fill_value=0)

        bars = plt.bar(x + idx * bar_width, final_data, width=bar_width, label=app, alpha=0.8)

        # Display count values on top of bars
        for bar in bars:
            plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(int(bar.get_height())),
                     ha='center', va='bottom', fontsize=8)

    plt.title("A: Most Frequent Protocols by App")
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    plt.xticks(x + bar_width * (len(results) / 2), top_protocols, rotation=45)
    plt.legend()
    plt.grid(axis="y", linestyle="--", alpha=0.6)
    plt.show()



#  B. Top 10 TCP Source Ports
"""
    Plots the top 10 most frequently used TCP source ports per application.

    This function analyzes TCP traffic from all processed PCAP files, 
    counts the most common source ports for each application, 
    and visualizes them in a grouped bar chart.

    **Process:**
    1) Extract source port counts from all applications.
    2) Identify the top 10 most used source ports per application.
    3) Create a unique list of the top ports across all applications.
    4) Plot a grouped bar chart showing port usage per application.

    **Returns:**
    - A bar chart displaying TCP source port distribution.
    """
def plot_tcp_source_ports():
    plt.figure(figsize=(18, 9))
    port_counts = {}

    # Count source ports for each application
    for app, app_data in results.items():
        ports = app_data['tcp']['Source Port'].dropna()
        port_counts[app] = ports.value_counts().nlargest(10)

    # Create a unique list of the top ports across all applications
    unique_ports = sorted(set(port for counts in port_counts.values() for port in counts.index))

    x = np.arange(len(unique_ports))
    bar_width = 0.15

    # Plot port usage per application
    for idx, (app, counts) in enumerate(port_counts.items()):
        values = [counts.get(port, 0) for port in unique_ports]
        bars = plt.bar(x + idx * bar_width, values, width=bar_width, color=colors[idx % len(colors)], label=app)

        # Display values on top of bars
        for bar in bars:
            if bar.get_height() > 0:
                plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 5,
                         str(int(bar.get_height())), ha='center', va='bottom', fontsize=9, rotation=45)

    plt.title("B: Top 10 TCP Source Ports by App")
    plt.xlabel("Source Port")
    plt.ylabel("Count")
    plt.xticks(x + bar_width * (len(results) / 2), unique_ports, rotation=45, ha="right")
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()


"""
    Plots the packet inter-arrival time distribution for each application.

    This function analyzes the time intervals between consecutive packets 
    in network traffic for each application and visualizes their distributions using KDE plots.

    **Process:**
    1) Extract inter-arrival times from all applications.
    2) Compute the average inter-arrival time for each app.
    3) Plot a Kernel Density Estimate (KDE) curve for each app.
    4) Mark the average inter-arrival time on each graph.

    **Returns:**
    - A set of KDE plots displaying inter-arrival time distributions.
    """
def plot_packet_inter_arrival():
    num_apps = len(results)
    cols = 2
    rows = (num_apps // cols) + (num_apps % cols > 0)

    fig, axes = plt.subplots(rows, cols, figsize=(16, 10))
    fig.suptitle("C: Packet Inter-arrival Time Distribution by App", fontsize=16, fontweight='bold')
    axes = axes.flatten()

    for idx, (app, app_data) in enumerate(results.items()):
        ax = axes[idx]
        if not app_data['inter_arrival']['Interval'].empty:
            intervals = app_data['inter_arrival']['Interval'].dropna()
            sns.kdeplot(
                intervals,
                ax=ax,
                color=colors[idx % len(colors)],
                fill=True,
                linewidth=2,
                label=app
            )

            # Compute and plot the average inter-arrival time
            avg_interval = intervals.mean() * 1000  # Convert to milliseconds
            ax.axvline(avg_interval / 1000, color='black', linestyle='--', linewidth=2)

            # Position the label above the graph
            y_max = ax.get_ylim()[1] * 1.05
            ax.text(avg_interval / 1000, y_max, f"Avg: {avg_interval:.2f} ms",
                    ha='center', va='bottom', fontsize=10, fontweight='bold', color='black',
                    bbox=dict(facecolor='white', alpha=0.8, edgecolor='black'))

            ax.set_title(f"Packet Inter-arrival Time: {app}")
            ax.set_xlabel("Inter-arrival Time (s)")
            ax.set_ylabel("Density")
            ax.grid(True, linestyle='--', alpha=0.6, which='both')

    # Remove empty subplots if the number of apps is odd
    for i in range(idx + 1, len(axes)):
        fig.delaxes(axes[i])

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.show()

"""
    Plots the packet size distribution for each application.

    This function analyzes packet size data from network traffic for each application
    and visualizes the distribution using histograms.

    **Process:**
    1) Extract packet sizes from all applications.
    2) Compute the average packet size for each app.
    3) Plot a histogram showing the packet size distribution.
    4) Mark the average packet size on each graph.

    **Returns:**
    - A set of histograms displaying packet size distributions.
    """
def plot_packet_size_distribution():
    num_apps = len(results)
    cols = 2
    rows = (num_apps // cols) + (num_apps % cols > 0)

    fig, axes = plt.subplots(rows, cols, figsize=(16, 10))
    fig.suptitle("D: Packet Size Distribution by App", fontsize=16, fontweight='bold')
    axes = axes.flatten()

    for idx, (app, app_data) in enumerate(results.items()):
        ax = axes[idx]
        if not app_data['ip']['Packet Size'].empty:
            packet_sizes = app_data['ip']['Packet Size'].dropna()
            ax.hist(packet_sizes, bins=50, alpha=0.6, color=colors[idx % len(colors)], edgecolor='black')

            # Compute and plot the average packet size
            avg_size = packet_sizes.mean()
            ax.axvline(avg_size, color='black', linestyle='--', linewidth=2)

            # Position the label above the graph
            y_max = ax.get_ylim()[1] * 1.05
            ax.text(avg_size, y_max, f"Avg: {avg_size:.2f} Bytes",
                    ha='center', va='bottom', fontsize=10, fontweight='bold', color='black',
                    bbox=dict(facecolor='white', alpha=0.8, edgecolor='black'))

            ax.set_title(f"Packet Size Distribution: {app}")
            ax.set_xlabel("Packet Size (Bytes)")
            ax.set_ylabel("Frequency")
            ax.grid(True, linestyle='--', alpha=0.6, which='both')

    # Remove empty subplots if the number of apps is odd
    for i in range(idx + 1, len(axes)):
        fig.delaxes(axes[i])

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.show()


#  Execute all visualizations
plot_ip_protocol_distribution()
plot_tcp_source_ports()
plot_packet_inter_arrival()
plot_packet_size_distribution()
