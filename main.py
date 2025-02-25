import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import os
import numpy as np

# 📂 נתיב לקבצים
pcap_folder = './pcapfiles/'

# שמירת התוצאות
results = {}

# 🎨 צבעים ייחודיים לכל אפליקציה
colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

# 🔍 פונקציה לניתוח קובץ PCAP
def analyze_pcap(file_path):
    cap = pyshark.FileCapture(file_path)

    ip_src = []
    ip_dst = []
    protocols = []
    packet_sizes = []

    tcp_src_ports = []
    tcp_dst_ports = []
    tcp_flags = []

    tls_handshake_types = []
    tls_versions = []

    for packet in cap:
        # A. IP Header Fields
        if 'ip' in packet:
            ip_src.append(packet.ip.src)
            ip_dst.append(packet.ip.dst)
            protocols.append(packet.highest_layer)
            packet_sizes.append(int(packet.length))
        else:
            ip_src.append(None)
            ip_dst.append(None)
            protocols.append(None)
            packet_sizes.append(None)

        # B. TCP Header Fields
        if 'tcp' in packet:
            tcp_src_ports.append(packet.tcp.srcport)
            tcp_dst_ports.append(packet.tcp.dstport)
            tcp_flags.append(packet.tcp.flags)
        else:
            tcp_src_ports.append(None)
            tcp_dst_ports.append(None)
            tcp_flags.append(None)

        # C. TLS Header Fields
        if 'tls' in packet:
            if hasattr(packet.tls, 'handshake_type'):
                tls_handshake_types.append(int(packet.tls.handshake_type))
            else:
                tls_handshake_types.append(None)
            if hasattr(packet.tls, 'record_version'):
                tls_versions.append(packet.tls.record_version)
            else:
                tls_versions.append(None)
        else:
            tls_handshake_types.append(None)
            tls_versions.append(None)

    cap.close()

    return {
        'ip': pd.DataFrame({
            'Source IP': ip_src,
            'Destination IP': ip_dst,
            'Protocol': protocols,
            'Packet Size': packet_sizes
        }),
        'tcp': pd.DataFrame({
            'Source Port': tcp_src_ports,
            'Destination Port': tcp_dst_ports,
            'TCP Flags': tcp_flags
        }),
        'tls': pd.DataFrame({
            'Handshake Type': tls_handshake_types,
            'TLS Version': tls_versions
        })
    }

# 🔍 עיבוד כל הקבצים בתיקיה
for idx, file in enumerate(os.listdir(pcap_folder)):
    if file.endswith('.pcap') or file.endswith('.pcapng'):
        app_name = file.split('.')[0]
        file_path = os.path.join(pcap_folder, file)
        results[app_name] = analyze_pcap(file_path)

# ✅ פונקציה לציור גרף עם תיאור מילולי
def plot_with_description(title, xlabel, ylabel, data, feature_name):
    plt.figure(figsize=(14, 7))
    descriptions = []

    # הגדרת הצירים
    categories = list(set(
        category
        for app_data in results.values()
        for category in app_data[data][feature_name].dropna().unique()
    ))
    categories.sort()

    n_categories = len(categories)
    n_apps = len(results)
    bar_width = 0.15
    x = np.arange(n_categories)

    for idx, (app, app_data) in enumerate(results.items()):
        feature_counts = app_data[data][feature_name].value_counts().reindex(categories, fill_value=0)
        positions = x + (idx * bar_width)
        plt.bar(positions, feature_counts, width=bar_width, color=colors[idx % len(colors)], label=app)

        # תיאור מילולי
        most_common = feature_counts.idxmax()
        count = feature_counts.max()
        descriptions.append(f"- **{app}**: Most frequent {feature_name} is '{most_common}' with {count} occurrences.")

    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(x + bar_width * (n_apps / 2), categories, rotation=45)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.6)

    # תוויות ערכים
    for idx, (app, app_data) in enumerate(results.items()):
        feature_counts = app_data[data][feature_name].value_counts().reindex(categories, fill_value=0)
        positions = x + (idx * bar_width)
        for i, count in enumerate(feature_counts):
            plt.text(positions[i], count + 5, str(count), ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    plt.show()

    # הדפסת תיאורים מילוליים
    print(f"### {title} - Description:")
    for description in descriptions:
        print(description)
    print("\n")

# ✅ A. IP Header Fields
plot_with_description("A: IP Protocol Distribution by App", "Protocol", "Count", "ip", "Protocol")

# ✅ B. TCP Source Ports
plot_with_description("B: TCP Source Ports Distribution by App", "Source Port", "Count", "tcp", "Source Port")

# ✅ C. TLS Handshake Types
plot_with_description("C: TLS Handshake Types by App", "Handshake Type", "Count", "tls", "Handshake Type")

# ✅ D. Packet Sizes
# פיזור גודל החבילות (Histogram)
plt.figure(figsize=(14, 7))
descriptions = []

for idx, (app, app_data) in enumerate(results.items()):
    if not app_data['ip']['Packet Size'].empty:
        packet_sizes = app_data['ip']['Packet Size'].dropna()
        plt.hist(packet_sizes, bins=50, alpha=0.5, color=colors[idx % len(colors)], label=app)

        # תיאור מילולי
        avg_size = packet_sizes.mean()
        descriptions.append(f"- **{app}**: Average packet size is {avg_size:.2f} bytes.")

plt.title("D: Packet Size Distribution by App")
plt.xlabel("Packet Size (Bytes)")
plt.ylabel("Frequency")
plt.legend()
plt.grid(True, linestyle='--', alpha=0.6)
plt.tight_layout()
plt.show()

# תיאור מילולי של גודל הפקטות
print("### D: Packet Size Description:")
for description in descriptions:
    print(description)
print("\n")