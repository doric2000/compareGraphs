import matplotlib
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np

matplotlib.use('TkAgg')

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
    packet_timestamps = []

    tcp_src_ports = []
    tcp_dst_ports = []
    tcp_flags = []

    for packet in cap:
        # A. IP Header Fields
        if 'ip' in packet:
            ip_src.append(packet.ip.src)
            ip_dst.append(packet.ip.dst)
            protocols.append(packet.highest_layer)
            packet_sizes.append(int(packet.length))
            packet_timestamps.append(float(packet.sniff_timestamp))
        else:
            ip_src.append(None)
            ip_dst.append(None)
            protocols.append(None)
            packet_sizes.append(None)
            packet_timestamps.append(None)

        # B. TCP Header Fields
        if 'tcp' in packet:
            tcp_src_ports.append(packet.tcp.srcport)
            tcp_dst_ports.append(packet.tcp.dstport)
            tcp_flags.append(packet.tcp.flags)
        else:
            tcp_src_ports.append(None)
            tcp_dst_ports.append(None)
            tcp_flags.append(None)

    cap.close()

    # חישוב מרווחי זמן בין פקטות
    packet_intervals = np.diff([t for t in packet_timestamps if t is not None])

    return {
        'ip': pd.DataFrame({
            'Source IP': ip_src,
            'Destination IP': ip_dst,
            'Protocol': protocols,
            'Packet Size': packet_sizes,
            'Timestamp': packet_timestamps
        }),
        'tcp': pd.DataFrame({
            'Source Port': tcp_src_ports,
            'Destination Port': tcp_dst_ports,
            'TCP Flags': tcp_flags
        }),
        'inter_arrival': pd.DataFrame({
            'Interval': packet_intervals
        })
    }


# 🔍 עיבוד כל הקבצים בתיקיה
for idx, file in enumerate(os.listdir(pcap_folder)):
    if file.endswith('.pcap') or file.endswith('.pcapng'):
        app_name = file.split('.')[0]
        file_path = os.path.join(pcap_folder, file)
        results[app_name] = analyze_pcap(file_path)


# ✅ A. IP Header Fields
def plot_ip_protocol_distribution():
    plt.figure(figsize=(14, 7))
    categories = list(set(
        protocol
        for app_data in results.values()
        for protocol in app_data['ip']['Protocol'].dropna().unique()
    ))
    categories.sort()

    x = np.arange(len(categories))
    bar_width = 0.15

    for idx, (app, app_data) in enumerate(results.items()):
        counts = app_data['ip']['Protocol'].value_counts().reindex(categories, fill_value=0)
        plt.bar(x + idx * bar_width, counts, width=bar_width, color=colors[idx % len(colors)], label=app)

        # הצגת ספירות
        for i, count in enumerate(counts):
            plt.text(x[i] + idx * bar_width, count + 5, str(count), ha='center', va='bottom', fontsize=8)

    plt.title("A: IP Protocol Distribution by App")
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    plt.xticks(x + bar_width * (len(results) / 2), categories, rotation=45)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()


# ✅ B. Top 10 TCP Source Ports - תיקון
def plot_tcp_source_ports_fixed():
    plt.figure(figsize=(18, 9))
    port_counts = {}

    # ספירת הפורטים עבור כל אפליקציה
    for app, app_data in results.items():
        ports = app_data['tcp']['Source Port'].dropna()
        port_counts[app] = ports.value_counts().nlargest(10)

    # יצירת רשימה ייחודית של פורטים לכל האפליקציות
    unique_ports = sorted(set(port for counts in port_counts.values() for port in counts.index))

    x = np.arange(len(unique_ports))
    bar_width = 0.15

    for idx, (app, counts) in enumerate(port_counts.items()):
        values = [counts.get(port, 0) for port in unique_ports]
        plt.bar(x + idx * bar_width, values, width=bar_width, color=colors[idx % len(colors)], label=app)

        # הצגת המספרים על גבי העמודות
        for i, count in enumerate(values):
            if count > 0:
                plt.text(x[i] + idx * bar_width, count + 2, str(count), ha='center', va='bottom', fontsize=8)

    plt.title("B: Top 10 TCP Source Ports by App (Fixed)")
    plt.xlabel("Source Port")
    plt.ylabel("Count")
    plt.xticks(x + bar_width * (len(results) / 2), unique_ports, rotation=45)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()


# ✅ C. Packet Inter-arrival Time - שיפור התצוגה עם KDE ו-Subplots
def plot_packet_inter_arrival_improved():
    num_apps = len(results)
    cols = 2  # מספר העמודות של הסאבפלוטים
    rows = (num_apps // cols) + (num_apps % cols > 0)

    fig, axes = plt.subplots(rows, cols, figsize=(16, 10))
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

            # חישוב ממוצע והצגתו
            avg_interval = intervals.mean() * 1000  # ms
            ax.axvline(avg_interval / 1000, color='black', linestyle='--', linewidth=1)
            ax.text(avg_interval / 1000, 0.8, f"Avg: {avg_interval:.2f} ms", rotation=90, va='center', fontsize=9)

            ax.set_xscale('log')
            ax.set_title(f"Packet Inter-arrival Time: {app}")
            ax.set_xlabel("Inter-arrival Time (s)")
            ax.set_ylabel("Density")
            ax.grid(True, linestyle='--', alpha=0.6, which='both')

    # הסתרת גרפים ריקים במידת הצורך
    for i in range(idx + 1, len(axes)):
        fig.delaxes(axes[i])

    plt.tight_layout()
    plt.show()


# ✅ D. Packet Sizes
def plot_packet_size_distribution():
    plt.figure(figsize=(14, 7))
    descriptions = []

    for idx, (app, app_data) in enumerate(results.items()):
        if not app_data['ip']['Packet Size'].empty:
            packet_sizes = app_data['ip']['Packet Size'].dropna()
            plt.hist(packet_sizes, bins=50, alpha=0.5, color=colors[idx % len(colors)], label=app)

            # ממוצע גודל החבילות
            avg_size = packet_sizes.mean()
            descriptions.append(f"- **{app}**: Average packet size is {avg_size:.2f} bytes.")

    plt.title("D: Packet Size Distribution by App")
    plt.xlabel("Packet Size (Bytes)")
    plt.ylabel("Frequency")
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()

    # הדפסת התיאורים
    print("### D: Packet Size Description:")
    for description in descriptions:
        print(description)
    print("\n")


# 📊 הרצת הגרפים המתוקנים
plot_ip_protocol_distribution()
plot_tcp_source_ports_fixed()
plot_packet_inter_arrival_improved()
plot_packet_size_distribution()
