import matplotlib
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np
from matplotlib.ticker import ScalarFormatter

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
    transport_protocols = []
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
            'Transport': transport_protocols,
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


# ✅ A. IP Header Fields - כולל פרוטוקולים של UDP
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

    top_protocols = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_protocols = [p[0] for p in top_protocols]

    bar_width = 0.15
    x = np.arange(len(top_protocols))

    for idx, (app, app_data) in enumerate(results.items()):
        filtered_data = app_data['ip']['Protocol'].value_counts().reindex(top_protocols, fill_value=0)
        transport_data = app_data['ip']['Transport'].value_counts().reindex(top_protocols, fill_value=0)
        final_data = filtered_data.add(transport_data, fill_value=0)
        bars = plt.bar(x + idx * bar_width, final_data, width=bar_width, label=app, alpha=0.8)

        for bar in bars:
            plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(int(bar.get_height())), ha='center',
                     va='bottom', fontsize=8)

    plt.title("A: Most Frequent Protocols by App")
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    plt.xticks(x + bar_width * (len(results) / 2), top_protocols, rotation=45)
    plt.legend()
    plt.grid(axis="y", linestyle="--", alpha=0.6)
    plt.show()


# ✅ B. Top 10 TCP Source Ports
def plot_tcp_source_ports():
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
        bars = plt.bar(x + idx * bar_width, values, width=bar_width, color=colors[idx % len(colors)], label=app)

        # הצגת המספרים על גבי העמודות עם הטייה כלפי מעלה
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


# ✅ C. Packet Inter-arrival Time
from matplotlib.ticker import MaxNLocator


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

            # חישוב ממוצע והוספתו
            avg_interval = intervals.mean() * 1000  # ms
            ax.axvline(avg_interval / 1000, color='black', linestyle='--', linewidth=2)

            # ✨ מיקום חדש לתווית מעל הגרף
            y_max = ax.get_ylim()[1] * 1.05  # קביעת מיקום מעל הגרף
            ax.text(avg_interval / 1000, y_max, f"Avg: {avg_interval:.2f} ms",
                    ha='center', va='bottom', fontsize=10, fontweight='bold', color='black',
                    bbox=dict(facecolor='white', alpha=0.8, edgecolor='black'))

            ax.set_title(f"Packet Inter-arrival Time: {app}")
            ax.set_xlabel("Inter-arrival Time (s)")
            ax.set_ylabel("Density")
            ax.grid(True, linestyle='--', alpha=0.6, which='both')

    for i in range(idx + 1, len(axes)):
        fig.delaxes(axes[i])

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.show()


# ✅ D. Packet Sizes
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

            # חישוב ממוצע והוספתו
            avg_size = packet_sizes.mean()
            ax.axvline(avg_size, color='black', linestyle='--', linewidth=2)

            # ✨ מיקום חדש לתווית הממוצע מעל הגרף
            y_max = ax.get_ylim()[1] * 1.05  # קביעת מיקום מעל הגרף
            ax.text(avg_size, y_max, f"Avg: {avg_size:.2f} Bytes",
                    ha='center', va='bottom', fontsize=10, fontweight='bold', color='black',
                    bbox=dict(facecolor='white', alpha=0.8, edgecolor='black'))

            ax.set_title(f"Packet Size Distribution: {app}")
            ax.set_xlabel("Packet Size (Bytes)")
            ax.set_ylabel("Frequency")
            ax.grid(True, linestyle='--', alpha=0.6, which='both')

    for i in range(idx + 1, len(axes)):
        fig.delaxes(axes[i])

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.show()


# 📊 הפעלת כל הגרפים
plot_ip_protocol_distribution()
plot_tcp_source_ports()
plot_packet_inter_arrival()
plot_packet_size_distribution()
