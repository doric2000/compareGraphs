
import os

import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
from scipy.stats import entropy
import pyshark
import numpy as np
import seaborn as sns
from sklearn.cluster import KMeans

matplotlib.use('TkAgg')

# 📂 נתיב לקבצים
pcap_folder = './pcapfiles/'
ssl_keys_folder = './sslkeys/'  # 🔑 תיקייה לקובצי SSL Key Log

# רשימת מאפיינים שנאסוף
flow_data = []

# 🔍 פונקציה לניתוח קובץ PCAP עם קובץ SSL
def analyze_pcap(file_path, ssl_key_path=None):
    capture_options = {}
    if ssl_key_path and os.path.exists(ssl_key_path):
        capture_options['override_prefs'] = {'tls.keylog_file': ssl_key_path}

    cap = pyshark.FileCapture(file_path, **capture_options)

    packet_sizes = []
    packet_timestamps = []

    for packet in cap:
        if 'ip' in packet:
            packet_sizes.append(int(packet.length))
            packet_timestamps.append(float(packet.sniff_timestamp))

    if len(packet_sizes) > 1:
        mean_size = np.mean(packet_sizes)
        std_size = np.std(packet_sizes)
        inter_arrival_times = np.diff(packet_timestamps)
        mean_inter_arrival = np.mean(inter_arrival_times) if len(inter_arrival_times) > 0 else 0
        std_inter_arrival = np.std(inter_arrival_times) if len(inter_arrival_times) > 0 else 0
        total_packets = len(packet_sizes)
        packet_entropy = entropy(packet_sizes, base=2) if len(set(packet_sizes)) > 1 else 0

        flow_data.append([mean_size, std_size, mean_inter_arrival, std_inter_arrival, total_packets, packet_entropy])

# עיבוד כל קובצי ה-PCAP
for file in os.listdir(pcap_folder):
    if file.endswith('.pcap') or file.endswith('.pcapng'):
        app_name = file.split('.')[0]
        file_path = os.path.join(pcap_folder, file)
        ssl_key_file = os.path.join(ssl_keys_folder, f"{app_name}.log")

        print(f"🔍 Analyzing: {file}")
        analyze_pcap(file_path, ssl_key_file if os.path.exists(ssl_key_file) else None)

# יצירת DataFrame לצורך ניתוח
df = pd.DataFrame(flow_data, columns=["Mean Size", "Std Size", "Mean Inter-Arrival", "Std Inter-Arrival", "Total Packets", "Flow Entropy"])

# 🚀 קיבוץ K-Means
kmeans = KMeans(n_clusters=3, random_state=42)
df['Cluster'] = kmeans.fit_predict(df[["Mean Size", "Std Size", "Mean Inter-Arrival", "Std Inter-Arrival", "Total Packets", "Flow Entropy"]])

# 🎨 יצירת גרפים
plt.figure(figsize=(10, 5))
sns.histplot(df["Mean Size"], bins=20, kde=True)
plt.title("התפלגות גודל החבילות")
plt.xlabel("גודל חבילה (bytes)")
plt.ylabel("תדירות")
plt.show()

plt.figure(figsize=(10, 5))
sns.histplot(df["Mean Inter-Arrival"], bins=20, kde=True)
plt.title("התפלגות זמני הגעה בין חבילות")
plt.xlabel("זמן (שניות)")
plt.ylabel("תדירות")
plt.show()

# שמירת הנתונים
df.to_csv("flow_analysis_results.csv", index=False)
print("✅ ניתוח הושלם! הנתונים נשמרו בקובץ flow_analysis_results.csv")

import matplotlib
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np
from sklearn.cluster import KMeans
from scipy.stats import entropy

matplotlib.use('TkAgg')

# 📂 נתיב לקבצים
pcap_folder = './pcapfiles/'
ssl_keys_folder = './sslkeys/'  # 🔑 תיקייה לקובצי SSL Key Log

# רשימת מאפיינים שנאסוף
flow_data = []

# 🔍 פונקציה לניתוח קובץ PCAP עם קובץ SSL
def analyze_pcap(file_path, ssl_key_path=None):
    capture_options = {}
    if ssl_key_path and os.path.exists(ssl_key_path):
        capture_options['override_prefs'] = {'tls.keylog_file': ssl_key_path}

    cap = pyshark.FileCapture(file_path, **capture_options)

    packet_sizes = []
    packet_timestamps = []

    for packet in cap:
        if 'ip' in packet:
            packet_sizes.append(int(packet.length))
            packet_timestamps.append(float(packet.sniff_timestamp))

    if len(packet_sizes) > 1:
        mean_size = np.mean(packet_sizes)
        std_size = np.std(packet_sizes)
        inter_arrival_times = np.diff(packet_timestamps)
        mean_inter_arrival = np.mean(inter_arrival_times) if len(inter_arrival_times) > 0 else 0
        std_inter_arrival = np.std(inter_arrival_times) if len(inter_arrival_times) > 0 else 0
        total_packets = len(packet_sizes)
        packet_entropy = entropy(packet_sizes, base=2) if len(set(packet_sizes)) > 1 else 0

        flow_data.append([mean_size, std_size, mean_inter_arrival, std_inter_arrival, total_packets, packet_entropy])

# עיבוד כל קובצי ה-PCAP
for file in os.listdir(pcap_folder):
    if file.endswith('.pcap') or file.endswith('.pcapng'):
        app_name = file.split('.')[0]
        file_path = os.path.join(pcap_folder, file)
        ssl_key_file = os.path.join(ssl_keys_folder, f"{app_name}.log")

        print(f"🔍 Analyzing: {file}")
        analyze_pcap(file_path, ssl_key_file if os.path.exists(ssl_key_file) else None)

# יצירת DataFrame לצורך ניתוח
df = pd.DataFrame(flow_data, columns=["Mean Size", "Std Size", "Mean Inter-Arrival", "Std Inter-Arrival", "Total Packets", "Flow Entropy"])

# 🚀 קיבוץ K-Means
kmeans = KMeans(n_clusters=3, random_state=42)
df['Cluster'] = kmeans.fit_predict(df[["Mean Size", "Std Size", "Mean Inter-Arrival", "Std Inter-Arrival", "Total Packets", "Flow Entropy"]])

# 🎨 יצירת גרפים
plt.figure(figsize=(10, 5))
sns.histplot(df["Mean Size"], bins=20, kde=True)
plt.title("התפלגות גודל החבילות")
plt.xlabel("גודל חבילה (bytes)")
plt.ylabel("תדירות")
plt.show()

plt.figure(figsize=(10, 5))
sns.histplot(df["Mean Inter-Arrival"], bins=20, kde=True)
plt.title("התפלגות זמני הגעה בין חבילות")
plt.xlabel("זמן (שניות)")
plt.ylabel("תדירות")
plt.show()

# שמירת הנתונים
df.to_csv("flow_analysis_results.csv", index=False)
print("✅ ניתוח הושלם! הנתונים נשמרו בקובץ flow_analysis_results.csv")
