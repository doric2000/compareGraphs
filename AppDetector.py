import pandas as pd
import os
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

# 📂 נתיב לתיקיית ה-CSV
csv_folder = './csv-files/'

# 🔍 קריאת כל קובצי ה-CSV
results = {}
for file in os.listdir(csv_folder):
    if file.endswith('.csv'):
        file_path = os.path.join(csv_folder, file)
        app_name = os.path.splitext(file)[0]
        df = pd.read_csv(file_path)

        # ניקוי נתונים חסרים
        df = df.dropna(subset=['Packet Size', 'Timestamp'])

        results[app_name] = df

# 🎨 צבעים ייחודיים לכל אפליקציה
colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

# ✅ חישוב מאפיינים סטטיסטיים לכל אפליקציה
features = {}
for app, df in results.items():
    packet_sizes = df['Packet Size']
    intervals = df['Timestamp'].diff().dropna()

    features[app] = {
        'avg_packet_size': packet_sizes.mean(),
        'std_packet_size': packet_sizes.std(),
        'avg_interval': intervals.mean(),
        'std_interval': intervals.std(),
        'num_packets': len(packet_sizes),
        'flow_entropy': -sum((packet_sizes.value_counts() / len(packet_sizes)) * np.log2(
            packet_sizes.value_counts() / len(packet_sizes)))
    }

# יצירת DataFrame מהמאפיינים
feature_df = pd.DataFrame(features).T

#  הצגת מאפיינים בטבלה
print("Network Traffic Features:")
print(feature_df.head())  # מדפיס את חמש השורות הראשונות

# ✅ ניתוח אשכולות (Clustering) לזיהוי אפליקציות
scaler = StandardScaler()
X = scaler.fit_transform(feature_df)
kmeans = KMeans(n_clusters=len(results), random_state=42, n_init=10)
clusters = kmeans.fit_predict(X)
feature_df['Cluster'] = clusters

# 📈 גרף להצגת חלוקת האפליקציות לפי אשכולות
plt.figure(figsize=(10, 6))
sns.scatterplot(x=feature_df['avg_packet_size'], y=feature_df['avg_interval'], hue=clusters, palette='viridis', s=100)
plt.xlabel("Avg Packet Size")
plt.ylabel("Avg Inter-Arrival Time")
plt.title("Clustering of Applications Based on Traffic Features")
plt.legend(title="Cluster")
plt.grid(True)
plt.show()


# ✅ יצירת גרפים להשוואת תבניות
def plot_packet_size_distribution():
    plt.figure(figsize=(14, 7))
    for idx, (app, df) in enumerate(results.items()):
        sns.histplot(df['Packet Size'], bins=50, kde=True, label=app, color=colors[idx % len(colors)], alpha=0.6)
    plt.title("Packet Size Distribution by App")
    plt.xlabel("Packet Size (Bytes)")
    plt.ylabel("Frequency")
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.show()


def plot_packet_inter_arrival():
    plt.figure(figsize=(14, 7))
    for idx, (app, df) in enumerate(results.items()):
        intervals = df['Timestamp'].diff().dropna()
        sns.kdeplot(intervals, label=app, fill=True, color=colors[idx % len(colors)])
    plt.title("Packet Inter-Arrival Time Distribution by App")
    plt.xlabel("Inter-arrival Time (s)")
    plt.ylabel("Density")
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.show()


# 📊 הפעלת כל הגרפים
plot_packet_size_distribution()
plot_packet_inter_arrival()
