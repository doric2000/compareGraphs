import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler
import matplotlib
matplotlib.use('TkAgg')

# 📂 קריאת קובצי ה-CSV
csv_folder = './csv-files/'  # שנה לפי הנתיב שלך

# 🔍 קריאת כל קובצי התעבורה
results = {}
for file in os.listdir(csv_folder):
    if file.endswith('.csv'):
        file_path = os.path.join(csv_folder, file)
        app_name = os.path.splitext(file)[0]
        df = pd.read_csv(file_path)

        # שינוי שמות העמודות
        df.rename(columns={'Time': 'Timestamp', 'Length': 'Packet Size'}, inplace=True)

        # המרת Timestamp למספרים
        df['Timestamp'] = pd.to_numeric(df['Timestamp'], errors='coerce')

        # ניקוי נתונים חסרים
        df = df.dropna(subset=['Packet Size', 'Timestamp'])
        results[app_name] = df

# ✅ חישוב מאפיינים סטטיסטיים לכל אפליקציה
features = []
app_names = []
for app, df in results.items():
    packet_sizes = df['Packet Size']
    intervals = df['Timestamp'].diff().dropna()

    feature_vector = [
        packet_sizes.mean(),
        packet_sizes.std(),
        intervals.mean(),
        intervals.std(),
        len(packet_sizes),
        -sum((packet_sizes.value_counts() / len(packet_sizes)) * np.log2(
            packet_sizes.value_counts() / len(packet_sizes)))
    ]

    features.append(feature_vector)
    app_names.append(app)

# יצירת DataFrame של המאפיינים
feature_columns = ['avg_packet_size', 'std_packet_size', 'avg_interval', 'std_interval', 'num_packets', 'flow_entropy']
feature_df = pd.DataFrame(features, columns=feature_columns)

# ✅ נורמליזציה של הנתונים
scaler = StandardScaler()
X_scaled = scaler.fit_transform(feature_df)

# 📌 שימוש ב-Gaussian Mixture Model (GMM) לזיהוי סוגי תעבורה
num_clusters = 4  # נגדיר ידנית, אבל אפשר לחפש את המספר הטוב ביותר עם AIC/BIC
gmm = GaussianMixture(n_components=num_clusters, random_state=42)
gmm_labels = gmm.fit_predict(X_scaled)

# ✅ הוספת התוויות לטבלה
feature_df['Predicted Category'] = gmm_labels

# 📊 הצגת התוצאות
print("\n📊 זיהוי אוטומטי של סוגי תעבורה:")
print(feature_df)

# ✅ הדפסת ההתאמה בין אפליקציות לקטגוריות
for app, cluster in zip(app_names, gmm_labels):
    print(f"📡 {app} → Cluster {cluster}")

# 📈 הצגת הגרף של הקבוצות שנמצאו
plt.figure(figsize=(10, 6))
sns.scatterplot(x=feature_df['avg_packet_size'], y=feature_df['avg_interval'], hue=gmm_labels, palette='viridis', s=100)
plt.xlabel("Avg Packet Size")
plt.ylabel("Avg Inter-Arrival Time")
plt.title("Automatic Traffic Classification using GMM")
plt.legend(title="Predicted Cluster")
plt.grid(True)
plt.show()