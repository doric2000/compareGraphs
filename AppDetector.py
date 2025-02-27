import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
import matplotlib

# ✅ הגדרת backend ל-TkAgg
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

# ✅ טבלת אפליקציות מוכרות
known_apps = {
    "Zoom": "Video Conferencing",
    "Skype": "Video Conferencing",
    "Netflix": "Video Streaming",
    "YouTube": "Video Streaming",
    "Spotify": "Audio Streaming",
    "Apple Music": "Audio Streaming",
    "Chrome": "Web Browsing",
    "Firefox": "Web Browsing",
    "WhatsApp": "Messaging",
    "Telegram": "Messaging"
}

# ✅ חישוב מאפיינים סטטיסטיים לכל הקלטה
features = []
app_labels = []
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

    # ✅ אם שם האפליקציה קיים בטבלת האפליקציות הידועות - נשתמש בו
    detected_category = "Unknown"
    for known_app, category in known_apps.items():
        if known_app.lower() in app.lower():
            detected_category = category
            break
    app_labels.append(detected_category)

# יצירת DataFrame של המאפיינים
feature_columns = ['avg_packet_size', 'std_packet_size', 'avg_interval', 'std_interval', 'num_packets', 'flow_entropy']
feature_df = pd.DataFrame(features, columns=feature_columns)

# ✅ נורמליזציה של הנתונים
scaler = StandardScaler()
X_scaled = scaler.fit_transform(feature_df)

# ✅ אימון מודל KNN עם הקלטות ידועות בלבד
train_X = []
train_y = []
for i, label in enumerate(app_labels):
    if label != "Unknown":
        train_X.append(X_scaled[i])
        train_y.append(label)

knn = KNeighborsClassifier(n_neighbors=3)
knn.fit(train_X, train_y)  # אימון KNN על הדאטה עם אפליקציות ידועות

# ✅ חיזוי האפליקציה לכל הקלטה
predicted_categories = knn.predict(X_scaled)
feature_df['Predicted App'] = predicted_categories  # הוספת עמודת התאמה

# 📊 **הצגת תוצאות הסיווג**
print("\n✅ Automatic Matching of Recordings to Apps:")
print(feature_df[['avg_packet_size', 'avg_interval', 'Predicted App']])

# ✅ 1️⃣ גרף של הקבוצות שנמצאו עם שמות האפליקציות הקרובות
plt.figure(figsize=(10, 6))
sns.scatterplot(x=feature_df['avg_packet_size'], y=feature_df['avg_interval'], hue=predicted_categories, palette='viridis', s=100)
plt.xlabel("Avg Packet Size")
plt.ylabel("Avg Inter-Arrival Time")
plt.title("Automatic Traffic Classification by Closest App")
plt.legend(title="Predicted App")
plt.grid(True)
plt.show()

# ✅ 2️⃣ **התפלגות גודל החבילות - היסטוגרמה**
plt.figure(figsize=(14, 7))
bins = np.logspace(np.log10(50), np.log10(1600), 50)

for idx, (app, df) in enumerate(results.items()):
    packet_sizes = df['Packet Size']
    packet_sizes = packet_sizes[(packet_sizes >= 50) & (packet_sizes <= 1600)]  # ✅ סינון ערכים קיצוניים
    sns.histplot(packet_sizes, bins=bins, label=app, color=f"C{idx}", alpha=0.6)

plt.title("Packet Size Histogram by App")
plt.xlabel("Packet Size (Bytes)")
plt.ylabel("Frequency")
plt.xscale("log")
plt.legend()
plt.grid(True, linestyle='--', alpha=0.6)
plt.show()

# ✅ **מציאת ערך ה-Y המקסימלי לכל הגרפים**
max_density = 0
densities = {}

for app, df in results.items():
    intervals = df['Timestamp'].diff().dropna()
    intervals = intervals[(intervals > 1e-4) & (intervals < 2)]  # ✅ סינון ערכים קיצוניים

    fig, ax = plt.subplots()
    kde = sns.kdeplot(intervals, bw_adjust=1.5, ax=ax)
    y_max = ax.get_ylim()[1]
    densities[app] = y_max
    max_density = max(max_density, y_max)
    plt.close(fig)

# ✅ **הגדלת `ylim` ב-20% כדי למנוע חיתוכים**
global_ylim = max_density * 1.2

# ✅ **יצירת גרפים נפרדים לכל אפליקציה עם `ylim` אחיד**
num_apps = len(results)
fig, axes = plt.subplots(nrows=num_apps, ncols=1, figsize=(14, 4 * num_apps), sharex=True, sharey=True)

for idx, (app, df) in enumerate(results.items()):
    intervals = df['Timestamp'].diff().dropna()
    intervals = intervals[(intervals > 1e-4) & (intervals < 2)]  # ✅ סינון ערכים קיצוניים

    sns.kdeplot(intervals, fill=True, alpha=0.4, color=f"C{idx}", bw_adjust=1.5, ax=axes[idx])
    sns.kdeplot(intervals, color='black', linewidth=1, bw_adjust=1.5, ax=axes[idx])  # ✅ קווי מתאר לשיפור הקריאות

    axes[idx].set_title(f"{app} - Packet Inter-Arrival Time KDE")
    axes[idx].set_ylabel("Density")
    axes[idx].set_ylim(0, global_ylim)  # ✅ שימוש במקסימום שחושב מראש
    axes[idx].grid(True, linestyle='--', alpha=0.6)

# ✅ שיתוף ציר ה-X לכל הגרפים
axes[-1].set_xlabel("Inter-arrival Time (s)")
plt.xscale("log")
plt.tight_layout()
plt.show()
