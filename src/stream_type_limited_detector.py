"""
two_column_detector.py
----------------------
This script processes CSV files containing only:
    Time, Length
Each CSV is treated as one "flow." For each CSV, it computes:
  - avg_packet_size, std_packet_size, max_packet_size
  - avg_interval, std_interval, burstiness (std_interval/avg_interval)
It then:
  1) Extracts a true label from the CSV file name.
  2) Trains a Random Forest classifier using Leave-One-Out Cross-Validation (LOOCV)
     so that every CSV file (flow) is used for testi`ng exactly once.
  3) Prints a custom classification report showing precision, recall, and support (without f1-score, macro avg, or weighted avg)
     and overall accuracy.
  4) Displays a scatter plot of (avg_packet_size vs. avg_interval) color-coded by the true label.

HOW TO RUN:
    python two_column_detector.py

REQUIREMENTS:
    pip install pandas numpy matplotlib seaborn scikit-learn
"""

import os
import numpy as np
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import LeaveOneOut, cross_val_predict

# Set backend if needed and use a clean style
matplotlib.use('TkAgg')
sns.set_style('whitegrid')


def load_csv_files(csv_folder):
    """
    Loads CSV files from `csv_folder` that contain at least:
      Time, Length
    Renames 'Time' -> 'Timestamp' and 'Length' -> 'Packet Size'.
    Returns a dict: {filename: DataFrame}.
    """
    results = {}
    for file in os.listdir(csv_folder):
        if file.endswith('.csv'):
            file_path = os.path.join(csv_folder, file)
            try:
                df = pd.read_csv(file_path)
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                continue

            # Robustly find and rename columns (case-insensitive, stripped)
            col_map = {c.strip().lower(): c for c in df.columns}
            time_col = None
            length_col = None
            for c in df.columns:
                cl = c.strip().lower()
                if cl == 'time':
                    time_col = c
                elif cl == 'length':
                    length_col = c
            if not time_col or not length_col:
                print(f"Skipping {file}: missing Time or Length column.")
                continue

            df.rename(columns={time_col: 'Timestamp', length_col: 'Packet Size'}, inplace=True)
            df['Timestamp'] = pd.to_numeric(df['Timestamp'], errors='coerce')
            df = df.dropna(subset=['Timestamp', 'Packet Size'])
            if df.empty:
                print(f"Skipping {file}: no valid data after cleaning.")
                continue
            results[file] = df
    return results


def extract_features(results):
    """
    Treat each CSV file as one "flow."
    For each file, compute:
      - avg_packet_size, std_packet_size, max_packet_size
      - avg_interval, std_interval, burstiness (std_interval/avg_interval)
    Returns a DataFrame with one row per CSV (indexed by filename).
    """
    rows = []
    for file_name, df in results.items():
        df = df.sort_values('Timestamp')
        sizes = df['Packet Size']
        timestamps = df['Timestamp']
        intervals = timestamps.diff().dropna()

        avg_pkt = sizes.mean()
        std_pkt = sizes.std()
        max_pkt = sizes.max()
        avg_int = intervals.mean() if not intervals.empty else 0.0
        std_int = intervals.std() if not intervals.empty else 0.0
        burstiness = std_int / avg_int if avg_int != 0 else 0.0

        rows.append({
            'File': file_name,
            'avg_packet_size': avg_pkt,
            'std_packet_size': std_pkt,
            'max_packet_size': max_pkt,
            'avg_interval': avg_int,
            'std_interval': std_int,
            'burstiness': burstiness
        })

    feature_df = pd.DataFrame(rows)
    feature_df.set_index('File', inplace=True)
    return feature_df


def extract_true_labels(feature_df):
    """
    Extracts the true traffic label from the CSV file name.
    For example, if the file name contains "video-streaming", the label is "Video Streaming".
    Adjust the keywords as needed.
    """
    true_labels = []
    for file_name in feature_df.index:
        lower_name = file_name.lower()
        if "video streaming" in lower_name or "video-streaming" in lower_name:
            true_labels.append("Video Streaming")
        elif "video call" in lower_name or "video-conferencing" in lower_name:
            true_labels.append("Video Calls")
        elif "audio streaming" in lower_name or "audio-streaming" in lower_name:
            true_labels.append("Audio Streaming")
        elif "web browsing" in lower_name or "web-surfing" in lower_name:
            true_labels.append("Web Browsing")
        else:
            true_labels.append("Unknown")
    feature_df['True_Label'] = true_labels
    return feature_df


def print_custom_classification_report(y_true, y_pred):
    """
    Prints a custom classification report displaying only precision, recall, and support for each class.
    """
    report_dict = classification_report(y_true, y_pred, zero_division=1, output_dict=True)

    # Remove macro avg and weighted avg entries
    keys_to_remove = ['macro avg', 'weighted avg']
    for key in keys_to_remove:
        if key in report_dict:
            del report_dict[key]

    # Prepare header
    header = f"{'Class':<20}{'Precision':>10}{'Recall':>10}{'Support':>10}"
    print(header)
    print("-" * len(header))

    # For each class, print the metrics (without f1-score)
    for class_label, metrics in report_dict.items():
        # For "accuracy", the report dict returns a float; we skip that entry.
        if class_label == "accuracy":
            continue
        precision = metrics.get("precision", 0)
        recall = metrics.get("recall", 0)
        support = metrics.get("support", 0)
        print(f"{class_label:<20}{precision:10.2f}{recall:10.2f}{support:10.0f}")


def train_model(feature_df):
    """
    Trains a Random Forest classifier using Leave-One-Out Cross-Validation (LOOCV).
    Uses the following features:
      avg_packet_size, std_packet_size, max_packet_size,
      avg_interval, std_interval, burstiness
    Ground truth labels are taken from the 'True_Label' column.
    Prints a custom classification report (without macro, weighted, and f1-score) and overall accuracy.
    Returns the trained model, scaler, and LOOCV predictions.
    """
    if 'True_Label' not in feature_df.columns:
        raise ValueError("Missing 'True_Label' column; run extract_true_labels first.")

    feature_cols = ['avg_packet_size', 'std_packet_size', 'max_packet_size',
                    'avg_interval', 'std_interval', 'burstiness']
    X = feature_df[feature_cols]
    y = feature_df['True_Label']

    # Normalize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    # Using LOOCV
    from sklearn.model_selection import LeaveOneOut, cross_val_predict
    loo = LeaveOneOut()
    y_pred = cross_val_predict(rf_model, X_scaled, y, cv=loo)

    print("\n=== CLASSIFICATION REPORT (LIMITED DATA) ===")
    print_custom_classification_report(y, y_pred)
    print(f"\nAccuracy: {accuracy_score(y, y_pred):.2f}")

    # Optionally, train on full data after evaluation
    rf_model.fit(X_scaled, y)

    return rf_model, scaler, X_scaled, y, y_pred


def visualize_traffic(feature_df):
    """
    Generates a scatter plot of avg_packet_size vs. avg_interval, color-coded by True_Label.
    """
    plt.figure(figsize=(10, 6))
    sns.scatterplot(
        data=feature_df,
        x='avg_packet_size',
        y='avg_interval',
        hue='True_Label',
        s=100
    )
    plt.title("Traffic Classification by CSV File")
    plt.xlabel("Avg Packet Size (bytes)")
    plt.ylabel("Avg Inter-Arrival Time (s)")
    plt.legend(title="True Label", bbox_to_anchor=(1.02, 1), loc='upper left')
    plt.tight_layout()
    plt.show()


###############################################################################
#                                   MAIN
###############################################################################

if __name__ == "__main__":
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', 1000)

    csv_folder = "../res/csv-files-encrypted"

    # 1) Load CSV files (only Time, Length)
    results = load_csv_files(csv_folder)
    if not results:
        print("No valid CSV files found (must contain Time, Length).")
        exit()

    # 2) Extract features (one sample per CSV)
    feature_df = extract_features(results)
    if feature_df.empty:
        print("No valid data extracted from CSVs.")
        exit()

    # 3) Extract true labels from the file names
    feature_df = extract_true_labels(feature_df)

    # 4) Train Random Forest using LOOCV and print custom classification report
    try:
        rf_model, scaler, X_scaled, y, y_pred = train_model(feature_df)
    except ValueError as e:
        print(f"Could not train Random Forest: {e}")
        exit()

    # 5) Visualize the results
    visualize_traffic(feature_df)
