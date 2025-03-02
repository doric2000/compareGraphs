"""
AppDetector.py
--------------
This script demonstrates how to:

1) Load multiple CSV files, each representing network traffic data.
2) Extract key numerical features (average packet size, intervals, burstiness, etc.).
3) Apply a basic rule-based classification to assign each CSV a 'Traffic_Type'.
4) Train and evaluate a Random Forest classifier based on these features.
5) Display a single scatter plot of (avg_packet_size vs avg_interval) with color-coded classes.

HOW TO RUN:
    python AppDetector.py

ASSUMPTIONS:
    - Each CSV has 'Time' or 'Timestamp' for timestamps,
      and 'Length' or 'Packet Size' for packet sizes.
    - The user placed these CSVs in a subfolder called './csv-files'.
    - This is a single-run script (not iterating 100 times).
"""

import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Scikit-learn imports for ML
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score


def load_csv_files(csv_folder):
    """
    Scans the given 'csv_folder' for all .csv files.
    Loads them into memory as Pandas DataFrames, performing minor cleanup:
    1) Renames columns 'Time' -> 'Timestamp' and 'Length' -> 'Packet Size' if they exist.
    2) Converts 'Timestamp' to numeric (float) if possible.
    3) Drops rows with missing timestamps or packet sizes.

    Returns:
        results (dict): A dictionary mapping 'app_name' (derived from filename) -> DataFrame.
    """
    results = {}
    for file in os.listdir(csv_folder):
        if file.endswith('.csv'):
            file_path = os.path.join(csv_folder, file)
            app_name = os.path.splitext(file)[0]  # e.g., 'Video-Streaming', 'web-surfing'

            df = pd.read_csv(file_path)
            # Rename columns if found
            if 'Time' in df.columns:
                df.rename(columns={'Time': 'Timestamp'}, inplace=True)
            if 'Length' in df.columns:
                df.rename(columns={'Length': 'Packet Size'}, inplace=True)

            # Ensure numeric Timestamps / drop missing
            if 'Timestamp' in df.columns:
                df['Timestamp'] = pd.to_numeric(df['Timestamp'], errors='coerce')
            if 'Packet Size' in df.columns:
                df.dropna(subset=['Timestamp', 'Packet Size'], inplace=True)

            results[app_name] = df
    return results


def extract_features(results):
    """
    Receives a dict {app_name: DataFrame}, where each DataFrame holds
    network traffic data for that 'app_name'.

    For each DataFrame, it calculates numeric features such as:
      - avg_packet_size
      - std_packet_size
      - avg_interval
      - std_interval
      - num_packets
      - flow_entropy
      - flow_duration
      - burstiness

    Returns:
        feature_df (pd.DataFrame):
            rows = different CSV apps,
            columns = numeric features above.
    """
    feature_list = []
    app_names = []

    for app_name, df in results.items():
        # Skip if no Packet Size data
        if 'Packet Size' not in df.columns or len(df) < 1:
            continue

        packet_sizes = df['Packet Size']
        intervals = df['Timestamp'].diff().dropna()

        avg_pkt = packet_sizes.mean()
        std_pkt = packet_sizes.std(ddof=0)
        avg_int = intervals.mean() if len(intervals) > 0 else 0.0
        std_int = intervals.std(ddof=0) if len(intervals) > 0 else 0.0
        num_packets = len(packet_sizes)

        # Compute flow entropy
        probs = packet_sizes.value_counts(normalize=True, dropna=True)
        flow_entropy = -np.sum(probs * np.log2(probs))

        # Compute duration
        if len(df) > 1:
            flow_duration = df['Timestamp'].max() - df['Timestamp'].min()
        else:
            flow_duration = 0.0

        # Compute burstiness
        if len(intervals) > 1 and avg_int != 0:
            burstiness = std_int / avg_int
        else:
            burstiness = 0.0

        # Build the feature vector
        feature_vector = [
            avg_pkt,
            std_pkt,
            avg_int,
            std_int,
            num_packets,
            flow_entropy,
            flow_duration,
            burstiness
        ]

        app_names.append(app_name)
        feature_list.append(feature_vector)

    feature_columns = [
        'avg_packet_size',
        'std_packet_size',
        'avg_interval',
        'std_interval',
        'num_packets',
        'flow_entropy',
        'flow_duration',
        'burstiness'
    ]

    feature_df = pd.DataFrame(feature_list, columns=feature_columns, index=app_names)
    return feature_df


def classify_traffic(feature_df):
    """
    Applies a simple rule-based classification to each row (flow),
    creating a new column 'Traffic_Type' that we then use for
    training / classification checks.

    Example rules:
        1) Video Streaming if avg_packet_size > 4000
        2) Video Calls if avg_packet_size < 800 and avg_interval < 0.1
        3) Audio Streaming if avg_packet_size < 1200
        4) Otherwise, Web Browsing
    """

    def classify_row(row):
        avg_pkt = row['avg_packet_size']
        avg_int = row['avg_interval']
        # We can use more fields if we want (like std_interval, num_packets, etc.)

        # Basic thresholds
        if avg_pkt > 4000:
            return "Video Streaming"
        elif avg_pkt < 800 and avg_int < 0.1:
            return "Video Calls"
        elif avg_pkt < 1200:
            return "Audio Streaming"
        else:
            return "Web Browsing"

    feature_df['Traffic_Type'] = feature_df.apply(classify_row, axis=1)
    return feature_df


def train_model(feature_df, rf_model=None, scaler=None):
    """
    Fits a RandomForestClassifier on the numeric columns in feature_df,
    ignoring the 'Traffic_Type' column.
    After training, returns the updated model, the scaler, and the test data info.

    Steps:
      1) Drop 'Traffic_Type' from feature_df => X
      2) y = feature_df['Traffic_Type']
      3) Scale numeric features using StandardScaler
      4) Remove classes with <2 samples if needed
      5) Split data into train/test sets (test_size=0.3), random_state=42
      6) Fit or update the existing rf_model on X_train, y_train
      7) Predict on X_test => y_pred

    Returns:
        rf_model (RandomForestClassifier): the updated model
        scaler (StandardScaler): the updated/created scaler
        X_test (np.array), y_test (Series), y_pred (np.array)
    """
    if 'Traffic_Type' not in feature_df.columns:
        raise ValueError("Missing 'Traffic_Type' column; run classify_traffic first.")

    # Separate features from label
    X = feature_df.drop(columns=['Traffic_Type'])
    y = feature_df['Traffic_Type']

    # Scale
    if scaler is None:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
    else:
        X_scaled = scaler.transform(X)

    # Remove categories with < 2 samples
    class_counts = y.value_counts()
    min_samples_per_class = class_counts.min()
    if min_samples_per_class < 2:
        valid_labels = class_counts[class_counts >= 2].index
        mask = y.isin(valid_labels)
        y = y[mask]
        X_scaled = X_scaled[mask]

    # We do not use stratify to avoid errors if certain classes have too few samples
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)

    # Initialize the model if none is provided
    if rf_model is None:
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42)

    # Fit the model
    rf_model.fit(X_train, y_train)

    # Predict
    y_pred = rf_model.predict(X_test)

    return rf_model, scaler, X_test, y_test, y_pred


def visualize_traffic(feature_df):
    """
    Plots a single scatter plot of (avg_packet_size vs avg_interval),
    coloring points by the 'Traffic_Type' we assigned.

    This is the final, single-run graph,
    so you can see how the flows are distributed.
    """
    plt.figure(figsize=(10, 6))
    sns.scatterplot(
        data=feature_df,
        x='avg_packet_size',
        y='avg_interval',
        hue='Traffic_Type',
        s=100
    )
    plt.title("Traffic Classification - Single Final Graph")
    plt.xlabel("Avg Packet Size (bytes)")
    plt.ylabel("Avg Inter-Arrival Time (s)")
    plt.legend(title="Traffic Type", bbox_to_anchor=(1.02, 1), loc='upper left')
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    # Folder where your CSVs are placed
    csv_folder = "./csv-files"

    # 1) Load CSVs
    results = load_csv_files(csv_folder)
    if not results:
        print("No CSV files found.")
        exit()

    # 2) Extract numeric features
    feature_df = extract_features(results)
    if feature_df.empty:
        print("No valid data found in CSVs.")
        exit()

    # 3) Basic classification (rule-based) to set 'Traffic_Type'
    feature_df = classify_traffic(feature_df)

    # 4) Train the model once
    rf_model, scaler, X_test, y_test, y_pred = train_model(feature_df)

    # 5) Print final classification + show a single scatter plot
    print("\n=== FINAL CLASSIFICATION (SINGLE RUN) ===")
    print(feature_df)
    visualize_traffic(feature_df)
