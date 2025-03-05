"""
stream_type_detector.py
--------------
This script demonstrates how to:

1) Load multiple CSV files, each representing network traffic data.
2) Extract key numerical features (average packet size, intervals, burstiness, etc.).
3) Apply a basic rule-based classification to assign each CSV a 'Traffic_Type'.
4) Train and evaluate a Random Forest classifier based on these features.
5) Display a scatter plot of (avg_packet_size vs avg_interval) with color-coded classes.

HOW TO RUN:
    python stream_type_detector.py

ASSUMPTIONS:
    - Each CSV has 'Time' or 'Timestamp' for timestamps,
      and 'Length' or 'Packet Size' for packet sizes.
    - The user placed these CSVs in a subfolder called './csv-files'.
    - This version limits analysis to what an attacker would know based on:
      * Packet size
      * Timestamps
      * Inter-arrival time (computed)
      * Burstiness (computed from intervals)
"""

import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import matplotlib

# Set TkAgg as the backend to display plots in certain environments (especially in PyCharm)
matplotlib.use('TkAgg')

# Function to load CSV files from a specified directory
def load_csv_files(csv_folder):
    """
    Loads all CSV files from the specified folder.
    It renames columns for consistency and cleans missing values.
    """
    results = {}
    for file in os.listdir(csv_folder):
        if file.endswith('.csv'):
            file_path = os.path.join(csv_folder, file)
            app_name = os.path.splitext(file)[0]
            df = pd.read_csv(file_path)

            # Rename columns to a standard format
            df.rename(columns={'Time': 'Timestamp', 'Length': 'Packet Size'}, inplace=True)

            # Convert timestamp to numeric values and drop missing data
            df['Timestamp'] = pd.to_numeric(df['Timestamp'], errors='coerce')
            df = df.dropna(subset=['Timestamp', 'Packet Size'])

            results[app_name] = df
    return results

# Function to extract relevant features from network traffic data
def extract_features(results):
    """
    Extracts statistical features from each traffic flow, including:
    - Average and standard deviation of packet sizes
    - Inter-packet time intervals
    - Burstiness
    """
    feature_list, app_names = [], []
    for app, df in results.items():
        packet_sizes = df['Packet Size']
        timestamps = df['Timestamp']
        intervals = timestamps.diff().dropna()  # Compute inter-arrival times

        # Statistical calculations
        avg_pkt = packet_sizes.mean()
        std_pkt = packet_sizes.std()
        max_pkt = packet_sizes.max()
        min_pkt = packet_sizes.min()

        avg_int = intervals.mean() if len(intervals) > 0 else 0.0
        std_int = intervals.std() if len(intervals) > 0 else 0.0

        burstiness = std_int / avg_int if avg_int != 0 else 0.0  # Measures traffic burstiness

        feature_vector = [avg_pkt, std_pkt, max_pkt, min_pkt, avg_int, std_int, burstiness]
        feature_list.append(feature_vector)
        app_names.append(app)

    # Define feature column names
    feature_columns = ['avg_packet_size', 'std_packet_size', 'max_packet_size', 'min_packet_size',
                       'avg_interval', 'std_interval', 'burstiness']

    return pd.DataFrame(feature_list, columns=feature_columns, index=app_names)

# Rule-based classification function
def classify_traffic(feature_df):
    """
    Classifies traffic using basic rule-based logic based on:
    - Packet size
    - Inter-arrival time
    """
    def classify_row(row):
        avg_pkt = row['avg_packet_size']
        avg_int = row['avg_interval']
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

# Function to train a Random Forest model for classification
def train_model(feature_df):
    """
    Trains a Random Forest model to classify network traffic automatically.
    """
    if 'Traffic_Type' not in feature_df.columns:
        raise ValueError("Missing 'Traffic_Type' column; run classify_traffic first.")

    X = feature_df.drop(columns=['Traffic_Type'])
    y = feature_df['Traffic_Type']

    # Remove categories with less than 2 occurrences
    min_samples_required = 2
    valid_classes = y.value_counts()
    valid_classes = valid_classes[valid_classes >= min_samples_required].index
    feature_df = feature_df[feature_df['Traffic_Type'].isin(valid_classes)]

    # Normalize the features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(feature_df.drop(columns=['Traffic_Type']))
    y = feature_df['Traffic_Type']

    # Ensure all categories appear in both training and test sets
    if len(y.unique()) > 1:
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, stratify=y, random_state=42
        )
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42
        )

    # Train the Random Forest model
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)
    y_pred = rf_model.predict(X_test)

    return rf_model, scaler, X_train, X_test, y_train, y_test, y_pred

# Function to visualize classification results
def visualize_traffic(feature_df):
    """
    Generates a scatter plot of average packet size vs. average inter-arrival time.
    """
    plt.figure(figsize=(10, 6))
    sns.scatterplot(
        data=feature_df,
        x='avg_packet_size',
        y='avg_interval',
        hue='Traffic_Type',
        s=100
    )
    plt.title("Traffic Classification - Updated for Attacker Model")
    plt.xlabel("Avg Packet Size (bytes)")
    plt.ylabel("Avg Inter-Arrival Time (s)")
    plt.legend(title="Traffic Type", bbox_to_anchor=(1.02, 1), loc='upper left')
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', 1000)
    csv_folder = "./csv-files"

    results = load_csv_files(csv_folder)
    if not results:
        print("No CSV files found.")
        exit()

    feature_df = extract_features(results)
    if feature_df.empty:
        print("No valid data found in CSVs.")
        exit()

    feature_df = classify_traffic(feature_df)
    rf_model, scaler, X_train, X_test, y_train, y_test, y_pred = train_model(feature_df)

    print("\n=== FINAL CLASSIFICATION (SINGLE RUN) ===")
    print(feature_df)

    visualize_traffic(feature_df)

    print("\n=== CLASSIFICATION REPORT ===")
    print(classification_report(y_test, y_pred, zero_division=1))

    print("\n=== ACCURACY SCORE ===")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")
