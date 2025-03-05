"""
stream_type_detector.py
------------------------
This script loads network traffic CSV files that contain columns like:
    No., Time, Source, Destination, Protocol, Length, Info
(and potentially others). It then:
  1) Robustly renames columns to a canonical form:
        No, Timestamp, Source, Destination, Protocol, Packet Size, Info
  2) Parses Source and Destination to extract IP and Port.
  3) Computes a hashed Flow ID (4-tuple + Protocol).
  4) Groups packets by Flow ID to extract per-flow features.
  5) Classifies flows using a rule-based approach and a Random Forest.
  6) Displays a scatter plot (avg_packet_size vs. avg_interval) color-coded by the final class.

HOW TO RUN:
    python stream_type_detector.py

REQUIREMENTS:
    pip install pandas numpy matplotlib seaborn scikit-learn
"""

import os
import hashlib
import numpy as np
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# If you have issues displaying plots, you can use a specific backend like TkAgg:
matplotlib.use('TkAgg')
sns.set_style('whitegrid')


###############################################################################
#                           HELPER FUNCTIONS
###############################################################################

def robust_rename_columns(df):
    """
    Renames columns by stripping whitespace and converting them to a canonical form.
    Expected mappings (case-insensitive):
      - 'no.'         -> 'No'
      - 'time'        -> 'Timestamp'
      - 'length'      -> 'Packet Size'
      - 'source'      -> 'Source'
      - 'destination' -> 'Destination'
      - 'protocol'    -> 'Protocol'
      - 'info'        -> 'Info'
    All other columns remain in the DataFrame with their stripped names.
    """
    expected_mapping = {
        'no.': 'No',
        'time': 'Timestamp',
        'length': 'Packet Size',
        'source': 'Source',
        'destination': 'Destination',
        'protocol': 'Protocol',
        'info': 'Info'
    }

    new_cols = []
    for col in df.columns:
        cleaned = col.strip().lower()
        new_name = expected_mapping.get(cleaned, col.strip())
        new_cols.append(new_name)

    df.columns = new_cols
    return df


def parse_ip_port(addr):
    """
    Parses an address string (e.g. "192.168.1.10:443") into (ip, port).
    If no port is found, returns (addr, None).
    """
    if not isinstance(addr, str):
        return (None, None)
    addr = addr.strip()
    idx = addr.rfind(':')
    if idx == -1:
        return (addr, None)
    else:
        ip_part = addr[:idx].strip()
        port_part = addr[idx+1:].strip()
        if port_part.isdigit():
            return (ip_part, port_part)
        else:
            return (addr, None)


def compute_flow_id(row):
    """
    Computes a hash-based Flow ID from:
      - src_ip, src_port, dst_ip, dst_port, Protocol
    Returns a 10-character uppercase hex string if all are present.
    """
    src_ip = row.get('src_ip')
    src_port = row.get('src_port')
    dst_ip = row.get('dst_ip')
    dst_port = row.get('dst_port')
    protocol = row.get('Protocol')

    if (not src_ip) or (not dst_ip) or (not protocol):
        return None

    # Use empty string if a port is missing
    if src_port is None:
        src_port = ''
    if dst_port is None:
        dst_port = ''

    tuple_str = f"{src_ip}_{src_port}_{dst_ip}_{dst_port}_{protocol}"
    return hashlib.sha256(tuple_str.encode()).hexdigest()[:10].upper()


###############################################################################
#                       MAIN PROCESSING FUNCTIONS
###############################################################################

def load_csv_files(csv_folder):
    """
    Loads CSV files from `csv_folder`.
    After robust renaming, we require:
      Timestamp, Source, Destination, Protocol, Packet Size
    If any of these are missing, we skip that file.
    Returns {filename: DataFrame} for valid files.
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

            # Rename columns robustly
            df = robust_rename_columns(df)

            # Ensure essential columns exist
            needed_cols = ['Timestamp', 'Source', 'Destination', 'Protocol', 'Packet Size']
            if not all(col in df.columns for col in needed_cols):
                print(f"Skipping {file}: missing essential columns.")
                continue

            # Convert Timestamp to numeric
            df['Timestamp'] = pd.to_numeric(df['Timestamp'], errors='coerce')
            df = df.dropna(subset=needed_cols)

            # Parse Source & Destination
            df[['src_ip', 'src_port']] = df['Source'].apply(lambda x: pd.Series(parse_ip_port(x)))
            df[['dst_ip', 'dst_port']] = df['Destination'].apply(lambda x: pd.Series(parse_ip_port(x)))

            # Compute Flow ID
            df['Flow_ID'] = df.apply(compute_flow_id, axis=1)
            df = df.dropna(subset=['Flow_ID'])
            if df.empty:
                print(f"Skipping {file}: no valid Flow_ID computed.")
                continue

            results[file] = df
    return results


def extract_features(results):
    """
    Groups packets by Flow_ID and computes per-flow features:
      - avg_packet_size, std_packet_size, max_packet_size
      - avg_interval, std_interval, burstiness (std_interval/avg_interval)
      - flow_duration, packet_count
      - protocol (most frequent in the flow)
    Returns a DataFrame with one row per flow, indexed by Flow_ID.
    """
    feature_rows = []
    for file_name, df in results.items():
        grouped = df.groupby('Flow_ID')
        for flow_id, group in grouped:
            group = group.sort_values('Timestamp')
            sizes = group['Packet Size']
            timestamps = group['Timestamp']
            intervals = timestamps.diff().dropna()

            avg_pkt = sizes.mean()
            std_pkt = sizes.std()
            max_pkt = sizes.max()
            avg_int = intervals.mean() if not intervals.empty else 0.0
            std_int = intervals.std() if not intervals.empty else 0.0
            burstiness = std_int / avg_int if avg_int != 0 else 0.0
            flow_duration = (timestamps.iloc[-1] - timestamps.iloc[0]) if len(timestamps) > 1 else 0.0
            packet_count = len(group)
            protocol = group['Protocol'].value_counts().idxmax()

            feature_rows.append({
                'Flow_ID': flow_id,
                'avg_packet_size': avg_pkt,
                'std_packet_size': std_pkt,
                'max_packet_size': max_pkt,
                'avg_interval': avg_int,
                'std_interval': std_int,
                'burstiness': burstiness,
                'flow_duration': flow_duration,
                'packet_count': packet_count,
                'protocol': protocol,
                'Source_File': file_name
            })

    feature_df = pd.DataFrame(feature_rows)
    if not feature_df.empty:
        feature_df.set_index('Flow_ID', inplace=True)
    return feature_df


def classify_traffic(feature_df):
    """
    Basic rule-based classification for each flow, based on:
      - avg_packet_size
      - avg_interval
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


def train_model(feature_df):
    """
    Trains a Random Forest using:
      avg_packet_size, std_packet_size, max_packet_size,
      avg_interval, std_interval, burstiness,
      flow_duration, packet_count, and protocol_encoded.
    Prints a classification report but hides macro avg, weighted avg, and f1-score lines.
    """
    if 'Traffic_Type' not in feature_df.columns:
        raise ValueError("Missing 'Traffic_Type' column; run classify_traffic first.")

    # Encode protocol
    le = LabelEncoder()
    feature_df['protocol_encoded'] = le.fit_transform(feature_df['protocol'].astype(str))

    feature_cols = [
        'avg_packet_size', 'std_packet_size', 'max_packet_size',
        'avg_interval', 'std_interval', 'burstiness',
        'flow_duration', 'packet_count', 'protocol_encoded'
    ]
    X = feature_df[feature_cols]
    y = feature_df['Traffic_Type']

    # Remove classes with fewer than 2 occurrences
    valid_classes = y.value_counts()[y.value_counts() >= 2].index
    df_filtered = feature_df[feature_df['Traffic_Type'].isin(valid_classes)]
    if df_filtered.empty:
        raise ValueError("All classes have fewer than 2 occurrences. Cannot train model.")

    X = df_filtered[feature_cols]
    y = df_filtered['Traffic_Type']

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train/test split
    unique_classes = y.nunique()
    if unique_classes > 2:
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, stratify=y, random_state=42
        )
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42
        )

    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)
    y_pred = rf_model.predict(X_test)

    # Generate the classification report, then filter out macro avg, weighted avg, and f1-score lines
    full_report = classification_report(y_test, y_pred, zero_division=1)
    filtered_report_lines = []
    for line in full_report.split('\n'):
        lower_line = line.lower()
        # Hide lines containing 'macro avg', 'weighted avg'
        if 'macro avg' in lower_line or 'weighted avg' in lower_line :
            continue
        filtered_report_lines.append(line)

    print("\n=== CLASSIFICATION REPORT ===")
    print('\n'.join(filtered_report_lines))
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")

    return rf_model, scaler, X_train, X_test, y_train, y_test, y_pred


def visualize_traffic(feature_df):
    """
    Scatter plot of avg_packet_size vs. avg_interval, color-coded by Traffic_Type.
    """
    plt.figure(figsize=(10, 6))
    sns.scatterplot(
        data=feature_df,
        x='avg_packet_size',
        y='avg_interval',
        hue='Traffic_Type',
        s=100
    )
    plt.title("Traffic Classification by Flow")
    plt.xlabel("Avg Packet Size (bytes)")
    plt.ylabel("Avg Inter-Arrival Time (s)")
    plt.legend(title="Traffic Type", bbox_to_anchor=(1.02, 1), loc='upper left')
    plt.tight_layout()
    plt.show()


###############################################################################
#                                   MAIN
###############################################################################

if __name__ == "__main__":
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', 1000)

    csv_folder = "../res/csv-files"
    results = load_csv_files(csv_folder)
    if not results:
        print("No valid CSV files found.")
        exit()

    feature_df = extract_features(results)
    if feature_df.empty:
        print("No valid flow data extracted from CSVs.")
        exit()

    feature_df = classify_traffic(feature_df)

    try:
        rf_model, scaler, X_train, X_test, y_train, y_test, y_pred = train_model(feature_df)
    except ValueError as e:
        print(f"Could not train Random Forest: {e}")

    visualize_traffic(feature_df)
