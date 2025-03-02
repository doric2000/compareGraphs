# AppDetector: Single-Run Network Traffic Classifier

This repository contains a Python script (**AppDetector.py**) that demonstrates:
1. Loading multiple CSV files from a specified folder (`./csv-files` by default).
2. Extracting numerical features (e.g., average packet size, intervals, burstiness).
3. Assigning an initial classification to each CSV (Video Streaming, Audio Streaming, etc.) via simple threshold rules.
4. Training a Random Forest model to verify or refine the classification.
5. Displaying a single scatter plot with color-coded classes.

## How It Works

1. **Load CSVs**  
   Each CSV is assumed to contain columns like `Time` (or `Timestamp`) and `Length` (or `Packet Size`). The script renames them if needed and drops incomplete rows.

2. **Extract Features**  
   For each CSV, the script calculates:
   - `avg_packet_size`: Mean packet size in bytes
   - `std_packet_size`: Standard deviation of packet sizes
   - `avg_interval`: Mean time between consecutive packets
   - `std_interval`: Standard deviation of those intervals
   - `num_packets`: Total packet count
   - `flow_entropy`: Entropy of packet sizes
   - `flow_duration`: Duration (max-min timestamp)
   - `burstiness`: The ratio `std_interval / avg_interval`

3. **Classify Traffic (Rule-Based)**  
   A basic function `classify_traffic` uses threshold conditions to label each CSV as `"Video Streaming"`, `"Video Calls"`, `"Audio Streaming"`, or `"Web Browsing"`.

4. **Train Model**  
   The script uses `RandomForestClassifier` from scikit-learn. It:
   - Removes categories with <2 samples (avoid classification issues).
   - Splits data (70% train / 30% test).
   - Trains the model and prints metrics (optionally).

5. **Visualize**  
   Finally, it plots a single scatter plot (`avg_packet_size` vs. `avg_interval`), coloring each CSV by its final classification label.

## Usage

1. **Install Requirements**  
   ```bash
   pip install -r requirements.txt
