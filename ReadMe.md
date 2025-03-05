# Network Traffic Analysis Project

This project provides tools for analyzing network traffic using PCAP files and detecting streaming types.

## Project Structure

### `pcap_feature_extractor.py` (PCAP Feature Extraction)
**Purpose:** 
This script extracts key features from network traffic captured in PCAP files. It calculates statistical metrics for packet flows to analyze network behavior.

**What it does:**
- Loads **PCAP** files from the `pcapfiles/` directory.
- Extracts network flow characteristics such as:
  - **Packet sizes** (mean, standard deviation)
  - **Inter-arrival times** (mean, standard deviation)
  - **Total packets per flow**
  - **Flow entropy** (a measure of randomness in packet sizes)
- Saves the extracted data in a structured **CSV file** (`flow_analysis_results.csv`).

**What it shows:**
- **Summary of extracted network features**
- **Saved output file (`flow_analysis_results.csv`)** containing analyzed results.

#### **File Structure Requirements for `pcap_feature_extractor.py`**
- **PCAP files directory:** `./pcapfiles/`
  - Should contain `.pcap` or `.pcapng` files such as:
    - `Audio-Streaming.pcapng`
    - `Video-Streaming.pcapng`
    - `Web-Surfing-1.pcapng`
- **CSV Output File:** `flow_analysis_results.csv`
  - Extracted features will be saved with columns:
    - `Mean Size`
    - `Std Size`
    - `Mean Inter-Arrival`
    - `Std Inter-Arrival`
    - `Total Packets`
    - `Flow Entropy`

---

### `stream_type_detector.py` && `stream_type_limited_detector.py` (Stream Type Detection)
**Purpose:** 
This script **classifies network traffic** into different streaming categories (Audio Streaming, Video Streaming, Web Surfing). It uses clustering and rule-based classification to detect streaming types.

**What it does:**
- Loads extracted feature data from CSV files.
- Uses **K-Means Clustering** to group traffic flows based on statistical characteristics.
- Applies **classification logic** to assign a category to each flow.
- Identifies the most probable application type based on observed network behavior.

**What it shows:**
- **Clustered traffic categories (Audio, Video, Web Surfing)**
- **Classification results in a structured output CSV file**

#### **File Structure Requirements for `stream_type_detector.py`**
- **Input CSV files:** Located in `csv-files/`.
  - Must contain the following columns:
    - `No.` (Packet number)
    - `Time` (Timestamp of packet capture)
    - `Source` (Source IP Address)
    - `Destination` (Destination IP Address)
    - `Protocol` (e.g., TCP, UDP, TLS)
    - `Length` (Size of the packet in bytes)
	
#### **File Structure Requirements for `stream_type_limited_detector.py`**
- **Input CSV files:** Located in `csv-files/`.
  - Must contain the following columns:
    - `No.` (Packet number)
    - `Time` (Timestamp of packet capture)
    - `Length` (Size of the packet in bytes)


  - Example files:
    - `Audio-Streaming.csv`
    - `Video-Conferencing.csv`
    - `Video-Streaming.csv`
    - `web-surfing-1.csv`
    - `Web-Surfing-2.csv`

- **PCAP files:** Used for matching against known traffic patterns.

---

## Installation
To install required dependencies, run:

```bash
pip install -r requirements.txt
```

## Dependencies
This project requires the following Python libraries:
- **PyShark** (for PCAP analysis)
- **Pandas** (for data processing)
- **NumPy** (for numerical computations)
- **Seaborn, Matplotlib** (for visualization)
- **SciPy** (for entropy calculations)
- **Scikit-learn** (for clustering and classification)
