# Network Traffic Analysis Project

This project provides tools for analyzing network traffic using PCAP files and detecting streaming types.

## Project Structure

### `pcap_feature_extractor.py`
This script extracts traffic features from PCAP files, such as:
- **Packet size statistics** (mean, standard deviation)
- **Packet inter-arrival times** (mean, standard deviation)
- **Total number of packets per flow**
- **Flow entropy** (measures randomness in packet sizes)

It performs the following operations:
1. Loads network traffic from `.pcap` or `.pcapng` files.
2. Extracts statistical features from packet data.
3. Saves the processed data to CSV files.

#### **File Structure Requirements for `pcap_feature_extractor.py`**
- **PCAP files directory:** `./pcapfiles/`
- **Output file:** `flow_analysis_results.csv`

---

### `stream_type_detector.py`
This script detects different types of streaming (Audio, Video, Web Surfing) from the extracted network features.
It uses clustering techniques such as:
- **K-Means clustering** to group similar network flows.
- **Decision rules** to classify traffic into predefined categories.

#### **File Structure Requirements for `stream_type_detector.py`**
- **Input CSV files:** Located in `csv-files/`.
- **PCAP files:** Used for matching against known traffic patterns.

---

## Installation
To install required dependencies, run:

```bash
pip install -r requirements.txt
```

## Dependencies
This project requires the following Python libraries:
- PyShark (for PCAP analysis)
- Pandas (for data processing)
- NumPy (for numerical computations)
- Seaborn, Matplotlib (for visualization)
- SciPy (for entropy calculations)
- Scikit-learn (for clustering and classification)
