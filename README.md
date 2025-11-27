# 🛡️ Real-time APT Detection System

[![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![Framework](https://img.shields.io/badge/framework-Flask-green.svg)](https://flask.palletsprojects.com/)
[![ML](https://img.shields.io/badge/ML-scikit--learn%20%7C%20TensorFlow-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)

A **real-time network intrusion detection system** that combines **Supervised (Random Forest)** and **Unsupervised (Autoencoder)** machine learning to detect both known and zero-day attacks. Features live packet capture, real-time classification, and explainable AI visualization.

---

## 🌟 Features

### Core Capabilities
- ✅ **Real-time Packet Capture** - Live network traffic monitoring with Scapy
- 🤖 **Hybrid ML Detection** 
  - **Random Forest Classifier** - Detects 7 attack types with 99%+ accuracy
  - **Autoencoder** - Anomaly detection for zero-day attacks
- 🔍 **Explainable AI** - LIME explanations for model decisions
- 📊 **Interactive Dashboard** - Live flow visualization with SocketIO
- 🌍 **Geolocation** - IP country mapping with flag visualization
- ⚡ **Low Latency** - Sub-second classification of network flows

### Attack Detection Categories
| Category | Attack Types |
|----------|-------------|
| **Benign** | Normal traffic |
| **Botnet** | Bot malware, C&C communication |
| **DDoS** | Distributed denial of service (HOIC, LOIC) |
| **DoS** | Denial of service (Hulk, Slowloris, GoldenEye) |
| **FTP-Patator** | FTP brute force attacks |
| **SSH-Patator** | SSH brute force attacks |
| **Web Attack** | SQL injection, XSS, brute force, infiltration |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Traffic                          │
└──────────────────────┬──────────────────────────────────────┘
                       │ Scapy Packet Capture
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Flow Feature Extraction (39 Features)          │
│  • Timing: Flow Duration, IAT, Active/Idle times            │
│  • Packet Stats: Length, Size, Count, Rates                 │
│  • Flags: SYN, ACK, FIN, PSH, URG                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
┌──────────────────┐       ┌──────────────────────┐
│  Random Forest   │       │   Autoencoder (AE)   │
│  (Supervised)    │       │   (Unsupervised)     │
│                  │       │                      │
│ • Attack Type    │       │ • Anomaly Score      │
│ • Confidence     │       │ • Reconstruction     │
│ • Risk Level     │       │   Error              │
└────────┬─────────┘       └──────────┬───────────┘
         │                            │
         └────────────┬───────────────┘
                      ▼
         ┌────────────────────────┐
         │   Flask Web Interface  │
         │                        │
         │ • Real-time Dashboard  │
         │ • Flow Details         │
         │ • LIME Explanations    │
         │ • Plotly Visualizations│
         └────────────────────────┘
```

---

## 📋 Requirements

### System Requirements
- **Operating System:** Windows 10/11 (64-bit)
- **RAM:** 8GB minimum (16GB recommended for training)
- **Storage:** 10GB free space (for dataset and models)
- **Network:** Administrator privileges for packet capture

### Software Dependencies
- **Python:** 3.11.x ([Download](https://www.python.org/downloads/release/python-3110/))
- **Npcap:** 1.71+ ([Download](https://npcap.com/#download))
  - Required for packet capture on Windows
  - Install with "WinPcap API-compatible Mode" enabled

---

## 🚀 Installation

### 1. Clone Repository
```bash
git clone https://github.com/YourUsername/APT_Detection.git
cd APT_Detection
```

### 2. Setup Python Environment
```bash
# Remove old environment if exists
rm -Recurse -Force venv

# Create virtual environment with Python 3.11
py -3.11 -m venv venv

# Activate environment
venv\Scripts\activate

# Upgrade pip
python -m pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt
```

### 3. Install Npcap (Windows Only)
1. Download [Npcap 1.71](https://npcap.com/dist/npcap-1.71.exe)
2. Run installer as Administrator
3. ✅ Check "Install Npcap in WinPcap API-compatible Mode"
4. ✅ Check "Support loopback traffic capture"

---

## 🎓 Model Training

### Option A: Use Pre-trained Models
Download pre-trained models from [Releases](https://github.com/YourUsername/APT_Detection/releases) and extract to `models/` folder.

### Option B: Train Your Own Models

#### 1. Download CICIDS 2018 Dataset
- **Source:** [UNB CICIDS 2018](https://www.unb.ca/cic/datasets/ids-2018.html)
- **Size:** ~6.3GB (10 CSV files)
- Extract all CSV files to a folder (e.g., `D:\Datasets\CICIDS2018\`)

#### 2. Update Training Script
Edit `retrain_classifier.py` line 469:
```python
dataset_folder = r'D:\Datasets\CICIDS2018'  # <-- Your dataset path
```

#### 3. Run Training
```bash
# Full training (10-30 minutes)
python retrain_classifier.py

# Quick test (2-5 minutes)
# Edit line 472: max_rows_per_file = 50000
python retrain_classifier.py
```

#### 4. Expected Output
```
Loading CICIDS 2018 Dataset Files
Found 10 CSV files
Merged dataset shape: (16,233,002, 79)

Final label distribution:
  Benign: 13,484,708 (82.5%)
  DDoS: 1,263,933 (7.7%)
  DoS: 654,300 (4.0%)
  Botnet: 286,191 (1.8%)
  ...

Training Random Forest Classifier
Overall Accuracy: 0.9994 (99.94%)

✓ TRAINING COMPLETE!
Models saved to models/ directory
```

---

## 💻 Usage

### Start the Application

#### Windows (Administrator Required)
```bash
# Activate environment
venv\Scripts\activate

# Run as Administrator (for packet capture)
python application.py
```

#### Linux/Mac
```bash
source venv/bin/activate
sudo python application.py  # sudo needed for packet capture
```

### Access Web Interface
Open browser and navigate to: **http://localhost:5000**

---

## 🖥️ Screenshots

### Main Dashboard - Real-time Flow Monitoring
![Dashboard](https://github.com/HoangNV2001/Real-time-IDS/assets/72451372/90b42a1a-e2cb-4445-8036-4504e9c7c4ba)

**Features:**
- Live network flows with color-coded risk levels
- Source/Destination IPs with country flags
- Attack classification with confidence scores
- Top source IPs chart

### Flow Detail Page - Explainable AI
![Flow Detail](https://github.com/HoangNV2001/Real-time-IDS/assets/72451372/c6ce1c6b-a006-461e-8872-d889abd69d0d)

**Features:**
- Complete flow metadata
- LIME feature importance explanation
- Autoencoder reconstruction error visualization
- Risk assessment breakdown

---

## 📁 Project Structure

```
APT_Detection/
├── flow/
│   ├── Flow.py              # Network flow object
│   ├── FlowFeature.py       # Feature extraction
│   └── PacketInfo.py        # Packet parsing
├── models/
│   ├── model.pkl            # Random Forest classifier
│   ├── explainer            # LIME explainer
│   ├── autoencoder_39ft.hdf5        # Autoencoder model
│   └── preprocess_pipeline_AE_39ft.save  # AE scaler
├── static/
│   ├── css/                 # Stylesheets
│   ├── images/              # Country flags, icons
│   └── js/                  # Frontend JavaScript
├── templates/
│   ├── index.html           # Main dashboard
│   └── detail.html          # Flow detail page
├── application.py           # Flask application
├── retrain_classifier.py   # Model training script
├── requirements.txt         # Python dependencies
└── README.md
```

---

## 🔧 Configuration

### Change Packet Capture Interface
Edit `application.py` line 339:
```python
# Auto-detect (default)
sniff(prn=newPacket, store=False)

# Specific interface
sniff(iface="Ethernet", prn=newPacket, store=False)
```

### Adjust Flow Timeout
Edit `application.py` line 79:
```python
FlowTimeout = 600  # seconds (default: 10 minutes)
```

### Modify ML Hyperparameters
Edit `retrain_classifier.py` lines 282-291:
```python
RandomForestClassifier(
    n_estimators=100,        # Number of trees
    max_depth=20,            # Tree depth
    min_samples_split=10,    # Min samples to split
    class_weight='balanced'  # Handle imbalanced data
)
```

---

## 🐛 Troubleshooting

### Issue: "Permission Denied" on Packet Capture
**Solution:** Run as Administrator (Windows) or use `sudo` (Linux/Mac)

### Issue: "No module named 'scapy'"
**Solution:** 
```bash
pip install scapy
# If fails, try:
pip install --upgrade scapy
```

### Issue: "Cannot open include file: 'pcap.h'"
**Solution:** Install [Npcap](https://npcap.com/#download) for Windows

### Issue: Model shows only 2 classes instead of 7
**Solution:** Retrain model - previous training was interrupted:
```bash
python retrain_classifier.py
```

### Issue: High memory usage during training
**Solution:** Limit data in `retrain_classifier.py`:
```python
max_rows_per_file = 100000  # Line 472
```

### Issue: Flask SocketIO connection errors
**Solution:** Update Flask-SocketIO:
```bash
pip install --upgrade Flask-SocketIO python-socketio
```

---

## 📊 Performance Metrics

### Model Performance (CICIDS 2018 Dataset)
| Metric | Random Forest | Autoencoder |
|--------|--------------|-------------|
| **Accuracy** | 99.94% | N/A (unsupervised) |
| **Precision** | 99% (avg) | Anomaly detection |
| **Recall** | 99% (avg) | High sensitivity |
| **F1-Score** | 99% (avg) | N/A |
| **Training Time** | 15-30 min | Pre-trained |
| **Inference Time** | <10ms per flow | <5ms per flow |

### System Performance
- **Packet Processing:** ~1000 packets/sec
- **Flow Classification:** Real-time (<1 sec latency)
- **Memory Usage:** ~2GB (runtime), ~8GB (training)
- **CPU Usage:** 20-40% (8-core system)

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📚 Citation

If you use this project in your research, please cite:

```bibtex
@misc{apt_detection_2025,
  author = {Nguyen Viet Hoang},
  title = {Real-time APT Detection System with Hybrid Machine Learning},
  year = {2025},
  publisher = {GitHub},
  url = {https://github.com/HoangNV2001/APT_Detection}
}
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Dataset:** [CICIDS 2018](https://www.unb.ca/cic/datasets/ids-2018.html) by Canadian Institute for Cybersecurity
- **SCVIC-APT Dataset:** [SCVIC](https://www.impactcybertrust.org/)
- **Libraries:** scikit-learn, TensorFlow/Keras, Flask, Scapy, LIME
- **Inspiration:** CICFlowMeter, Zeek IDS

---

## 📞 Contact

**Project Maintainer (New version):** Avidu Witharana  
**Email:** avidu@pm.me
**GitHub:** [@avidzcheetah](https://github.com/avidzcheetah)

**Project Creator (Old Version):** Nguyen Viet Hoang  
**Email:** hoang.nv194434@sis.hust.edu.vn  
**GitHub:** [@HoangNV2001](https://github.com/HoangNV2001)

---

## 🗺️ Roadmap

- [ ] Add support for PCAP file analysis (offline mode)
- [ ] Implement deep learning models (LSTM, CNN)
- [ ] Add alert notification system (email, Slack, Discord)
- [ ] Create Docker container for easy deployment
- [ ] Add API endpoints for external integration
- [ ] Support for Linux/Mac native packet capture
- [ ] Real-time dashboard with Grafana integration
- [ ] Model performance monitoring and drift detection

---

<div align="center">

**⭐ Star this repo if you find it useful! ⭐**

Made with ❤️ by [Nguyen Viet Hoang](https://github.com/HoangNV2001)

</div>
