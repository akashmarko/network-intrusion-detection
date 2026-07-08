# Network Intrusion Detection System (NIDS) using Machine Learning

A machine learning system that analyzes network traffic and classifies it as normal or as one of four attack types (DoS, Probe, R2L, U2R) built end-to-end with IBM watsonx.ai AutoAI and deployed as a live, interactive dashboard.

[![IBM Cloud](https://img.shields.io/badge/IBM-Cloud%20Lite-052FAD?style=flat&logo=ibm)](https://cloud.ibm.com)
[![watsonx.ai](https://img.shields.io/badge/watsonx.ai-AutoAI-blue)](https://www.ibm.com/products/watsonx-ai)
[![IBM Bob](https://img.shields.io/badge/IBM-Bob-052FAD?style=flat&logo=ibm)](https://cloud.ibm.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?logo=streamlit)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**🚀 Live Demo:** *https://akashmarko-network-intrusion-detection.streamlit.app*

**📈 Data Analytics:** View the full [Data Analytics & Exploration Report](./data-analytics-eda/README_data-analytics.md) to see statistical distributions and data cleaning strategies.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Dataset](#dataset)
- [Model Results](#model-results)
- [Getting Started](#getting-started)

---

## Overview

Every device on a network is constantly generating connection records and hidden in that traffic are the early signs of attacks like Denial of Service floods, network scans, or unauthorized access attempts. This project builds a classifier that reads a single network connection's features and predicts whether it's normal traffic or one of four attack categories:

| Class | What it means |
|---|---|
| **Normal** | Legitimate network traffic |
| **DoS** | Denial of Service - flooding a system to make it unavailable |
| **Probe** | Scanning a network to gather information before an attack |
| **R2L** | Remote to Local - an outside attacker gaining unauthorized local access |
| **U2R** | User to Root - a local user illegitimately gaining admin/root privileges |

Manually reviewing network traffic is impossible at scale, with busy networks seeing thousands of connection attempts per second. This project demonstrates an automated early-warning solution using a real dataset, an AutoML-trained and ranked model, a live API deployment, and an interactive Streamlit dashboard for instant, real-time traffic predictions.

## How It Works

```
Kaggle NSL-KDD Dataset
        |
Data Cleaning & Encoding (Python, pandas)
        │
IBM watsonx.ai AutoAI (multiclass classification)
   -> tests multiple algorithms, ranks by accuracy
        │
Best Pipeline Selected & Saved
        │
Deployed as an Online REST API (IBM Cloud)
        │
Streamlit Dashboard
   -> user enters traffic parameters -> live prediction via API
```

1. **Data prep:** raw connection logs are cleaned, categorical fields (protocol, service, flag) are encoded, and the many specific attack labels are grouped into the 5 classes above.
2. **Training:** the cleaned dataset is handed to AutoAI, which automatically tests several algorithms (e.g. Random Forest, XGBoost, Gradient Boosting), tunes hyperparameters, and ranks results on a leaderboard.
3. **Deployment:** the best-performing pipeline is promoted and deployed as an online scoring endpoint.
4. **Interface:** a Streamlit app takes user input, authenticates against the API, and returns a color-coded prediction (green = normal, red = attack, with the attack type named).


## Dataset

- **Source:** [Kaggle Network Intrusion Detection NSL-KDD dataset](https://www.kaggle.com/code/timgoodfellow/nsl-kdd-explorations)
- **Files used:** `KDDTrain+.text` and `cleanTrain_data.csv`( used for training model )
- **Format:** each row is one network connection, with features like `duration`, `protocol_type`, `service`, `src_bytes`, `dst_bytes`, `num_failed_logins`, and a label marking the traffic class.
- A comprehensive exploratory analysis of this same dataset [`/data-analytics-eda`](./data-analytics-eda/).

## Model Results

| Metric | Value |
|---|---|
| Algorithm selected by AutoAI | *Snap Decision Tree Classifier* |
| Overall accuracy | *0.997* |
| Tuning applied | *HOP-1* |

Attack types like U2R are rare in this dataset, so overall accuracy alone can be misleading. Per-class precision/recall was reviewed to check this before picking a final pipeline.


## Getting Started

**1. Clone the repository**
```bash
git clone https://github.com/akashmarko/network-intrusion-detection.git
```

**2. Set up the environment**
```bash
python -m venv venv
source venv\Scripts\activate
pip install -r requirements.txt
```

**3. Add your watsonx.ai credentials**
Create a `.streamlit/secrets.toml` file (or set environment variables):
```toml
WATSONX_API_KEY = "your-ibm-cloud-api-key"
WATSONX_SCORING_URL = "your-deployment-scoring-endpoint"
```

**4. Run the dashboard**
```bash
streamlit run streamlit-app/app.py
```
Then open `http://localhost:8501` in your browser.


## License

This project is open for educational and portfolio use. Feel free to fork and adapt it.
