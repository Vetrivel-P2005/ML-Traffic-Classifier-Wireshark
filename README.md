# Intelligent Traffic Behavior Detection and Packet Classification using Machine Learning on PCAP Data

This project aims to classify network traffic using machine learning models trained on features extracted from real-world packet capture (PCAP) files. It enhances network visibility, anomaly detection, and security monitoring.

## 📌 Project Overview

Traditional rule-based traffic classification methods often fail when dealing with encrypted or obfuscated traffic. Our solution uses supervised machine learning to classify and detect traffic behavior from PCAP files.

## 🎯 Objectives

- Capture real-time network traffic using Wireshark
- Extract relevant features (e.g., protocol, port, packet size)
- Train ML models (SVM, k-NN) to classify traffic types
- Detect anomalies in traffic patterns
- Visualize results for better interpretation

## 🧑‍💻 Tech Stack

- **Wireshark** – For capturing PCAP data
- **Python** – For scripting and ML implementation
- **Scapy & pandas** – For parsing and preprocessing PCAP
- **scikit-learn** – For ML models
- **matplotlib & seaborn** – For data visualization

## ⚙️ Working Principle

1. **Data Collection**: Capture live traffic using Wireshark.
2. **Feature Extraction**: Use Scapy and pandas to extract features like protocol, packet length, port numbers, and timestamps.
3. **Model Training**: Apply k-NN and SVM for classification.
4. **Detection & Visualization**: Classify new traffic and detect anomalies. Visualize using matplotlib and seaborn.

## 👨‍👩‍👧‍👦 Team Members

- **Vetrivel P** – ML model implementation
- **Praveen S** – Data preprocessing and documentation
- **Balamurugan V** – Packet capture and feature extraction
- **Pragadeesh D** – Visualization and anomaly detection

