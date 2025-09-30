



# New section"""

import os
import pandas as pd
from scapy.all import rdpcap
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, classification_report

# Feature extraction function
def extract_features(pcap_file):
    packets = rdpcap(pcap_file)
    features = []
    for pkt in packets:
        length = len(pkt)
        src_port = pkt.sport if hasattr(pkt, 'sport') else 0
        dst_port = pkt.dport if hasattr(pkt, 'dport') else 0
        protocol = pkt.proto if hasattr(pkt, 'proto') else 0
        features.append([length, src_port, dst_port, protocol])
    return pd.DataFrame(features, columns=['length', 'src_port', 'dst_port', 'protocol'])

# Extract features from all pcaps in captures/
data_folder = 'captures/pcap'
all_features = []

for filename in os.listdir(data_folder):
    if filename.endswith('.pcap') or filename.endswith('.pcapng'):
        filepath = os.path.join(data_folder, filename)
        df_temp = extract_features(filepath)
        all_features.append(df_temp)

df_combined = pd.concat(all_features, ignore_index=True)

# Map protocol numbers to names
protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
df_combined['protocol_name'] = df_combined['protocol'].map(protocol_map).fillna('OTHER')

# Basic labeling based on ports
def port_based_label(row):
    if row['src_port'] == 80 or row['dst_port'] == 80:
        return 'HTTP'
    elif row['src_port'] == 53 or row['dst_port'] == 53:
        return 'DNS'
    elif row['src_port'] == 21 or row['dst_port'] == 21:
        return 'FTP'
    else:
        return 'OTHER'

df_combined['label'] = df_combined.apply(port_based_label, axis=1)

# Convert protocol names to numeric
df_combined['protocol_num'] = pd.factorize(df_combined['protocol_name'])[0]

# Prepare features and label vectors
X = df_combined[['length', 'src_port', 'dst_port', 'protocol_num']]
y = df_combined['label']

# Split into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train k-NN model
model = KNeighborsClassifier(n_neighbors=3)
model.fit(X_train, y_train)

# Make predictions
y_pred = model.predict(X_test)

# Evaluate model
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))