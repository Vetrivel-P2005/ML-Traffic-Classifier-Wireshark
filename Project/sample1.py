import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

class PacketClassifier:
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.feature_columns = []
        
    def extract_packet_features(self, packet):
        """Extract features from a single packet"""
        features = {}
        
        # Basic packet features
        features['packet_length'] = len(packet)
        features['has_ip'] = 1 if packet.haslayer(IP) else 0
        
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            features['ip_length'] = ip_layer.len
            features['ip_ttl'] = ip_layer.ttl
            features['ip_flags'] = ip_layer.flags
            features['ip_frag'] = ip_layer.frag
            features['ip_proto'] = ip_layer.proto
            
            # Protocol-specific features
            features['is_tcp'] = 1 if packet.haslayer(TCP) else 0
            features['is_udp'] = 1 if packet.haslayer(UDP) else 0
            features['is_icmp'] = 1 if packet.haslayer(ICMP) else 0
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                features['src_port'] = tcp_layer.sport
                features['dst_port'] = tcp_layer.dport
                features['tcp_flags'] = tcp_layer.flags
                features['tcp_window'] = tcp_layer.window
                features['tcp_seq'] = tcp_layer.seq
                features['tcp_ack'] = tcp_layer.ack
                features['tcp_dataofs'] = tcp_layer.dataofs
            else:
                features['src_port'] = 0
                features['dst_port'] = 0
                features['tcp_flags'] = 0
                features['tcp_window'] = 0
                features['tcp_seq'] = 0
                features['tcp_ack'] = 0
                features['tcp_dataofs'] = 0
                
            if packet.haslayer(UDP):
                udp_layer = packet[UDP]
                features['src_port'] = udp_layer.sport
                features['dst_port'] = udp_layer.dport
                features['udp_length'] = udp_layer.len
            else:
                features['udp_length'] = 0
                
        else:
            # Default values for non-IP packets
            for key in ['ip_length', 'ip_ttl', 'ip_flags', 'ip_frag', 'ip_proto',
                       'is_tcp', 'is_udp', 'is_icmp', 'src_port', 'dst_port',
                       'tcp_flags', 'tcp_window', 'tcp_seq', 'tcp_ack', 
                       'tcp_dataofs', 'udp_length']:
                features[key] = 0
                
        return features
    
    def classify_packet(self, packet):
        """Classify packet based on common patterns"""
        if not packet.haslayer(IP):
            return 'non_ip'
            
        ip_layer = packet[IP]
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            
            # Web traffic
            if tcp_layer.dport in [80, 443, 8080, 8443] or tcp_layer.sport in [80, 443, 8080, 8443]:
                return 'web_traffic'
            # Email
            elif tcp_layer.dport in [25, 587, 465, 993, 995, 143, 110] or tcp_layer.sport in [25, 587, 465, 993, 995, 143, 110]:
                return 'email'
            # SSH/Telnet
            elif tcp_layer.dport in [22, 23] or tcp_layer.sport in [22, 23]:
                return 'remote_access'
            # FTP
            elif tcp_layer.dport in [21, 20] or tcp_layer.sport in [21, 20]:
                return 'file_transfer'
            # Database
            elif tcp_layer.dport in [1433, 3306, 5432, 1521] or tcp_layer.sport in [1433, 3306, 5432, 1521]:
                return 'database'
            else:
                return 'other_tcp'
                
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            
            # DNS
            if udp_layer.dport == 53 or udp_layer.sport == 53:
                return 'dns'
            # DHCP
            elif udp_layer.dport in [67, 68] or udp_layer.sport in [67, 68]:
                return 'dhcp'
            # NTP
            elif udp_layer.dport == 123 or udp_layer.sport == 123:
                return 'ntp'
            # SNMP
            elif udp_layer.dport in [161, 162] or udp_layer.sport in [161, 162]:
                return 'snmp'
            else:
                return 'other_udp'
                
        elif packet.haslayer(ICMP):
            return 'icmp'
        else:
            return 'other_ip'
    
    def load_and_process_pcap(self, pcap_file_path):
        """Load pcap file and extract features"""
        print(f"Loading packets from {pcap_file_path}...")
        
        try:
            packets = rdpcap(pcap_file_path)
            print(f"Loaded {len(packets)} packets")
        except Exception as e:
            print(f"Error loading pcap file: {e}")
            return None, None
        
        features_list = []
        labels_list = []
        
        print("Extracting features...")
        for i, packet in enumerate(packets):
            if i % 1000 == 0:
                print(f"Processed {i} packets...")
                
            try:
                # Extract features
                features = self.extract_packet_features(packet)
                features_list.append(features)
                
                # Generate label
                label = self.classify_packet(packet)
                labels_list.append(label)
                
            except Exception as e:
                print(f"Error processing packet {i}: {e}")
                continue
        
        # Convert to DataFrame
        df_features = pd.DataFrame(features_list)
        df_labels = pd.Series(labels_list, name='label')
        
        print(f"Extracted features for {len(df_features)} packets")
        print("\nLabel distribution:")
        print(df_labels.value_counts())
        
        return df_features, df_labels
    
    def train_model(self, features, labels):
        """Train the classification model"""
        print("\nTraining model...")
        
        # Store feature columns
        self.feature_columns = features.columns.tolist()
        
        # Encode labels
        labels_encoded = self.label_encoder.fit_transform(labels)
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features_scaled, labels_encoded, test_size=0.2, random_state=42, stratify=labels_encoded
        )
        
        # Train model
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\nModel Accuracy: {accuracy:.3f}")
        
        # Classification report
        print("\nClassification Report:")
        class_names = self.label_encoder.classes_
        print(classification_report(y_test, y_pred, target_names=class_names))
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': self.feature_columns,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\nTop 10 Most Important Features:")
        print(feature_importance.head(10))
        
        return X_test, y_test, y_pred
    
    def plot_results(self, y_test, y_pred):
        """Plot confusion matrix and feature importance"""
        plt.figure(figsize=(15, 5))
        
        # Confusion Matrix
        plt.subplot(1, 3, 1)
        cm = confusion_matrix(y_test, y_pred)
        class_names = self.label_encoder.classes_
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=class_names, yticklabels=class_names)
        plt.title('Confusion Matrix')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.xticks(rotation=45)
        plt.yticks(rotation=0)
        
        # Feature Importance
        plt.subplot(1, 3, 2)
        feature_importance = pd.DataFrame({
            'feature': self.feature_columns,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=True).tail(10)
        
        plt.barh(feature_importance['feature'], feature_importance['importance'])
        plt.title('Top 10 Feature Importance')
        plt.xlabel('Importance')
        
        # Label Distribution
        plt.subplot(1, 3, 3)
        label_counts = pd.Series(self.label_encoder.inverse_transform(y_test)).value_counts()
        plt.pie(label_counts.values, labels=label_counts.index, autopct='%1.1f%%')
        plt.title('Test Set Label Distribution')
        
        plt.tight_layout()
        plt.show()
    
    def predict_packet_class(self, packet):
        """Predict the class of a single packet"""
        features = self.extract_packet_features(packet)
        features_df = pd.DataFrame([features])
        
        # Ensure all columns are present
        for col in self.feature_columns:
            if col not in features_df.columns:
                features_df[col] = 0
        
        features_df = features_df[self.feature_columns]
        features_scaled = self.scaler.transform(features_df)
        
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0]
        
        predicted_class = self.label_encoder.inverse_transform([prediction])[0]
        confidence = max(probability)
        
        return predicted_class, confidence

# Example usage
def main():
    """
    Main function to demonstrate the packet classifier
    
    To use this:
    1. Install required packages: pip install scapy scikit-learn pandas matplotlib seaborn
    2. Place your pcap/pcapng file in the same directory
    3. Update the file path below
    4. Run the script
    """
    
    classifier = PacketClassifier()
    
    # Load your pcap file here
    pcap_file = "sample_traffic.pcap"  # Replace with your pcap file path
    
    try:
        # Load and process the pcap file
        features, labels = classifier.load_and_process_pcap(pcap_file)
        
        if features is not None:
            # Train the model
            X_test, y_test, y_pred = classifier.train_model(features, labels)
            
            # Plot results
            classifier.plot_results(y_test, y_pred)
            
            # Example: Classify new packets
            print("\nTo classify new packets, use:")
            print("predicted_class, confidence = classifier.predict_packet_class(packet)")
            
    except FileNotFoundError:
        print(f"Error: Could not find pcap file '{pcap_file}'")
        print("\nTo use this classifier:")
        print("1. Export pcap data from Wireshark")
        print("2. Place the .pcap or .pcapng file in your working directory")
        print("3. Update the 'pcap_file' variable with your filename")
        print("4. Install required packages:")
        print("   pip install scapy scikit-learn pandas matplotlib seaborn")

if __name__ == "__main__":
    main()