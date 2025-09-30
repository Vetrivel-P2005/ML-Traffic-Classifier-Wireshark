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
import os
import glob
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
        
        try:
            # Basic packet features
            features['packet_length'] = len(packet)
            features['has_ip'] = 1 if packet.haslayer(IP) else 0
            
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                features['ip_length'] = self._safe_int(ip_layer.len)
                features['ip_ttl'] = self._safe_int(ip_layer.ttl)
                features['ip_flags'] = self._safe_int(ip_layer.flags)
                features['ip_frag'] = self._safe_int(ip_layer.frag)
                features['ip_proto'] = self._safe_int(ip_layer.proto)
                
                # Protocol-specific features
                features['is_tcp'] = 1 if packet.haslayer(TCP) else 0
                features['is_udp'] = 1 if packet.haslayer(UDP) else 0
                features['is_icmp'] = 1 if packet.haslayer(ICMP) else 0
                
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    features['src_port'] = self._safe_int(tcp_layer.sport)
                    features['dst_port'] = self._safe_int(tcp_layer.dport)
                    features['tcp_flags'] = self._safe_int(tcp_layer.flags)
                    features['tcp_window'] = self._safe_int(tcp_layer.window)
                    features['tcp_seq'] = self._safe_int(tcp_layer.seq)
                    features['tcp_ack'] = self._safe_int(tcp_layer.ack)
                    features['tcp_dataofs'] = self._safe_int(tcp_layer.dataofs)
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
                    features['src_port'] = self._safe_int(udp_layer.sport)
                    features['dst_port'] = self._safe_int(udp_layer.dport)
                    features['udp_length'] = self._safe_int(udp_layer.len)
                else:
                    features['udp_length'] = 0
                    
            else:
                # Default values for non-IP packets
                for key in ['ip_length', 'ip_ttl', 'ip_flags', 'ip_frag', 'ip_proto',
                           'is_tcp', 'is_udp', 'is_icmp', 'src_port', 'dst_port',
                           'tcp_flags', 'tcp_window', 'tcp_seq', 'tcp_ack', 
                           'tcp_dataofs', 'udp_length']:
                    features[key] = 0
                    
        except Exception as e:
            print(f"Warning: Error extracting features from packet: {e}")
            # Return default features in case of error
            for key in ['packet_length', 'has_ip', 'ip_length', 'ip_ttl', 'ip_flags', 
                       'ip_frag', 'ip_proto', 'is_tcp', 'is_udp', 'is_icmp', 
                       'src_port', 'dst_port', 'tcp_flags', 'tcp_window', 
                       'tcp_seq', 'tcp_ack', 'tcp_dataofs', 'udp_length']:
                features[key] = 0
                
        return features
    
    def _safe_int(self, value):
        """Safely convert value to integer, handling FlagValue and other objects"""
        try:
            # Handle Scapy FlagValue objects
            if hasattr(value, 'value'):
                return int(value.value)
            # Handle None values
            elif value is None:
                return 0
            # Handle regular numeric values
            else:
                return int(value)
        except (ValueError, TypeError, AttributeError):
            # Return 0 for any conversion errors
            return 0
    
    def classify_packet(self, packet):
        """Classify packet based on common patterns"""
        try:
            if not packet.haslayer(IP):
                return 'non_ip'
                
            ip_layer = packet[IP]
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = self._safe_int(tcp_layer.sport)
                dst_port = self._safe_int(tcp_layer.dport)
                
                # Web traffic
                if dst_port in [80, 443, 8080, 8443] or src_port in [80, 443, 8080, 8443]:
                    return 'web_traffic'
                # Email
                elif dst_port in [25, 587, 465, 993, 995, 143, 110] or src_port in [25, 587, 465, 993, 995, 143, 110]:
                    return 'email'
                # SSH/Telnet
                elif dst_port in [22, 23] or src_port in [22, 23]:
                    return 'remote_access'
                # FTP
                elif dst_port in [21, 20] or src_port in [21, 20]:
                    return 'file_transfer'
                # Database
                elif dst_port in [1433, 3306, 5432, 1521] or src_port in [1433, 3306, 5432, 1521]:
                    return 'database'
                else:
                    return 'other_tcp'
                    
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = self._safe_int(udp_layer.sport)
                dst_port = self._safe_int(udp_layer.dport)
                
                # DNS
                if dst_port == 53 or src_port == 53:
                    return 'dns'
                # DHCP
                elif dst_port in [67, 68] or src_port in [67, 68]:
                    return 'dhcp'
                # NTP
                elif dst_port == 123 or src_port == 123:
                    return 'ntp'
                # SNMP
                elif dst_port in [161, 162] or src_port in [161, 162]:
                    return 'snmp'
                else:
                    return 'other_udp'
                    
            elif packet.haslayer(ICMP):
                return 'icmp'
            else:
                return 'other_ip'
                
        except Exception as e:
            print(f"Warning: Error classifying packet: {e}")
            return 'unknown'
    
    def load_and_process_pcap(self, pcap_file_path):
        """Load single pcap file and extract features"""
        print(f"Loading packets from {pcap_file_path}...")
        
        try:
            packets = rdpcap(pcap_file_path)
            print(f"Loaded {len(packets)} packets from {os.path.basename(pcap_file_path)}")
        except Exception as e:
            print(f"Error loading pcap file {pcap_file_path}: {e}")
            return None, None
        
        features_list = []
        labels_list = []
        
        print("Extracting features...")
        for i, packet in enumerate(packets):
            if i % 1000 == 0:
                print(f"  Processed {i} packets...")
                
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
        
        print(f"Extracted features for {len(df_features)} packets from {os.path.basename(pcap_file_path)}")
        
        return df_features, df_labels
    
    def load_and_process_folder(self, folder_path, file_limit=None):
        """Load and process multiple pcap files from a folder"""
        print(f"Scanning folder: {folder_path}")
        
        # Find all pcap/pcapng files
        pcap_patterns = ['*.pcap', '*.pcapng', '*.cap']
        pcap_files = []
        
        for pattern in pcap_patterns:
            pcap_files.extend(glob.glob(os.path.join(folder_path, pattern)))
        
        if not pcap_files:
            print(f"No pcap/pcapng files found in {folder_path}")
            print("Supported file extensions: .pcap, .pcapng, .cap")
            return None, None
        
        print(f"Found {len(pcap_files)} pcap files:")
        for file in pcap_files:
            print(f"  - {os.path.basename(file)}")
        
        # Limit files if specified
        if file_limit:
            pcap_files = pcap_files[:file_limit]
            print(f"Processing first {len(pcap_files)} files due to limit")
        
        all_features = []
        all_labels = []
        
        for i, pcap_file in enumerate(pcap_files, 1):
            print(f"\n[{i}/{len(pcap_files)}] Processing {os.path.basename(pcap_file)}")
            
            features, labels = self.load_and_process_pcap(pcap_file)
            
            if features is not None and not features.empty:
                all_features.append(features)
                all_labels.append(labels)
            else:
                print(f"Skipping {os.path.basename(pcap_file)} due to processing errors")
        
        if not all_features:
            print("No valid features extracted from any files")
            return None, None
        
        # Combine all data
        print(f"\nCombining data from {len(all_features)} files...")
        combined_features = pd.concat(all_features, ignore_index=True)
        combined_labels = pd.concat(all_labels, ignore_index=True)
        
        print(f"Total packets processed: {len(combined_features)}")
        print("\nOverall label distribution:")
        print(combined_labels.value_counts())
        
        return combined_features, combined_labels
    
    def train_model(self, features, labels):
        """Train the classification model"""
        print("\nTraining model...")
        
        # Store feature columns
        self.feature_columns = features.columns.tolist()
        
        # Clean the data: remove any rows with non-numeric values
        print("Cleaning data...")
        original_size = len(features)
        
        # Replace any remaining non-numeric values with 0
        features_cleaned = features.copy()
        for col in features_cleaned.columns:
            features_cleaned[col] = pd.to_numeric(features_cleaned[col], errors='coerce').fillna(0)
        
        # Remove rows where all features are 0 (likely corrupted packets)
        valid_rows = (features_cleaned != 0).any(axis=1)
        features_cleaned = features_cleaned[valid_rows]
        labels_cleaned = labels[valid_rows]
        
        print(f"Cleaned dataset: {len(features_cleaned)}/{original_size} packets retained")
        
        if len(features_cleaned) == 0:
            print("Error: No valid data remaining after cleaning")
            return None, None, None
        
        # Encode labels
        labels_encoded = self.label_encoder.fit_transform(labels_cleaned)
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features_cleaned)
        
        # Check if we have enough samples for each class
        unique_labels, label_counts = np.unique(labels_encoded, return_counts=True)
        min_samples = min(label_counts)
        
        if min_samples < 2:
            print("Warning: Some classes have very few samples. Results may not be reliable.")
        
        # Split data with stratification if possible
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                features_scaled, labels_encoded, test_size=0.2, random_state=42, 
                stratify=labels_encoded if min_samples >= 2 else None
            )
        except ValueError:
            # Fall back to random split if stratification fails
            X_train, X_test, y_train, y_test = train_test_split(
                features_scaled, labels_encoded, test_size=0.2, random_state=42
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
        print(classification_report(y_test, y_pred, target_names=class_names, zero_division=0))
        
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
    2. Update the folder_path below to point to your pcap files folder
    3. Run the script
    """
    
    classifier = PacketClassifier()
    
    # Update this path to your pcap files folder
    pcap_folder = "./pcap_files"  # Replace with your folder path
    # Alternative examples:
    # pcap_folder = "/path/to/your/pcap/files"  # Linux/Mac
    # pcap_folder = r"C:\path\to\your\pcap\files"  # Windows
    
    print("Network Packet Classification ML Model")
    print("=" * 50)
    
    # Check if folder exists
    if not os.path.exists(pcap_folder):
        print(f"Error: Folder '{pcap_folder}' does not exist")
        print("\nPlease:")
        print("1. Create the folder or update the path")
        print("2. Place your .pcap/.pcapng files in the folder")
        print("3. Update the 'pcap_folder' variable in the code")
        return
    
    try:
        # Option 1: Process all files in folder
        features, labels = classifier.load_and_process_folder(pcap_folder)
        
        # Option 2: Process with file limit (uncomment to use)
        # features, labels = classifier.load_and_process_folder(pcap_folder, file_limit=5)
        
        # Option 3: Process single file (uncomment to use)
        # single_file = os.path.join(pcap_folder, "your_file.pcap")
        # features, labels = classifier.load_and_process_pcap(single_file)
        
        if features is not None and not features.empty:
            print(f"\nDataset shape: {features.shape}")
            print(f"Number of classes: {labels.nunique()}")
            
            # Check if we have enough data for training
            if len(features) < 100:
                print("Warning: Very small dataset. Consider adding more pcap files.")
            
            # Train the model
            X_test, y_test, y_pred = classifier.train_model(features, labels)
            
            # Plot results
            classifier.plot_results(y_test, y_pred)
            
            # Save model info
            print("\nModel trained successfully!")
            print("You can now use the classifier for predictions:")
            print("predicted_class, confidence = classifier.predict_packet_class(packet)")
            
        else:
            print("No valid data extracted from pcap files.")
            
    except Exception as e:
        print(f"Error during processing: {e}")

# Additional utility functions
def list_pcap_files(folder_path):
    """List all pcap files in a folder"""
    if not os.path.exists(folder_path):
        print(f"Folder '{folder_path}' does not exist")
        return []
    
    pcap_patterns = ['*.pcap', '*.pcapng', '*.cap']
    pcap_files = []
    
    for pattern in pcap_patterns:
        pcap_files.extend(glob.glob(os.path.join(folder_path, pattern)))
    
    return pcap_files

def get_file_info(folder_path):
    """Get information about pcap files in folder"""
    files = list_pcap_files(folder_path)
    
    print(f"PCAP Files in '{folder_path}':")
    print("-" * 60)
    
    if not files:
        print("No pcap files found")
        return
    
    total_size = 0
    for file in files:
        size = os.path.getsize(file)
        total_size += size
        print(f"{os.path.basename(file):30} {size/1024/1024:.2f} MB")
    
    print("-" * 60)
    print(f"Total files: {len(files)}")
    print(f"Total size: {total_size/1024/1024:.2f} MB")

if __name__ == "__main__":
    # Uncomment to see file info first
    # get_file_info("./pcap_files")
    
    main()