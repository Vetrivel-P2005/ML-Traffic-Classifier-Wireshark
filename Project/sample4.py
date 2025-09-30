# Examples of how to use your trained classifier for predictions

# Method 1: Classify packets from a new pcap file
def classify_new_pcap_file(classifier, pcap_file_path):
    """Classify all packets in a new pcap file"""
    print(f"Classifying packets in: {pcap_file_path}")
    
    try:
        from scapy.all import rdpcap
        packets = rdpcap(pcap_file_path)
        
        results = []
        for i, packet in enumerate(packets):
            predicted_class, confidence = classifier.predict_packet_class(packet)
            results.append({
                'packet_id': i,
                'predicted_class': predicted_class,
                'confidence': confidence
            })
            
            # Print first 10 predictions as examples
            if i < 10:
                print(f"Packet {i}: {predicted_class} (confidence: {confidence:.3f})")
        
        return results
        
    except Exception as e:
        print(f"Error: {e}")
        return None

# Method 2: Classify packets in real-time from network interface
def classify_live_packets(classifier, interface='eth0', packet_count=50):
    """Classify packets captured live from network interface"""
    print(f"Starting live packet classification on interface: {interface}")
    print("Press Ctrl+C to stop...")
    
    try:
        from scapy.all import sniff
        
        def packet_handler(packet):
            predicted_class, confidence = classifier.predict_packet_class(packet)
            print(f"Live packet: {predicted_class} (confidence: {confidence:.3f})")
        
        # Capture packets live
        sniff(iface=interface, prn=packet_handler, count=packet_count)
        
    except Exception as e:
        print(f"Error in live capture: {e}")
        print("Note: Live capture may require root/admin privileges")

# Method 3: Classify specific packet types
def classify_packet_examples(classifier):
    """Examples of classifying different types of packets"""
    from scapy.all import IP, TCP, UDP, ICMP
    
    # Example 1: HTTP packet
    http_packet = IP(dst="192.168.1.1")/TCP(dport=80)
    pred_class, confidence = classifier.predict_packet_class(http_packet)
    print(f"HTTP packet: {pred_class} (confidence: {confidence:.3f})")
    
    # Example 2: DNS packet  
    dns_packet = IP(dst="8.8.8.8")/UDP(dport=53)
    pred_class, confidence = classifier.predict_packet_class(dns_packet)
    print(f"DNS packet: {pred_class} (confidence: {confidence:.3f})")
    
    # Example 3: HTTPS packet
    https_packet = IP(dst="www.google.com")/TCP(dport=443)
    pred_class, confidence = classifier.predict_packet_class(https_packet)
    print(f"HTTPS packet: {pred_class} (confidence: {confidence:.3f})")
    
    # Example 4: ICMP packet
    icmp_packet = IP(dst="192.168.1.1")/ICMP()
    pred_class, confidence = classifier.predict_packet_class(icmp_packet)
    print(f"ICMP packet: {pred_class} (confidence: {confidence:.3f})")

# Method 4: Batch classification with detailed analysis
def detailed_packet_analysis(classifier, pcap_file_path):
    """Detailed analysis of packets in a pcap file"""
    from scapy.all import rdpcap
    import pandas as pd
    
    print(f"Analyzing: {pcap_file_path}")
    packets = rdpcap(pcap_file_path)
    
    results = []
    class_counts = {}
    
    for i, packet in enumerate(packets):
        predicted_class, confidence = classifier.predict_packet_class(packet)
        
        # Count classes
        if predicted_class not in class_counts:
            class_counts[predicted_class] = 0
        class_counts[predicted_class] += 1
        
        # Store detailed info
        packet_info = {
            'packet_id': i,
            'predicted_class': predicted_class,
            'confidence': confidence,
            'packet_size': len(packet),
            'has_ip': 1 if packet.haslayer(IP) else 0,
            'protocol': 'Unknown'
        }
        
        if packet.haslayer(IP):
            if packet.haslayer(TCP):
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
        
        results.append(packet_info)
    
    # Create DataFrame for analysis
    df = pd.DataFrame(results)
    
    print("\n=== CLASSIFICATION SUMMARY ===")
    print(f"Total packets analyzed: {len(packets)}")
    print("\nClass distribution:")
    for class_name, count in sorted(class_counts.items()):
        percentage = (count / len(packets)) * 100
        print(f"  {class_name}: {count} packets ({percentage:.1f}%)")
    
    print(f"\nAverage confidence: {df['confidence'].mean():.3f}")
    print(f"Low confidence packets (<0.5): {sum(df['confidence'] < 0.5)}")
    
    # Show some examples of each class
    print("\n=== EXAMPLES BY CLASS ===")
    for class_name in df['predicted_class'].unique():
        class_examples = df[df['predicted_class'] == class_name].head(3)
        print(f"\n{class_name.upper()}:")
        for _, example in class_examples.iterrows():
            print(f"  Packet {example['packet_id']}: "
                  f"{example['protocol']} - "
                  f"Size: {example['packet_size']} bytes - "
                  f"Confidence: {example['confidence']:.3f}")
    
    return df

# Method 5: Real-time monitoring with filtering
def monitor_specific_traffic(classifier, target_class='web_traffic', min_confidence=0.7):
    """Monitor and alert for specific types of network traffic"""
    from scapy.all import sniff
    import time
    
    print(f"Monitoring for {target_class} with confidence >= {min_confidence}")
    print("Press Ctrl+C to stop...")
    
    detected_count = 0
    start_time = time.time()
    
    def packet_handler(packet):
        nonlocal detected_count
        
        predicted_class, confidence = classifier.predict_packet_class(packet)
        
        if predicted_class == target_class and confidence >= min_confidence:
            detected_count += 1
            timestamp = time.strftime("%H:%M:%S", time.localtime())
            print(f"[{timestamp}] DETECTED: {predicted_class} "
                  f"(confidence: {confidence:.3f}) - "
                  f"Total detected: {detected_count}")
    
    try:
        sniff(prn=packet_handler, timeout=60)  # Monitor for 60 seconds
        
        elapsed_time = time.time() - start_time
        print(f"\nMonitoring completed:")
        print(f"Time elapsed: {elapsed_time:.1f} seconds")
        print(f"Total {target_class} detected: {detected_count}")
        
    except KeyboardInterrupt:
        print(f"\nMonitoring stopped by user")
        print(f"Total {target_class} detected: {detected_count}")

# Example usage functions
if __name__ == "__main__":
    # Assuming your classifier is already trained and available
    # Replace 'classifier' with your actual trained classifier object
    
    print("=== PACKET CLASSIFICATION EXAMPLES ===\n")
    
    # Example 1: Classify a new pcap file
    print("1. Classifying packets from a new pcap file:")
    new_pcap = "E:/pcap/new_traffic.pcap"  # Update with your file
    # results = classify_new_pcap_file(classifier, new_pcap)
    
    print("\n2. Classifying synthetic packets:")
    # classify_packet_examples(classifier)
    
    print("\n3. Detailed analysis of a pcap file:")
    # analysis_df = detailed_packet_analysis(classifier, new_pcap)
    
    print("\n4. Live packet classification:")
    # classify_live_packets(classifier, interface='Wi-Fi', packet_count=20)
    
    print("\n5. Monitor specific traffic:")
    # monitor_specific_traffic(classifier, target_class='web_traffic', min_confidence=0.8)
    
    print("\n=== USAGE INSTRUCTIONS ===")
    print("To use these functions with your trained classifier:")
    print("1. Ensure your classifier object is available in the scope")
    print("2. Uncomment the function calls above")
    print("3. Update file paths and interface names as needed")
    print("4. Run the specific function you want to use")

# Quick prediction function for single packets
def quick_predict(classifier, packet):
    """Quick prediction with formatted output"""
    predicted_class, confidence = classifier.predict_packet_class(packet)
    
    print(f"Prediction: {predicted_class}")
    print(f"Confidence: {confidence:.3f}")
    
    if confidence > 0.8:
        print("Classification: High confidence ✓")
    elif confidence > 0.5:
        print("Classification: Medium confidence ~")
    else:
        print("Classification: Low confidence ⚠️")
    
    return predicted_class, confidence