#!/usr/bin/env python3
"""
Simplified Anomaly Detector and Display
--------------------------------------
This script runs anomaly detection on the KDD dataset and displays results.
"""

import sys
import os
import time
import json
from datetime import datetime

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from app.services.anomaly_detection.detector import process_kdd_dataset, get_latest_anomalies, detected_anomalies
    from app.services.anomaly_detection.detector import BLOCKCHAIN_ENDPOINT, THREAT_ENDPOINT, CRITICAL_CONFIDENCE_THRESHOLD, AUTO_REPORT_ENABLED
except ImportError:
    print("Error importing modules. Make sure you're running this from the zomato-app directory.")
    sys.exit(1)

def print_section(title):
    """Print a section header."""
    print("\n" + "=" * 80)
    print(" " + title)
    print("=" * 80 + "\n")

def print_threat(threat):
    """Print threat details."""
    confidence = threat.get('highest_confidence', 0)
    risk_level = "CRITICAL" if confidence >= 0.9 else "HIGH" if confidence >= 0.85 else "MEDIUM" if confidence >= 0.7 else "LOW"
    
    print(f"[{risk_level} RISK - {confidence*100:.1f}%]")
    print(f"  Timestamp: {threat.get('timestamp', 'N/A')}")
    print(f"  Source: {threat.get('src_ip', 'unknown')}")
    print(f"  Destination: {threat.get('dst_ip', 'unknown')}")
    print(f"  Protocol: {threat.get('protocol_type', 'unknown')}")
    print(f"  Service: {threat.get('service', 'unknown')}")
    print(f"  Flag: {threat.get('flag', 'unknown')}")
    
    # Format alert types
    alert_types = threat.get('alert_types', [])
    if isinstance(alert_types, list):
        alert_str = ", ".join(alert_types)
    else:
        alert_str = str(alert_types)
    print(f"  Alert Types: {alert_str}")
    
    # Print additional details
    print("  Additional Details:")
    print(f"    Source Bytes: {threat.get('src_bytes', 'N/A')}")
    print(f"    Destination Bytes: {threat.get('dst_bytes', 'N/A')}")
    print(f"    Duration: {threat.get('duration', 'N/A')} seconds")
    
    # Print error rates if available
    if 'serror_rate' in threat:
        print(f"    SYN Error Rate: {threat.get('serror_rate', 'N/A')}")
    if 'rerror_rate' in threat:
        print(f"    REJ Error Rate: {threat.get('rerror_rate', 'N/A')}")
    
    print()

def main():
    """Main function."""
    print_section("Network Anomaly Detection Demo")
    
    # Display configuration
    print(f"Critical Confidence Threshold: {CRITICAL_CONFIDENCE_THRESHOLD}")
    print(f"Auto Reporting Enabled: {AUTO_REPORT_ENABLED}")
    print(f"Threat Endpoint: {THREAT_ENDPOINT}")
    print(f"Blockchain Endpoint: {BLOCKCHAIN_ENDPOINT}")
    
    # First, check if the dataset exists
    dataset_path = os.path.join('data_kdd', 'kdd_test.csv')
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        return
    
    print(f"\nUsing dataset: {dataset_path}")
    print("Starting detection process...")
    
    # Process the dataset
    import threading
    detection_thread = threading.Thread(
        target=process_kdd_dataset,
        args=(dataset_path, 10, 1),  # Batch size 10, sleep interval 1s
        daemon=True
    )
    detection_thread.start()
    
    # Wait for processing to begin
    time.sleep(2)
    
    # Display threats as they're detected
    print_section("Detected Threats")
    
    try:
        detected_count = 0
        last_size = 0
        
        # Display for 30 seconds or until user interrupts
        for _ in range(30):
            # Get any new anomalies
            current_size = len(detected_anomalies)
            if current_size > last_size:
                # Display new anomalies
                for i in range(last_size, current_size):
                    anomaly = detected_anomalies[i]
                    print_threat(anomaly)
                    detected_count += 1
                
                last_size = current_size
            
            # Sleep briefly to allow more detection
            time.sleep(1)
            
        print(f"\nDetected {detected_count} threats in total.")
    except KeyboardInterrupt:
        print("\nDetection stopped by user.")
    
    print("\nDemo completed.")

if __name__ == "__main__":
    main() 