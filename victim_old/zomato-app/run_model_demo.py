#!/usr/bin/env python3
"""
Network Anomaly Detection Demo Script
-------------------------------------
This script demonstrates the anomaly detection capabilities by running the model
against the KDD dataset and displaying detailed threat information.
"""

import sys
import os
import time
import requests
import json
from datetime import datetime
from tabulate import tabulate
from colorama import init, Fore, Back, Style

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Initialize colorama for colored terminal output
init()

try:
    from app.services.anomaly_detection.detector import process_kdd_dataset, get_latest_anomalies, detected_anomalies
    from app.services.anomaly_detection.detector import BLOCKCHAIN_ENDPOINT, THREAT_ENDPOINT, CRITICAL_CONFIDENCE_THRESHOLD
except ImportError:
    print(f"{Fore.RED}Error importing modules. Make sure you're running this from the zomato-app directory.{Style.RESET_ALL}")
    sys.exit(1)

def print_header(text):
    """Print a formatted header."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}" + "=" * 80)
    print(f" {text}")
    print("=" * 80 + f"{Style.RESET_ALL}\n")

def print_threat(threat, full_details=False):
    """Print a formatted threat."""
    confidence = threat.get('highest_confidence', 0)
    
    # Determine color based on confidence
    if confidence >= 0.9:
        color = Fore.RED + Style.BRIGHT
        risk = "CRITICAL"
    elif confidence >= 0.85:
        color = Fore.RED
        risk = "HIGH"
    elif confidence >= 0.7:
        color = Fore.YELLOW
        risk = "MEDIUM"
    else:
        color = Fore.GREEN
        risk = "LOW"
    
    print(f"{color}[{risk} RISK - {confidence*100:.1f}%] {Style.RESET_ALL}")
    
    # Print basic information
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
    
    # Print full details if requested
    if full_details:
        print("\n  Additional Details:")
        print(f"    Source Bytes: {threat.get('src_bytes', 'N/A')}")
        print(f"    Destination Bytes: {threat.get('dst_bytes', 'N/A')}")
        print(f"    Duration: {threat.get('duration', 'N/A')} seconds")
        
        # Print error rates if available
        if 'serror_rate' in threat:
            print(f"    SYN Error Rate: {threat.get('serror_rate', 'N/A')}")
        if 'rerror_rate' in threat:
            print(f"    REJ Error Rate: {threat.get('rerror_rate', 'N/A')}")
    
    print()

def fetch_blockchain_data():
    """Fetch data from the Zero Day Sentinel blockchain endpoint."""
    print(f"Fetching data from {BLOCKCHAIN_ENDPOINT}...")
    try:
        response = requests.get(BLOCKCHAIN_ENDPOINT, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"{Fore.RED}Error: HTTP {response.status_code}{Style.RESET_ALL}")
            return None
    except Exception as e:
        print(f"{Fore.RED}Error fetching blockchain data: {str(e)}{Style.RESET_ALL}")
        return None

def display_blockchain_data(blockchain_data):
    """Display formatted blockchain data."""
    if not blockchain_data:
        return
    
    if 'chain' in blockchain_data:
        chain = blockchain_data['chain']
        print(f"\nBlockchain contains {len(chain)} blocks.\n")
        
        headers = ["Block", "Timestamp", "Type", "IP", "Severity", "Details"]
        table_data = []
        
        for i, block in enumerate(chain):
            # Extract data
            data = block.get('data', {})
            timestamp = block.get('timestamp', 'Unknown')
            block_hash = block.get('hash', 'Unknown')[:8] + "..."  # Truncate for display
            
            # Handle genesis block differently
            if i == 0 or 'message' in data:
                row = [
                    i, 
                    timestamp, 
                    "Genesis", 
                    "N/A", 
                    "N/A", 
                    data.get('message', 'Unknown')
                ]
            else:
                # Handle threat blocks
                attack_type = data.get('attack_type', 'Unknown')
                ip = data.get('ip', '0.0.0.0')
                severity = data.get('severity', 'Unknown')
                details = data.get('details', {})
                
                # Format details for display
                detail_str = ""
                if 'protocol' in details:
                    detail_str += f"Protocol: {details['protocol']}, "
                if 'destination_port' in details:
                    detail_str += f"Port: {details['destination_port']}, "
                if 'flag' in details and details['flag'] != 'N/A':
                    detail_str += f"Flag: {details['flag']}"
                
                row = [i, timestamp, attack_type, ip, severity, detail_str]
            
            table_data.append(row)
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
    else:
        print(f"{Fore.RED}Invalid blockchain data format{Style.RESET_ALL}")

def main():
    """Main function to run the demo."""
    print_header("Network Anomaly Detection Demo")
    
    # Display information about the model
    print(f"Critical Confidence Threshold: {CRITICAL_CONFIDENCE_THRESHOLD}")
    print(f"Threat Endpoint: {THREAT_ENDPOINT}")
    print(f"Blockchain Endpoint: {BLOCKCHAIN_ENDPOINT}")
    
    # First, check if the dataset exists
    dataset_path = os.path.join('data_kdd', 'kdd_test.csv')
    if not os.path.exists(dataset_path):
        print(f"{Fore.RED}Error: Dataset not found at {dataset_path}{Style.RESET_ALL}")
        return
    
    print(f"\nUsing dataset: {dataset_path}")
    print("Starting detection process...")
    
    # Process the dataset in a separate thread to allow us to continue displaying results
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
    print_header("Detected Threats")
    
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
                    print_threat(anomaly, full_details=True)
                    detected_count += 1
                
                last_size = current_size
            
            # Sleep briefly to allow more detection
            time.sleep(1)
            
        print(f"\nDetected {detected_count} threats in total.")
    except KeyboardInterrupt:
        print("\nDetection stopped by user.")
    
    # Fetch and display blockchain data
    print_header("Zero Day Sentinel Blockchain Data")
    blockchain_data = fetch_blockchain_data()
    if blockchain_data:
        display_blockchain_data(blockchain_data)
    
    print("\nDemo completed.")

if __name__ == "__main__":
    main() 