#!/usr/bin/env python3
"""
Complete Security Status Display
-------------------------------
This script provides a comprehensive view of the security status,
including active threats, risk rates, and blockchain integration.
"""

import sys
import os
import time
import json
import requests
from datetime import datetime

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    # Import detector module
    from app.services.anomaly_detection.detector import (
        process_kdd_dataset, get_latest_anomalies, detected_anomalies,
        BLOCKCHAIN_ENDPOINT, THREAT_ENDPOINT, CRITICAL_CONFIDENCE_THRESHOLD, AUTO_REPORT_ENABLED
    )
except ImportError:
    print("Error importing modules. Make sure you're running this from the zomato-app directory.")
    sys.exit(1)

def print_header(title):
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(" " + title)
    print("=" * 80 + "\n")

def print_threat(threat, index=None):
    """Print threat details with color-coded risk level."""
    confidence = threat.get('highest_confidence', 0)
    
    # Determine risk level based on confidence
    if confidence >= 0.9:
        risk_level = "CRITICAL"
        color_start = "\033[1;31m"  # Bold Red
    elif confidence >= 0.85:
        risk_level = "HIGH"
        color_start = "\033[31m"    # Red
    elif confidence >= 0.7:
        risk_level = "MEDIUM"
        color_start = "\033[33m"    # Yellow
    else:
        risk_level = "LOW"
        color_start = "\033[32m"    # Green
    
    color_end = "\033[0m"
    
    # Print threat number if provided
    if index is not None:
        print(f"Threat #{index + 1}")
    
    # Print risk level with coloring
    print(f"{color_start}[{risk_level} RISK - {confidence*100:.1f}%]{color_end}")
    
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
    
    # Print reporting status
    if confidence >= CRITICAL_CONFIDENCE_THRESHOLD:
        if AUTO_REPORT_ENABLED:
            print(f"  {color_start}Reporting Status: Automatically reported to {THREAT_ENDPOINT}{color_end}")
        else:
            print(f"  {color_start}Reporting Status: NOT reported (Auto-reporting disabled){color_end}")
    
    print()

def fetch_blockchain_data():
    """Fetch data from the Zero Day Sentinel blockchain endpoint."""
    print(f"Fetching data from {BLOCKCHAIN_ENDPOINT}...")
    try:
        response = requests.get(BLOCKCHAIN_ENDPOINT, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: HTTP {response.status_code}")
            return None
    except Exception as e:
        print(f"Error fetching blockchain data: {str(e)}")
        return None

def display_blockchain_data(blockchain_data):
    """Display formatted blockchain data."""
    if not blockchain_data:
        return
    
    if 'chain' in blockchain_data:
        chain = blockchain_data['chain']
        print(f"\nBlockchain contains {len(chain)} blocks.\n")
        
        # Count threat types
        threat_types = {}
        threat_severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for i, block in enumerate(chain):
            # Extract data
            data = block.get('data', {})
            timestamp = block.get('timestamp', 'Unknown')
            block_hash = block.get('hash', 'Unknown')
            
            print(f"Block #{i} - {timestamp}")
            print(f"Hash: {block_hash[:16]}...{block_hash[-16:] if len(block_hash) > 32 else block_hash}")
            
            # Handle genesis block differently
            if i == 0 or 'message' in data:
                print(f"Type: Genesis")
                print(f"Message: {data.get('message', 'Unknown')}")
            else:
                # Handle threat blocks
                attack_type = data.get('attack_type', 'Unknown')
                ip = data.get('ip', '0.0.0.0')
                severity = data.get('severity', 'Unknown').lower()
                details = data.get('details', {})
                
                # Update statistics
                if attack_type in threat_types:
                    threat_types[attack_type] += 1
                else:
                    threat_types[attack_type] = 1
                    
                if severity in threat_severities:
                    threat_severities[severity] += 1
                
                # Apply color based on severity
                if severity == 'critical':
                    severity_str = f"\033[1;31m{severity.upper()}\033[0m"  # Bold Red
                elif severity == 'high':
                    severity_str = f"\033[31m{severity.upper()}\033[0m"    # Red
                elif severity == 'medium':
                    severity_str = f"\033[33m{severity.upper()}\033[0m"    # Yellow
                else:
                    severity_str = f"\033[32m{severity.upper()}\033[0m"    # Green
                
                print(f"Type: {attack_type}")
                print(f"IP: {ip}")
                print(f"Severity: {severity_str}")
                
                # Print details if available
                if details:
                    print("Details:")
                    for key, value in details.items():
                        print(f"  {key}: {value}")
            
            # Separator between blocks
            print("-" * 40)
        
        # Print statistics after displaying all blocks
        if threat_types:
            print("\nThreat Type Distribution:")
            for attack_type, count in threat_types.items():
                print(f"  {attack_type}: {count} occurrences")
        
        if sum(threat_severities.values()) > 0:
            print("\nSeverity Distribution:")
            for severity, count in threat_severities.items():
                # Apply color based on severity
                if severity == 'critical':
                    severity_str = f"\033[1;31m{severity.upper()}\033[0m"  # Bold Red
                elif severity == 'high':
                    severity_str = f"\033[31m{severity.upper()}\033[0m"    # Red
                elif severity == 'medium':
                    severity_str = f"\033[33m{severity.upper()}\033[0m"    # Yellow
                else:
                    severity_str = f"\033[32m{severity.upper()}\033[0m"    # Green
                print(f"  {severity_str}: {count} occurrences")
    else:
        print("Invalid blockchain data format")

def process_dataset():
    """Process the KDD dataset and return all detected threats."""
    dataset_path = os.path.join('data_kdd', 'kdd_test.csv')
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        return []
    
    print(f"Processing dataset: {dataset_path}")
    
    # Use a small batch size for quicker results
    process_kdd_dataset(dataset_path, batch_size=10, sleep_interval=0)
    
    # Return all detected anomalies
    return detected_anomalies.copy()

def check_auto_report_status():
    """Check and display the auto-reporting status."""
    status = "ENABLED" if AUTO_REPORT_ENABLED else "DISABLED"
    
    if AUTO_REPORT_ENABLED:
        print(f"Auto-reporting is currently {status}.")
        print(f"Threats with confidence level ≥ {CRITICAL_CONFIDENCE_THRESHOLD * 100:.1f}% will be automatically reported to {THREAT_ENDPOINT}")
    else:
        print(f"Auto-reporting is currently {status}.")
        print(f"Critical threats will be detected but NOT reported to the external endpoint.")
        print("To enable auto-reporting, run:")
        print("  python toggle_auto_report.py --enable")

def display_security_summary(threats):
    """Display a summary of the security status."""
    # Group threats by risk level
    critical_threats = []
    high_threats = []
    medium_threats = []
    low_threats = []
    
    for threat in threats:
        confidence = threat.get('highest_confidence', 0)
        if confidence >= 0.9:
            critical_threats.append(threat)
        elif confidence >= 0.85:
            high_threats.append(threat)
        elif confidence >= 0.7:
            medium_threats.append(threat)
        else:
            low_threats.append(threat)
    
    # Calculate the overall security status
    if len(critical_threats) > 0:
        status = "\033[1;31mCRITICAL\033[0m"  # Bold Red
    elif len(high_threats) > 0:
        status = "\033[31mHIGH RISK\033[0m"   # Red
    elif len(medium_threats) > 0:
        status = "\033[33mMEDIUM RISK\033[0m" # Yellow
    elif len(low_threats) > 0:
        status = "\033[32mLOW RISK\033[0m"    # Green
    else:
        status = "\033[32mSECURE\033[0m"      # Green
    
    # Display summary
    print(f"Security Status: {status}")
    print(f"Total Threats: {len(threats)}")
    print(f"Critical Threats: {len(critical_threats)}")
    print(f"High Risk Threats: {len(high_threats)}")
    print(f"Medium Risk Threats: {len(medium_threats)}")
    print(f"Low Risk Threats: {len(low_threats)}")
    
    if len(critical_threats) > 0:
        print("\n\033[1;31mWARNING: Critical threats detected! Immediate action recommended.\033[0m")

def main():
    """Main function."""
    print_header("Network Security Status Dashboard")
    
    # Display configuration
    print("Configuration:")
    print(f"Critical Confidence Threshold: {CRITICAL_CONFIDENCE_THRESHOLD}")
    check_auto_report_status()
    print(f"Blockchain Endpoint: {BLOCKCHAIN_ENDPOINT}")
    print(f"Threat Endpoint: {THREAT_ENDPOINT}")
    
    # Process dataset and get threats
    threats = process_dataset()
    
    # Sort threats by confidence level (highest first)
    threats.sort(key=lambda x: x.get('highest_confidence', 0), reverse=True)
    
    # Display security summary
    print_header("Security Status Summary")
    display_security_summary(threats)
    
    # Display ALL detected threats with risk rates
    print_header(f"ALL Detected Threats ({len(threats)} total)")
    
    for i, threat in enumerate(threats):
        print_threat(threat, i)
    
    # Fetch and display blockchain data
    print_header("Zero Day Sentinel Blockchain Data")
    blockchain_data = fetch_blockchain_data()
    if blockchain_data:
        display_blockchain_data(blockchain_data)
    else:
        print("Failed to fetch blockchain data.")
    
    print("\nStatus check completed.")

if __name__ == "__main__":
    main() 