#!/usr/bin/env python3
"""
Blockchain Data Fetch and Display
--------------------------------
Fetches data from the Zero Day Sentinel blockchain and displays it in a formatted way.
"""

import sys
import os
import json
import requests
from datetime import datetime

# The blockchain endpoint
BLOCKCHAIN_ENDPOINT = "https://zero-day-sentinel.onrender.com/chain"

def print_header(text):
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(" " + text)
    print("=" * 80 + "\n")

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
        
        for i, block in enumerate(chain):
            # Extract data
            data = block.get('data', {})
            timestamp = block.get('timestamp', 'Unknown')
            block_hash = block.get('hash', 'Unknown')
            
            print(f"Block #{i} - {timestamp}")
            print(f"Hash: {block_hash}")
            
            # Handle genesis block differently
            if i == 0 or 'message' in data:
                print(f"Type: Genesis")
                print(f"Message: {data.get('message', 'Unknown')}")
            else:
                # Handle threat blocks
                attack_type = data.get('attack_type', 'Unknown')
                ip = data.get('ip', '0.0.0.0')
                severity = data.get('severity', 'Unknown')
                details = data.get('details', {})
                
                print(f"Type: {attack_type}")
                print(f"IP: {ip}")
                print(f"Severity: {severity}")
                
                # Print details if available
                if details:
                    print("Details:")
                    for key, value in details.items():
                        print(f"  {key}: {value}")
            
            # Separator between blocks
            print("-" * 40)
    else:
        print("Invalid blockchain data format")

def main():
    """Main function."""
    print_header("Zero Day Sentinel Blockchain Data")
    
    # Fetch and display blockchain data
    blockchain_data = fetch_blockchain_data()
    if blockchain_data:
        display_blockchain_data(blockchain_data)
    else:
        print("Failed to fetch blockchain data.")
    
    print("\nComplete.")

if __name__ == "__main__":
    main() 