#!/usr/bin/env python
"""
Quick script to test anomaly detection with the KDD dataset
"""
import os
import sys
import time
from app.services.anomaly_detection.detector import (
    process_kdd_dataset, 
    get_latest_anomalies,
    AUTO_REPORT_ENABLED
)

def main():
    """Run the anomaly detection on the KDD dataset"""
    # Set auto-reporting to True for testing
    global AUTO_REPORT_ENABLED
    AUTO_REPORT_ENABLED = True
    
    print("Starting anomaly detection test...")
    print(f"Auto-reporting is {'ENABLED' if AUTO_REPORT_ENABLED else 'DISABLED'}")
    
    # Determine dataset path
    dataset_path = os.path.join('data_kdd', 'kdd_test.csv')
    if not os.path.exists(dataset_path):
        print(f"Dataset not found at {dataset_path}")
        sys.exit(1)
    
    print(f"Using dataset: {dataset_path}")
    
    # Process the dataset - with only the required parameters
    process_kdd_dataset(
        dataset_path,  # First parameter is the dataset file path
        10,            # Process small batches (batch_size)
        1              # 1 second between batches (sleep_interval)
    )
    
    # Get and display detected anomalies
    anomalies = get_latest_anomalies(max_items=100)
    print(f"\nDetected {len(anomalies)} anomalies:")
    
    for i, anomaly in enumerate(anomalies, 1):
        confidence = anomaly.get('highest_confidence', 0)
        severity = 'CRITICAL' if confidence >= 0.9 else \
                  'HIGH' if confidence >= 0.85 else \
                  'MEDIUM' if confidence >= 0.7 else 'LOW'
        
        print(f"{i}. {severity} ({confidence:.2f}): {anomaly.get('protocol_type')} - {anomaly.get('service')} - {anomaly.get('alert_types')}")
    
    print("\nTest completed.")

if __name__ == "__main__":
    main() 