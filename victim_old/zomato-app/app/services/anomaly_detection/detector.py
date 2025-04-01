"""
Network Anomaly Detection Module
--------------------------------
This module provides rule-based network traffic anomaly detection
using the KDD Cup dataset format, integrated with the Zomato application.
"""

import pandas as pd
import numpy as np
import time
from datetime import datetime
import queue
import os
import threading
import requests

# Import threat intelligence service
try:
    from app.services.anomaly_detection.threat_intel import threat_intel
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    print("Threat intelligence module not available, continuing without it")
    THREAT_INTEL_AVAILABLE = False

# Global queue for real-time anomaly updates
anomaly_queue = queue.Queue()

# Global list for storing detected anomalies
detected_anomalies = []

# External threat reporting endpoint
THREAT_ENDPOINT = "https://zero-day-sentinel.onrender.com/threat"
BLOCKCHAIN_ENDPOINT = "https://zero-day-sentinel.onrender.com/chain"

# Critical threshold for reporting to external endpoint
CRITICAL_CONFIDENCE_THRESHOLD = 0.85

# Global variable to control auto-reporting
AUTO_REPORT_ENABLED = True

class RuleBasedDetector:
    """
    Rule-based anomaly detector for network traffic data.
    Analyzes network connections based on predefined rules and thresholds.
    """
    
    def __init__(self):
        """Initialize detector with predefined rules."""
        # Define rules for different attack types
        self.rules = {
            # Known attack services
            'suspicious_services': ['finger', 'ftp_data', 'imap4', 'mtp', 'netbios_dgm', 
                                    'netbios_ns', 'pop_3', 'rje', 'shell', 'sql_net', 'supdup'],
            
            # Suspicious protocol-flag combinations
            'protocol_flag_combos': [
                ('tcp', 'REJ'), ('tcp', 'RSTO'), ('tcp', 'RSTOSO'), ('tcp', 'S0'),
                ('tcp', 'S1'), ('tcp', 'S2'), ('tcp', 'S3'), ('tcp', 'SF')
            ],
            
            # Thresholds for numeric features
            'thresholds': {
                'duration': 300,  # Long connection duration in seconds
                'src_bytes': 100000,  # Large data transfer from source
                'dst_bytes': 100000,  # Large data transfer to destination
                'count': 100,  # High connection count to same host
                'srv_count': 100,  # High connection count to same service
                'serror_rate': 0.7,  # High SYN error rate
                'srv_serror_rate': 0.7,  # High service SYN error rate
                'rerror_rate': 0.7,  # High REJ error rate
                'srv_rerror_rate': 0.7,  # High service REJ error rate
                'same_srv_rate': 0.9,  # High same service rate
            }
        }
        
        # Known attack labels from KDD dataset
        self.attack_labels = [
            'back', 'buffer_overflow', 'ftp_write', 'guess_passwd', 'imap', 
            'ipsweep', 'land', 'loadmodule', 'multihop', 'neptune', 'nmap', 'perl', 
            'phf', 'pod', 'portsweep', 'rootkit', 'satan', 'smurf', 'spy', 
            'teardrop', 'warezclient', 'warezmaster'
        ]
        
        # Track IP addresses for rate limiting
        self.connection_tracker = {}
        
        # If threat intelligence is available, fetch known threats
        self.known_threat_services = set()
        if THREAT_INTEL_AVAILABLE:
            try:
                self.update_threat_intelligence()
            except Exception as e:
                print(f"Error initializing threat intelligence: {str(e)}")
    
    def update_threat_intelligence(self):
        """Update the detector with the latest threat intelligence data."""
        if not THREAT_INTEL_AVAILABLE:
            return
            
        try:
            threats = threat_intel.get_known_threats()
            if threats:
                # Extract services from known threats
                self.known_threat_services = set([
                    threat.get('service') for threat in threats 
                    if threat.get('service')
                ])
                
                # Add known threat services to our suspicious services list
                self.rules['suspicious_services'].extend(
                    [s for s in self.known_threat_services 
                     if s not in self.rules['suspicious_services']]
                )
                
                print(f"Updated with {len(threats)} known threats")
        except Exception as e:
            print(f"Error updating threat intelligence: {str(e)}")
        
    def check_rules(self, row):
        """
        Apply detection rules to a network connection record.
        
        Args:
            row: Pandas Series or dict containing connection data
            
        Returns:
            List of tuples with (alert_type, confidence_score)
        """
        alerts = []
        
        # Check for attacks by service type
        if row['service'] in self.rules['suspicious_services']:
            alerts.append(('suspicious_service', 0.7))
        
        # Check for suspicious protocol-flag combinations
        if (row['protocol_type'], row['flag']) in self.rules['protocol_flag_combos']:
            if row['flag'] in ['S0', 'S1', 'S2', 'S3']:
                alerts.append(('potential_scan', 0.8))
            elif row['flag'] in ['REJ', 'RSTO', 'RSTOSO']:
                alerts.append(('connection_rejected', 0.6))
        
        # Check thresholds for numeric features
        if row['duration'] > self.rules['thresholds']['duration']:
            alerts.append(('long_duration', 0.7))
            
        if row['src_bytes'] > self.rules['thresholds']['src_bytes']:
            alerts.append(('high_data_transfer', 0.8))
            
        if row['dst_bytes'] > self.rules['thresholds']['dst_bytes']:
            alerts.append(('high_data_received', 0.8))
            
        if row['count'] > self.rules['thresholds']['count']:
            alerts.append(('high_connection_count', 0.9))
            
        # Check error rates
        if row['serror_rate'] > self.rules['thresholds']['serror_rate']:
            alerts.append(('high_syn_error_rate', 0.95))
            
        if row['rerror_rate'] > self.rules['thresholds']['rerror_rate']:
            alerts.append(('high_reject_rate', 0.85))
        
        # If the dataset already has labels, use them
        if 'labels' in row and row['labels'] in self.attack_labels:
            alerts.append((f'known_attack_{row["labels"]}', 1.0))
            
        return alerts
        
    def process_batch(self, batch):
        """
        Process a batch of network traffic records.
        
        Args:
            batch: DataFrame with network traffic records
            
        Returns:
            List of detected anomalies with details
        """
        batch_anomalies = []
        
        for _, row in batch.iterrows():
            # Apply rules
            alerts = self.check_rules(row)
            
            # If alerts found, create an anomaly entry
            if alerts:
                # Extract highest confidence score
                highest_confidence = max([conf for _, conf in alerts])
                
                # Create anomaly entry
                anomaly = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'src_ip': row.get('src_ip', 'unknown'),
                    'dst_ip': row.get('dst_ip', 'unknown'),
                    'protocol_type': row.get('protocol_type', 'unknown'),
                    'service': row.get('service', 'unknown'),
                    'flag': row.get('flag', 'unknown'),
                    'duration': row.get('duration', 0),
                    'src_bytes': row.get('src_bytes', 0),
                    'dst_bytes': row.get('dst_bytes', 0),
                    'alert_types': [alert_type for alert_type, _ in alerts],
                    'confidence_scores': [conf for _, conf in alerts],
                    'highest_confidence': highest_confidence
                }
                
                # Add anomaly to results
                batch_anomalies.append(anomaly)
                
                # Add to global queue for real-time updates
                anomaly_queue.put(anomaly)
                
                # Keep track of top anomalies
                detected_anomalies.append(anomaly)
                
                # Send critical threats to external endpoint if auto-reporting is enabled
                if highest_confidence >= CRITICAL_CONFIDENCE_THRESHOLD and AUTO_REPORT_ENABLED:
                    threading.Thread(target=send_to_threat_endpoint, args=(anomaly,)).start()
        
        # Keep only the most recent anomalies
        if len(detected_anomalies) > 100:
            detected_anomalies.pop(0)
        
        return batch_anomalies

# Function to get the latest anomalies from the queue
def get_latest_anomalies(max_items=10):
    """
    Get the latest anomalies from the queue without blocking.
    
    Args:
        max_items: Maximum number of items to retrieve
        
    Returns:
        List of anomaly dictionaries
    """
    anomalies = []
    for _ in range(max_items):
        try:
            # Non-blocking get
            anomaly = anomaly_queue.get_nowait()
            anomalies.append(anomaly)
            anomaly_queue.task_done()
        except queue.Empty:
            break
    return anomalies

# Function to process a dataset file in batches for real-time simulation
def process_kdd_dataset(file_path, batch_size=100, sleep_interval=1):
    """
    Process a KDD dataset file in batches, simulating real-time detection.
    
    Args:
        file_path: Path to the KDD dataset CSV file
        batch_size: Number of records to process in each batch
        sleep_interval: Seconds to wait between batches
        
    Returns:
        None (results are added to anomaly_queue)
    """
    detector = RuleBasedDetector()
    
    # Load dataset with correct column names
    print(f"Loading KDD dataset from {file_path}...")
    
    try:
        # Attempt to load the dataset - ensure the first row is used as headers
        df = pd.read_csv(file_path)
        print(f"Loaded dataset with {len(df)} records and {len(df.columns)} columns")
        print(f"Column names: {df.columns.tolist()}")
        
        # Check if required columns exist
        required_columns = ['protocol_type', 'service', 'flag', 'duration', 'src_bytes', 'dst_bytes', 
                           'count', 'serror_rate', 'rerror_rate', 'srv_count']
                           
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            print(f"Error: Missing required columns: {missing_columns}")
            return None
        
        # Process in batches
        print(f"Processing in batches of {batch_size} records...")
        batch_count = 0
        
        for i in range(0, len(df), batch_size):
            batch_count += 1
            batch = df.iloc[i:i+batch_size]
            
            print(f"Processing batch {batch_count} with {len(batch)} records")
            anomalies = detector.process_batch(batch)
            
            if len(anomalies) > 0:
                print(f"Batch {batch_count}: Found {len(anomalies)} anomalies")
                # Print first anomaly for debugging
                first_anomaly = anomalies[0] if anomalies else {}
                print(f"Sample anomaly: {first_anomaly}")
            else:
                print(f"Batch {batch_count}: No anomalies detected")
                
            # Simulate real-time processing
            time.sleep(sleep_interval)
            
    except Exception as e:
        print(f"Error processing dataset: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

# Global flag to track if detection is running
detection_running = False

# Main function to start the detection process
def start_anomaly_detection(dataset_path=None):
    """
    Start the anomaly detection process using the specified dataset.
    
    Args:
        dataset_path: Path to the KDD dataset file
        
    Returns:
        True if started successfully, False otherwise
    """
    global detection_running
    global detected_anomalies
    
    # Don't start if already running
    if detection_running:
        print("Detection already running, not starting again")
        return False
    
    try:
        # Clear the anomaly queue before starting
        while not anomaly_queue.empty():
            try:
                anomaly_queue.get_nowait()
                anomaly_queue.task_done()
            except:
                break
        
        # Clear detected anomalies list
        detected_anomalies = []
        
        print(f"Attempting to start anomaly detection with dataset: {dataset_path}")
        
        # Handle relative vs absolute paths
        if dataset_path:
            abs_path = os.path.abspath(dataset_path)
            print(f"Absolute path: {abs_path}")
            
            if os.path.exists(abs_path):
                print(f"Dataset file exists at: {abs_path}")
                # Start in a separate thread to not block the web application
                detection_thread = threading.Thread(
                    target=process_kdd_dataset,
                    args=(abs_path, 100, 5),
                    daemon=True
                )
                detection_running = True
                detection_thread.start()
                print("Detection thread started successfully")
                return True
            else:
                print(f"Dataset file does not exist at: {abs_path}")
                
                # Try in the current working directory
                cwd = os.getcwd()
                alt_path = os.path.join(cwd, dataset_path)
                print(f"Trying alternate path: {alt_path}")
                
                if os.path.exists(alt_path):
                    print(f"Dataset found at alternate path: {alt_path}")
                    detection_thread = threading.Thread(
                        target=process_kdd_dataset,
                        args=(alt_path, 100, 5),
                        daemon=True
                    )
                    detection_running = True
                    detection_thread.start()
                    print("Detection thread started successfully with alternate path")
                    return True
                else:
                    print(f"Dataset not found at alternate path: {alt_path}")
                    return False
        else:
            print("No dataset path provided")
            return False
    except Exception as e:
        print(f"Error starting anomaly detection: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

# Function to stop detection
def stop_anomaly_detection():
    """
    Stop the anomaly detection process.
    
    Returns:
        True if stopped successfully, False otherwise
    """
    global detection_running
    detection_running = False
    
    # If threat intel is available, report all high-confidence anomalies
    if THREAT_INTEL_AVAILABLE and detected_anomalies:
        try:
            # Filter high-confidence anomalies
            high_confidence_anomalies = [
                a for a in detected_anomalies 
                if a.get('highest_confidence', 0) > 0.8
            ]
            
            if high_confidence_anomalies:
                print(f"Reporting {len(high_confidence_anomalies)} high-confidence anomalies to threat intelligence")
                threat_intel.bulk_report_anomalies(high_confidence_anomalies)
        except Exception as e:
            print(f"Error reporting to threat intelligence: {str(e)}")
    
    return True

# Function to fetch external threats
def fetch_external_threats():
    """
    Fetch threats from external threat intelligence.
    
    Returns:
        List of threat dictionaries or None if unavailable
    """
    if not THREAT_INTEL_AVAILABLE:
        return None
        
    try:
        return threat_intel.get_known_threats()
    except Exception as e:
        print(f"Error fetching external threats: {str(e)}")
        return None

def send_to_threat_endpoint(anomaly):
    """
    Send critical threats to the external threat endpoint.
    
    Args:
        anomaly: Dictionary containing anomaly details
    """
    # Skip if auto-reporting is disabled
    if not AUTO_REPORT_ENABLED:
        print("Auto-reporting disabled, skipping report to /threat endpoint")
        return
        
    try:
        threat_data = {
            'timestamp': anomaly['timestamp'],
            'source_ip': anomaly['src_ip'],
            'destination_ip': anomaly['dst_ip'],
            'protocol': anomaly['protocol_type'],
            'service': anomaly['service'],
            'flag': anomaly['flag'],
            'alert_types': anomaly['alert_types'],
            'confidence': anomaly['highest_confidence'],
            'severity': 'critical' if anomaly['highest_confidence'] >= 0.9 else 'high',
            'details': {
                'src_bytes': anomaly['src_bytes'],
                'dst_bytes': anomaly['dst_bytes'],
                'duration': anomaly['duration']
            }
        }
        
        # Send to external threat endpoint
        response = requests.post(
            THREAT_ENDPOINT,
            json=threat_data,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code in [200, 201]:
            print(f"Successfully reported critical threat to {THREAT_ENDPOINT}")
        else:
            print(f"Failed to report threat: HTTP {response.status_code}")
            
    except Exception as e:
        print(f"Error reporting threat: {str(e)}")

# For testing
if __name__ == "__main__":
    test_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                            'data_kdd', 'kdd_test.csv')
    process_kdd_dataset(test_path) 