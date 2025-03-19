from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
import os
import threading
from datetime import datetime
from app.services.anomaly_detection.detector import start_anomaly_detection, get_latest_anomalies, BLOCKCHAIN_ENDPOINT, AUTO_REPORT_ENABLED
import requests

anomaly_bp = Blueprint('anomaly', __name__)

# Global variable for anomaly detection status
anomaly_detection_status = {
    'running': False,
    'progress': 0,
    'high_risk_count': 0,
    'medium_risk_count': 0,
    'low_risk_count': 0
}

@anomaly_bp.route('/anomaly_detection')
def anomaly_detection_dashboard():
    """
    Display the network anomaly detection dashboard.
    This is integrated with the KDD dataset for real-time simulation.
    """
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))
    
    return render_template('anomaly_dashboard.html')

@anomaly_bp.route('/anomaly_detection/start', methods=['POST'])
def start_anomaly_detection_route():
    """
    Start the anomaly detection process with the selected dataset.
    This is an API endpoint that returns JSON and doesn't redirect.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    try:
        # Get parameters from form
        dataset = request.form.get('dataset', 'kdd_test')
        batch_size = int(request.form.get('batch_size', 100))
        sleep_interval = int(request.form.get('sleep_interval', 5))
        auto_report = request.form.get('auto_report') == 'on'
        
        print(f"Starting detection with dataset={dataset}, batch_size={batch_size}, sleep_interval={sleep_interval}, auto_report={auto_report}")
        
        # Set auto-report setting in the detector module
        import app.services.anomaly_detection.detector as detector
        detector.AUTO_REPORT_ENABLED = auto_report
        
        # Clear any existing anomalies to start fresh
        if hasattr(detector, 'detected_anomalies'):
            detector.detected_anomalies.clear()
            print("Cleared existing anomalies")
        else:
            print("Warning: detector.detected_anomalies does not exist")
            # Initialize it if it doesn't exist
            detector.detected_anomalies = []
            
        # For testing - create some sample threats to make sure the display works
        print("Creating some sample threats for testing")
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        sample_threats = [
            {
                'timestamp': current_time,
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'protocol_type': 'tcp',
                'service': 'http',
                'flag': 'S0',
                'duration': 30,
                'src_bytes': 1500,
                'dst_bytes': 8000,
                'alert_types': ['potential_scan', 'high_data_received'],
                'highest_confidence': 0.95,
                'serror_rate': 0.1,
                'rerror_rate': 0.05
            },
            {
                'timestamp': current_time,
                'src_ip': '192.168.1.101',
                'dst_ip': '10.0.0.2',
                'protocol_type': 'udp',
                'service': 'domain',
                'flag': 'SF',
                'duration': 15,
                'src_bytes': 500,
                'dst_bytes': 3000,
                'alert_types': ['suspicious_service'],
                'highest_confidence': 0.86,
                'serror_rate': 0.05,
                'rerror_rate': 0.02
            },
            {
                'timestamp': current_time,
                'src_ip': '192.168.1.102',
                'dst_ip': '10.0.0.3',
                'protocol_type': 'tcp',
                'service': 'ftp',
                'flag': 'REJ',
                'duration': 5,
                'src_bytes': 200,
                'dst_bytes': 400,
                'alert_types': ['connection_rejected'],
                'highest_confidence': 0.75,
                'serror_rate': 0.15,
                'rerror_rate': 0.25
            },
            {
                'timestamp': current_time,
                'src_ip': '192.168.1.103',
                'dst_ip': '10.0.0.4',
                'protocol_type': 'icmp',
                'service': 'ecr_i',
                'flag': 'SF',
                'duration': 2,
                'src_bytes': 100,
                'dst_bytes': 100,
                'alert_types': ['high_connection_count'],
                'highest_confidence': 0.65,
                'serror_rate': 0.01,
                'rerror_rate': 0.01
            }
        ]
        
        # Add the sample threats to our detector
        detector.detected_anomalies.extend(sample_threats)
        
        # Also add them to the queue for immediate processing
        for threat in sample_threats:
            try:
                detector.anomaly_queue.put(threat)
                print(f"Added threat to queue: {threat['protocol_type']} {threat['service']} ({threat['highest_confidence']:.2f})")
            except Exception as e:
                print(f"Error adding to queue: {str(e)}")
        
        print(f"Added {len(sample_threats)} sample threats. Total threats: {len(detector.detected_anomalies)}")
        
        # Determine dataset path
        if dataset == 'kdd_train':
            dataset_path = os.path.join('data_kdd', 'kdd_train.csv')
        else:
            dataset_path = os.path.join('data_kdd', 'kdd_test.csv')
        
        # Verify dataset exists
        if not os.path.exists(dataset_path):
            print(f"Dataset not found at {dataset_path}")
            return jsonify({'success': False, 'error': f'Dataset not found at {dataset_path}'})
        
        print(f"Starting anomaly detection with dataset: {dataset_path}")
        
        # Start detection
        success = detector.start_anomaly_detection(dataset_path)
        
        if not success:
            print("Failed to start detection")
            return jsonify({'success': False, 'error': 'Failed to start detection process'})
        
        # Force immediate processing of a small batch to show results quickly
        try:
            # Process first batch immediately in a non-blocking way
            def process_initial_batch():
                try:
                    detector.process_kdd_dataset(dataset_path, batch_size=10, sleep_interval=0)
                    print("Initial batch processed successfully")
                except Exception as e:
                    print(f"Error in initial batch processing: {str(e)}")
            
            # Start processing in background
            initial_batch_thread = threading.Thread(target=process_initial_batch)
            initial_batch_thread.daemon = True
            initial_batch_thread.start()
            print("Started initial batch processing thread")
        except Exception as e:
            print(f"Error processing initial batch: {str(e)}")
        
        # Store detection status
        global anomaly_detection_status
        anomaly_detection_status = {
            'running': success,
            'dataset': dataset,
            'batch_size': batch_size,
            'sleep_interval': sleep_interval,
            'auto_report': auto_report,
            'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'progress': 0,
            'high_risk_count': 0,
            'medium_risk_count': 0,
            'low_risk_count': 0
        }
        
        print("Detection started successfully, returning response")
        return jsonify({'success': success, 'error': None if success else 'Failed to start detection'})
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error in start_anomaly_detection_route: {str(e)}")
        return jsonify({'success': False, 'error': f'Exception occurred: {str(e)}'})

@anomaly_bp.route('/anomaly_detection/stop', methods=['POST'])
def stop_anomaly_detection():
    """
    Stop the anomaly detection process.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    global anomaly_detection_status
    anomaly_detection_status['running'] = False
    
    return jsonify({'success': True})

@anomaly_bp.route('/anomaly_detection/updates')
def get_anomaly_updates():
    """
    Get updates on anomaly detection progress and new anomalies.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    # Get latest anomalies from the queue
    anomalies = get_latest_anomalies(max_items=10)
    
    global anomaly_detection_status
    
    # Update counters based on new anomalies
    for anomaly in anomalies:
        if anomaly.get('highest_confidence', 0) >= 0.9:
            anomaly_detection_status['high_risk_count'] += 1
        elif anomaly.get('highest_confidence', 0) >= 0.7:
            anomaly_detection_status['medium_risk_count'] += 1
        else:
            anomaly_detection_status['low_risk_count'] += 1
    
    # Increment progress (simulate progress)
    if anomaly_detection_status.get('running', False):
        anomaly_detection_status['progress'] += 1
        if anomaly_detection_status['progress'] > 100:
            anomaly_detection_status['progress'] = 0
    
    # Prepare response
    response = {
        'success': True,
        'status': 'Running' if anomaly_detection_status.get('running', False) else 'Stopped',
        'progress': anomaly_detection_status.get('progress', 0),
        'high_risk_count': anomaly_detection_status.get('high_risk_count', 0),
        'medium_risk_count': anomaly_detection_status.get('medium_risk_count', 0),
        'low_risk_count': anomaly_detection_status.get('low_risk_count', 0),
        'anomalies': [
            {
                'timestamp': a.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                'protocol_type': a.get('protocol_type', 'unknown'),
                'service': a.get('service', 'unknown'),
                'flag': a.get('flag', 'unknown'),
                'alert_types': a.get('alert_types', ''),
                'highest_confidence': a.get('highest_confidence', 0)
            } for a in anomalies
        ]
    }
    
    return jsonify(response)

@anomaly_bp.route('/anomaly_detection/report_threat', methods=['POST'])
def report_threat():
    """
    Report a detected threat to the Zero Day Sentinel service.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    # Get the threat data from the request
    try:
        threat_data = request.json
        
        # Post the threat to Zero Day Sentinel
        response = requests.post(
            'https://zero-day-sentinel.onrender.com/threat',
            json=threat_data,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code in [200, 201]:
            return jsonify({
                'success': True, 
                'message': 'Threat reported successfully',
                'response': response.json() if response.content else None,
                'threat_id': threat_data.get('id')
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to report threat: HTTP {response.status_code}',
                'response': response.text
            })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error reporting threat: {str(e)}'
        })

@anomaly_bp.route('/anomaly_detection/verify_threat', methods=['GET'])
def verify_threat():
    """
    Verify if a reported threat exists in the Zero Day Sentinel blockchain.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    threat_id = request.args.get('threat_id')
    if not threat_id:
        return jsonify({'success': False, 'error': 'No threat ID provided'})
    
    try:
        # Fetch the blockchain data
        response = requests.get(
            'https://zero-day-sentinel.onrender.com/chain',
            timeout=10
        )
        
        if response.status_code == 200:
            blockchain_data = response.json()
            
            # Look for the threat in the blockchain
            found = False
            block_index = -1
            
            for i, block in enumerate(blockchain_data):
                if 'transactions' in block:
                    for transaction in block['transactions']:
                        if transaction.get('id') == threat_id:
                            found = True
                            block_index = i
                            break
                    if found:
                        break
            
            return jsonify({
                'success': True,
                'found': found,
                'block_index': block_index if found else -1
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to fetch blockchain: HTTP {response.status_code}',
                'response': response.text
            })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error verifying threat: {str(e)}'
        })

@anomaly_bp.route('/anomaly_detection/blockchain', methods=['GET'])
def get_blockchain():
    """
    Fetch the blockchain data from Zero Day Sentinel.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    try:
        # Fetch blockchain data from Zero Day Sentinel
        response = requests.get(
            BLOCKCHAIN_ENDPOINT,
            timeout=10
        )
        
        if response.status_code == 200:
            blockchain_data = response.json()
            return jsonify({
                'success': True,
                'blockchain': blockchain_data
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to fetch blockchain data: HTTP {response.status_code}'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching blockchain data: {str(e)}'
        })

@anomaly_bp.route('/anomaly_detection/critical_threats', methods=['GET'])
def get_critical_threats():
    """
    Get all threats from the anomaly detection system, not just critical ones.
    Modified to include ALL threats regardless of confidence level.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    try:
        # Get latest anomalies - all of them
        all_anomalies = get_latest_anomalies(max_items=100)
        print(f"Fetched {len(all_anomalies)} anomalies from get_latest_anomalies")
        
        # Format for display - INCLUDE ALL THREATS
        formatted_threats = []
        
        # If we didn't get any anomalies from get_latest_anomalies, check if the detector module has any
        if not all_anomalies:
            # Import detector module to directly access detected_anomalies
            import app.services.anomaly_detection.detector as detector
            
            if hasattr(detector, 'detected_anomalies') and detector.detected_anomalies:
                all_anomalies = detector.detected_anomalies
                print(f"Using {len(all_anomalies)} anomalies directly from detector.detected_anomalies")
            else:
                print("No anomalies found in detector.detected_anomalies either")
                
                # If still no anomalies, create some dummy threats for debugging
                print("Creating dummy threats for debugging")
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                all_anomalies = [
                    {
                        'timestamp': current_time,
                        'src_ip': '192.168.1.200',
                        'dst_ip': '10.0.0.5',
                        'protocol_type': 'tcp',
                        'service': 'http',
                        'flag': 'S0',
                        'alert_types': ['potential_scan'],
                        'highest_confidence': 0.92
                    }
                ]
        
        # Format the threats
        for a in all_anomalies:
            # Make sure alert_types is a proper list
            if isinstance(a.get('alert_types', []), list):
                alert_types = a.get('alert_types', [])
            elif isinstance(a.get('alert_types', ''), str):
                alert_types = a.get('alert_types', '').split(', ')
            else:
                alert_types = []
                
            # Determine severity based on confidence
            confidence = a.get('highest_confidence', 0)
            if confidence >= 0.9:
                severity = 'critical'
            elif confidence >= 0.85:
                severity = 'high'
            elif confidence >= 0.7:
                severity = 'medium'
            else:
                severity = 'low'
                
            # Format the threat
            formatted_threat = {
                'timestamp': a.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                'source': a.get('src_ip', 'unknown'),
                'destination': a.get('dst_ip', 'unknown'),
                'protocol': a.get('protocol_type', 'unknown'),
                'service': a.get('service', 'unknown'),
                'alert_types': alert_types,
                'confidence': confidence,
                'severity': severity
            }
            
            formatted_threats.append(formatted_threat)
        
        print(f"Returning {len(formatted_threats)} formatted threats")
        
        return jsonify({
            'success': True,
            'critical_threats': formatted_threats,  # Keep the same key for backward compatibility
            'count': len(formatted_threats)
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error in get_critical_threats: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Exception occurred: {str(e)}'
        })

@anomaly_bp.route('/anomaly_detection/toggle_reporting', methods=['POST'])
def toggle_reporting():
    """
    Toggle the auto-reporting of threats to the external endpoint.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    enabled = request.json.get('enabled', False)
    
    # Update the global variable in the detector module
    import app.services.anomaly_detection.detector as detector
    detector.AUTO_REPORT_ENABLED = enabled
    
    return jsonify({
        'success': True,
        'auto_report_enabled': enabled
    }) 