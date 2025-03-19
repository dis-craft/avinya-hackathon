from flask import Blueprint, render_template, jsonify, request
from app.services.anomaly_detection.detector import start_anomaly_detection, stop_anomaly_detection, get_latest_anomalies, detected_anomalies, CRITICAL_CONFIDENCE_THRESHOLD
import os
import requests
import json
from datetime import datetime

# Create blueprint for anomaly detection
anomaly_bp = Blueprint('anomaly', __name__)

# Zero Day Sentinel blockchain endpoint
BLOCKCHAIN_ENDPOINT = "https://zero-day-sentinel.onrender.com/chain"

@anomaly_bp.route('/admin/anomaly')
def anomaly_panel():
    """Show the anomaly detection admin panel."""
    # Get the most recent anomalies with high confidence
    all_anomalies = detected_anomalies
    
    # Separate critical anomalies (based on threshold)
    critical_anomalies = [
        anomaly for anomaly in all_anomalies 
        if anomaly.get('highest_confidence', 0) >= CRITICAL_CONFIDENCE_THRESHOLD
    ]
    
    # Calculate risk distribution
    critical_count = len([a for a in all_anomalies if a.get('highest_confidence', 0) >= 0.9])
    high_count = len([a for a in all_anomalies if 0.85 <= a.get('highest_confidence', 0) < 0.9])
    medium_count = len([a for a in all_anomalies if 0.7 <= a.get('highest_confidence', 0) < 0.85])
    low_count = len([a for a in all_anomalies if a.get('highest_confidence', 0) < 0.7])
    
    return render_template(
        'admin/anomaly.html',
        anomalies=all_anomalies,
        critical_anomalies=critical_anomalies,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count
    )

@anomaly_bp.route('/api/anomalies')
def get_anomalies():
    """API endpoint to get anomalies as JSON."""
    # Get the limit from query parameters (default to 10)
    limit = request.args.get('limit', default=10, type=int)
    
    # Check if only critical anomalies are requested
    critical_only = request.args.get('critical', default='false', type=str).lower() == 'true'
    
    # Get anomalies
    if critical_only:
        anomalies = [
            anomaly for anomaly in detected_anomalies 
            if anomaly.get('highest_confidence', 0) >= CRITICAL_CONFIDENCE_THRESHOLD
        ]
    else:
        anomalies = detected_anomalies
    
    # Limit the number of anomalies returned
    limited_anomalies = anomalies[:limit] if limit > 0 else anomalies
    
    return jsonify({
        'count': len(limited_anomalies),
        'total': len(anomalies),
        'threshold': CRITICAL_CONFIDENCE_THRESHOLD,
        'anomalies': limited_anomalies
    })

@anomaly_bp.route('/api/blockchain')
def get_blockchain_data():
    """API endpoint to fetch and return blockchain data from Zero Day Sentinel."""
    try:
        # Fetch blockchain data
        response = requests.get(BLOCKCHAIN_ENDPOINT, timeout=10)
        
        if response.status_code == 200:
            blockchain_data = response.json()
            
            # Process the data for better visualization
            if 'chain' in blockchain_data:
                # Add statistics and summaries
                chain = blockchain_data['chain']
                
                # Count threat types and severities
                threat_types = {}
                threat_severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                
                # Process each block
                for i, block in enumerate(chain):
                    # For non-genesis blocks, update statistics
                    if i > 0 and 'data' in block:
                        data = block['data']
                        if 'attack_type' in data:
                            attack_type = data['attack_type']
                            if attack_type in threat_types:
                                threat_types[attack_type] += 1
                            else:
                                threat_types[attack_type] = 1
                        
                        if 'severity' in data:
                            severity = data['severity'].lower()
                            if severity in threat_severities:
                                threat_severities[severity] += 1
                
                # Add statistics to the response
                blockchain_data['statistics'] = {
                    'threat_types': threat_types,
                    'threat_severities': threat_severities,
                    'total_blocks': len(chain),
                    'total_threats': len(chain) - 1  # Excluding genesis block
                }
            
            return jsonify(blockchain_data)
        else:
            return jsonify({
                'error': f'Failed to fetch blockchain data. Status code: {response.status_code}'
            }), 500
    except Exception as e:
        return jsonify({
            'error': f'Error fetching blockchain data: {str(e)}'
        }), 500

@anomaly_bp.route('/api/start_detection')
def api_start_detection():
    """API endpoint to start anomaly detection."""
    dataset = request.args.get('dataset', default='data_kdd/kdd_test.csv')
    
    success = start_anomaly_detection(dataset)
    
    return jsonify({
        'success': success,
        'message': 'Anomaly detection started successfully' if success else 'Failed to start anomaly detection'
    })

@anomaly_bp.route('/api/stop_detection')
def api_stop_detection():
    """API endpoint to stop anomaly detection."""
    success = stop_anomaly_detection()
    
    return jsonify({
        'success': success,
        'message': 'Anomaly detection stopped successfully' if success else 'Failed to stop anomaly detection'
    })

@anomaly_bp.route('/api/toggle_reporting')
def api_toggle_reporting():
    """API endpoint to toggle automatic reporting of threats."""
    from app.services.anomaly_detection.detector import AUTO_REPORT_ENABLED
    
    # Get the requested state (default to toggling the current state)
    requested_state = request.args.get('enable')
    
    if requested_state is not None:
        # Convert to boolean
        if requested_state.lower() in ['true', '1', 'yes', 'y']:
            new_state = True
        elif requested_state.lower() in ['false', '0', 'no', 'n']:
            new_state = False
        else:
            return jsonify({
                'success': False,
                'message': f'Invalid value for "enable" parameter: {requested_state}'
            }), 400
    else:
        # Toggle the current state
        new_state = not AUTO_REPORT_ENABLED
    
    # Update the auto-report flag
    # Note: This is modifying the in-memory variable
    # In a real application, this should modify a persistent configuration
    globals()['AUTO_REPORT_ENABLED'] = new_state
    
    return jsonify({
        'success': True,
        'auto_report_enabled': new_state,
        'message': f'Auto-reporting has been {"enabled" if new_state else "disabled"}'
    })

@anomaly_bp.route('/api/config')
def api_get_config():
    """API endpoint to get the current configuration."""
    from app.services.anomaly_detection.detector import AUTO_REPORT_ENABLED, THREAT_ENDPOINT, BLOCKCHAIN_ENDPOINT
    
    return jsonify({
        'auto_report_enabled': AUTO_REPORT_ENABLED,
        'critical_confidence_threshold': CRITICAL_CONFIDENCE_THRESHOLD,
        'threat_endpoint': THREAT_ENDPOINT,
        'blockchain_endpoint': BLOCKCHAIN_ENDPOINT
    }) 