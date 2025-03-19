#!/usr/bin/env python3
"""
Auto-Report Toggle Tool
-----------------------
This script provides a simple way to toggle the auto-reporting
feature for critical security threats.
"""

import sys
import os
import json

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from app.services.anomaly_detection.detector import AUTO_REPORT_ENABLED, CRITICAL_CONFIDENCE_THRESHOLD, THREAT_ENDPOINT
except ImportError:
    print("Error importing modules. Make sure you're running this from the zomato-app directory.")
    sys.exit(1)

def print_status():
    """Print the current status of auto-reporting."""
    status = "ENABLED" if AUTO_REPORT_ENABLED else "DISABLED"
    endpoint = THREAT_ENDPOINT
    threshold = CRITICAL_CONFIDENCE_THRESHOLD
    
    print("\n===== Auto-Reporting Configuration =====")
    print(f"Status: {status}")
    print(f"Endpoint: {endpoint}")
    print(f"Confidence Threshold: {threshold * 100:.1f}%")
    print("=======================================\n")
    
    if AUTO_REPORT_ENABLED:
        print("Critical threats will be automatically reported to the external endpoint.")
        print(f"Threats with confidence level ≥ {threshold * 100:.1f}% will be reported to {endpoint}")
    else:
        print("Auto-reporting is currently disabled.")
        print("Critical threats will be detected but NOT reported to the external endpoint.")
        print("You can toggle this feature using the command:")
        print("  python toggle_auto_report.py --enable")
    
    return AUTO_REPORT_ENABLED

def toggle_auto_report(enable=None):
    """
    Toggle the auto-reporting feature.
    
    Args:
        enable: If True, enable auto-reporting. If False, disable it.
               If None, toggle the current state.
    
    Returns:
        The new state (True for enabled, False for disabled)
    """
    global AUTO_REPORT_ENABLED
    
    # Determine the new state
    if enable is None:
        # Toggle current state
        new_state = not AUTO_REPORT_ENABLED
    else:
        # Set to specified state
        new_state = enable
    
    # Update the variable
    # Note: In a real application, this would need to modify a persistent config
    # or database setting. This is just updating the in-memory variable.
    AUTO_REPORT_ENABLED = new_state
    
    # Print the new status
    status = "ENABLED" if AUTO_REPORT_ENABLED else "DISABLED"
    print(f"\nAuto-reporting has been {status}.\n")
    
    return AUTO_REPORT_ENABLED

def main():
    """Main function to process command line arguments."""
    # Process command line arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "--enable" or arg == "-e":
            toggle_auto_report(True)
        elif arg == "--disable" or arg == "-d":
            toggle_auto_report(False)
        elif arg == "--toggle" or arg == "-t":
            toggle_auto_report()
        elif arg == "--status" or arg == "-s":
            print_status()
        else:
            print("Unknown argument:", arg)
            print("Usage: python toggle_auto_report.py [--enable | --disable | --toggle | --status]")
    else:
        # No arguments, just print status
        print_status()
        print("\nUse --enable, --disable, or --toggle to change the setting.")

if __name__ == "__main__":
    main() 