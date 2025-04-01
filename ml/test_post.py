import requests

def send_threat(threat_data):
    # Replace the URL with your Railway endpoint for posting threats
    url = "https://zero-day-sentinel-production.up.railway.app/threat"
    try:
        response = requests.post(url, json=threat_data)
        if response.status_code in (200, 201):
            print("Threat posted successfully!")
            print("Response:", response.json())
        else:
            print(f"Failed to post threat. Status: {response.status_code}")
            print("Response:", response.text)
    except Exception as e:
        print("Error posting threat:", e)

if __name__ == "__main__":
    # Dummy threat data for testing
    dummy_threat = {
        "type": "suspicious_login",
        "details": {
            "ip": "192.168.1.10",
            "message": "Abnormal login behavior detected"
        }
    }
    send_threat(dummy_threat)
