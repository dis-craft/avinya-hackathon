from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import json
import os
from datetime import datetime, timezone

# ------------------------------
# Blockchain Code
# ------------------------------

import hashlib
import json
from datetime import datetime, timezone

import hashlib
import json
from datetime import datetime, timezone

class Block:
    def __init__(self, data, previous_hash, timestamp=None, data_hash=None, block_hash=None):
        self.data = data
        self.previous_hash = previous_hash
        self.timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        self.data_hash = data_hash or hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        self.hash = block_hash or Block.calculate_hash(self.data_hash, self.previous_hash, self.timestamp)

    @staticmethod
    def calculate_hash(data_hash, previous_hash, timestamp):
        block_string = json.dumps({
            "data_hash": data_hash,
            "previous_hash": previous_hash,
            "timestamp": timestamp
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            "data": self.data,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "data_hash": self.data_hash,
            "hash": self.hash
        }


class Blockchain:
    RESET_BLOCKCHAIN = False
    FILE_NAME = "blockchain.json"
    VERSION = "1.0"

    def __init__(self):
        if self.RESET_BLOCKCHAIN and os.path.exists(self.FILE_NAME):
            os.remove(self.FILE_NAME)

        self.chain = self.load_chain()
        if not self.chain:
            self.chain = [self.create_genesis_block()]
            self.save_chain()

    @staticmethod
    def create_genesis_block():
        return Block({"type": "genesis", "message": "Zero-Day Sentinel Started"}, "0")

    def add_block(self, data):
        data_hash = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        # Prevent duplicate threat data from being added
        if any(block.data_hash == data_hash for block in self.chain):
            print(f"Skipping duplicate block with data_hash: {data_hash}")
            return False
        new_block = Block(data, self.chain[-1].hash)
        self.chain.append(new_block)
        self.save_chain()
        return True

    def save_chain(self):
    # Disabled for in-memory storage
        pass

    def load_chain(self):
    # Disabled file-based persistence; always start with a fresh blockchain in memory.
        return None

    def verify_chain(self):
        with open("blockchain.json", "r") as file:
            blockchain_data = json.load(file)
            blockchain = blockchain_data["chain"]

        for i in range(1, len(blockchain)):
            # Verify previous block first
            prev_block = blockchain[i - 1]
            # Recalculate data_hash from the actual data
            computed_prev_data_hash = hashlib.sha256(json.dumps(prev_block["data"], sort_keys=True).encode()).hexdigest()
            if computed_prev_data_hash != prev_block["data_hash"]:
                return False, f"Data tampering detected in block {i-1}"
            # Recalculate the previous block's overall hash using computed data_hash, previous_hash, and timestamp
            recalculated_prev_hash = Block.calculate_hash(
                computed_prev_data_hash,
                prev_block["previous_hash"],
                prev_block["timestamp"]
            )
            # Check if the stored hash of previous block matches the recalculated one
            if prev_block["hash"] != recalculated_prev_hash:
                return False, f"Invalid hash in block {i-1}"

            # Now, verify the current block's "previous_hash" field
            if blockchain[i]["previous_hash"] != prev_block["hash"]:
                return False, f"Invalid previous hash at block {i}"

            # Verify current block data and hash
            curr_block = blockchain[i]
            computed_curr_data_hash = hashlib.sha256(json.dumps(curr_block["data"], sort_keys=True).encode()).hexdigest()
            if computed_curr_data_hash != curr_block["data_hash"]:
                return False, f"Data tampering detected in block {i}"
            recalculated_curr_hash = Block.calculate_hash(
                computed_curr_data_hash,
                curr_block["previous_hash"],
                curr_block["timestamp"]
            )
            if curr_block["hash"] != recalculated_curr_hash:
                return False, f"Invalid hash at block {i}"

        return True, "Blockchain is valid!"

    def get_chain_length(self):
        return len(self.chain)

# ------------------------------
# Flask Backend API
# ------------------------------

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
blockchain = Blockchain()

@app.route("/chain", methods=["GET"])
def get_chain():
    return jsonify({"length": len(blockchain.chain), "chain": [b.to_dict() for b in blockchain.chain]})

@app.route("/threat", methods=["POST"])
def add_threat():
    """
    Receives threat data from the ML model or manual POST requests.
    Example format:
    {
        "id": "threat-1742364492669-vk8go90b5",
        "timestamp": "2025-03-19 11:36:53",
        "ip": "192.168.1.86",
        "attack_type": "Connection Attempt",
        "severity": "High",
        "status": "Detected",
        "details": {
        "user_agent": "Zomato Anomaly Detector/1.0",
        "method": "GET",
        "url_path": "/private",
        "source_port": 52949,
        "destination_port": 443,
        "protocol": "tcp",
        "flag": "REJ"
        }
    }
    """
    threat_data = request.get_json()

    # Validate the threat data format
    if not threat_data:
        return jsonify({"error": "Invalid threat data"}), 400

    # Standardized format for all new blocks
    block_data = {
        "id": threat_data.get("id", f"threat-{datetime.now().timestamp()}"),
        "timestamp": threat_data.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
        "ip": threat_data.get("ip", "0.0.0.0"),
        "attack_type": threat_data.get("attack_type", "unknown"),
        "severity": threat_data.get("severity", "Low"),
        "status": threat_data.get("status", "Unknown"),
        "details": {
            "user_agent": threat_data.get("details", {}).get("user_agent", "N/A"),
            "method": threat_data.get("details", {}).get("method", "N/A"),
            "url_path": threat_data.get("details", {}).get("url_path", "/"),
            "source_port": threat_data.get("details", {}).get("source_port", 0),
            "destination_port": threat_data.get("details", {}).get("destination_port", 0),
            "protocol": threat_data.get("details", {}).get("protocol", "N/A"),
            "flag": threat_data.get("details", {}).get("flag", "N/A")
        }
    }

    # Add the threat as a block
    added = blockchain.add_block(block_data)
    
    if not added:
        return jsonify({"message": "Duplicate threat data, block not added"}), 409

    return jsonify({
        "message": "Threat added successfully!",
        "new_block": blockchain.chain[-1].to_dict()
    })

@app.route("/verify", methods=["GET"])
def verify():
    valid, msg = blockchain.verify_chain()
    if valid:
        return jsonify({"message": msg})
    else:
        return jsonify({"error": msg}), 400

# ------------------------------
# Main Execution
# ------------------------------

@app.route("/reset", methods=["POST"])
def reset_blockchain():
    global blockchain
    blockchain = Blockchain()  # Reinitialize the blockchain in memory
    return jsonify({"message": "Blockchain reset successfully!", "chain": [b.to_dict() for b in blockchain.chain]})



if __name__ == "__main__":
    # Get the port Railway assigns or default to 5000
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)