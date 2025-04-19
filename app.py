from flask import Flask, request, jsonify
import json
import time
import hashlib
from typing import List, Dict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Key Generation
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Helper functions for signatures
def sign_message(private_key, message: Dict) -> bytes:
    message_bytes = json.dumps(message, sort_keys=True).encode()
    return private_key.sign(
        message_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify_signature(public_key, message: Dict, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            json.dumps(message, sort_keys=True).encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Smart contract logic
def execute_contract(contract: Dict, message: Dict) -> bool:
    if contract["type"] == "volume-check":
        return message["volume"] <= contract["params"]["max_volume"]
    elif contract["type"] == "material-check":
        return message["material"] in contract["params"]["allowed_materials"]
    return False

# Block structure
class Block:
    def __init__(self, index: int, message: Dict, signature: bytes, contract: Dict, previous_hash: str):
        self.index = index
        self.timestamp = time.time()
        self.message = message
        self.signature = signature.hex()
        self.contract = contract
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'message': self.message,
            'signature': self.signature,
            'contract': self.contract,
            'previous_hash': self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def to_dict(self) -> Dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "message": self.message,
            "signature": self.signature,
            "contract": self.contract,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

# Blockchain class
class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_message = {"volume": 0, "material": "none", "x": 0, "y": 0, "timestamp": str(time.time())}
        genesis_contract = {"type": "volume-check", "params": {"max_volume": 1000}}
        genesis_block = Block(0, genesis_message, b'', genesis_contract, "0")
        self.chain.append(genesis_block)

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, message: Dict, signature: bytes, contract: Dict, pub_key) -> bool:
        if not verify_signature(pub_key, message, signature):
            return False
        if not execute_contract(contract, message):
            return False
        new_block = Block(len(self.chain), message, signature, contract, self.get_latest_block().hash)
        self.chain.append(new_block)
        return True

    def is_chain_valid(self, chain=None) -> bool:
        chain = chain or self.chain
        for i in range(1, len(chain)):
            if chain[i].previous_hash != chain[i - 1].hash:
                return False
            if chain[i].hash != chain[i].calculate_hash():
                return False
        return True

    def resolve_conflicts(self, other_chains: List[List[Block]]):
        longest_chain = self.chain
        for chain in other_chains:
            if len(chain) > len(longest_chain) and self.is_chain_valid(chain):
                longest_chain = chain
        self.chain = longest_chain

    def to_json(self):
        return [block.to_dict() for block in self.chain]

blockchain = Blockchain()

@app.route('/chain', methods=['GET'])
def get_chain():
    return jsonify(blockchain.to_json()), 200

@app.route('/add_block', methods=['POST'])
def add_block():
    data = request.json
    message = data['message']
    contract = data['contract']
    signature = bytes.fromhex(data['signature'])
    success = blockchain.add_block(message, signature, contract, public_key)
    return jsonify({'status': 'success' if success else 'failure'}), 200

@app.route('/sign', methods=['POST'])
def sign():
    data = request.json['message']
    signature = sign_message(private_key, data)
    return jsonify({'signature': signature.hex()}), 200

if __name__ == '__main__':
    app.run(debug=True)
