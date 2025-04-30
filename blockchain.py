import hashlib
import json
from time import time

class Blockchain:
    def __init__(self):
        self.chain = []  # List to store all blocks
        self.current_transactions = []  # List to store transactions

        # Create the genesis block (the first block in the chain)
        self.new_block(previous_hash="1", proof=100)

    def new_block(self, proof, previous_hash=None):
        """Create a new block and add it to the chain"""
        block = {
            "index": len(self.chain) + 1,
            "timestamp": time(),
            "transactions": self.current_transactions,
            "proof": proof,
            "previous_hash": previous_hash or self.hash(self.chain[-1]),
        }

        self.current_transactions = []  # Reset the list of transactions
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """Create a new transaction and add it to the current block"""
        self.current_transactions.append({
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
        })
        return self.last_block["index"] + 1

    @staticmethod
    def hash(block):
        """Hash a block using SHA-256"""
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        """Return the last block in the chain"""
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        """Simple Proof-of-Work algorithm"""
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        """Validate the proof: Does hash(last_proof, proof) contain 4 leading zeros?"""
        guess = f"{last_proof}{proof}".encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"
    
'''if __name__ == "__main__":
    blockchain = Blockchain()

    print("Mining a new block...⛏️")
    last_proof = blockchain.last_block["proof"]
    proof = blockchain.proof_of_work(last_proof)

    blockchain.new_transaction(sender="Alice", recipient="Bob", amount=5)
    new_block = blockchain.new_block(proof)

    print(f"New Block Mined: {new_block}")
    print(f"Full Blockchain: {blockchain.chain}")'''
