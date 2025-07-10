# blockchain.py
import hashlib
import json
from datetime import datetime

class Block:
    def __init__(self, index, timestamp, data, previous_hash, hash=None):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = hash or self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

    @staticmethod
    def from_dict(data):
        return Block(
            index=data["index"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            data=data["data"],
            previous_hash=data["previous_hash"],
            hash=data["hash"]
        )

class Blockchain:
    def __init__(self, mongo_db):
        self.db = mongo_db
        self.collection = self.db["blockchain"]
        self.chain = []
        self.load_chain()

        if not self.chain:
            genesis = self.create_genesis_block()
            self.collection.insert_one(genesis.to_dict())
            self.chain.append(genesis)

    def create_genesis_block(self):
        return Block(0, datetime.now(), {"action": "genesis"}, "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        prev_block = self.get_latest_block()
        new_block = Block(
            index=prev_block.index + 1,
            timestamp=datetime.now(),
            data=data,
            previous_hash=prev_block.hash
        )
        self.collection.insert_one(new_block.to_dict())
        self.chain.append(new_block)
        return new_block

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.hash != current.calculate_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
        return True

    def get_all_blocks(self):
        return [block.to_dict() for block in self.chain]

    def load_chain(self):
        docs = list(self.collection.find().sort("index", 1))
        self.chain = [Block.from_dict(doc) for doc in docs]
