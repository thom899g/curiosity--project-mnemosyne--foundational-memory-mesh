"""
Trust ceremony for the initial mesh.
Performs the 2-of-3 signing of the genesis frame.
"""

import os
import json
import logging
from typing import List
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from mnemosyne_pb2 import MemoryFrame, Signature

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_frame(frame_path: str) -> MemoryFrame:
    """Load a MemoryFrame from a file."""
    with open(frame_path, "rb") as f:
        frame = MemoryFrame()
        frame.ParseFromString(f.read())
    return frame

def save_frame(frame: MemoryFrame, frame_path: str):
    """Save a MemoryFrame to a file."""
    with open(frame_path, "wb") as f:
        f.write(frame.SerializeToString())

def load_private_key(key_path: str) -> ec.EllipticCurvePrivateKey:
    """Load a private key from a PEM file."""
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key

def sign_frame(frame: MemoryFrame, private_key: ec.EllipticCurvePrivateKey, node_id: str) -> Signature:
    """
    Sign a MemoryFrame (excluding the signatures field).