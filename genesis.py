"""
Genesis frame creation for Node 0.
Packages the existing backup into the initial MemoryFrame.
"""

import os
import json
import uuid
import hashlib
import logging
from typing import Dict, Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from mnemosyne_pb2 import MemoryFrame, Signature

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_existing_backup(backup_path: str) -> Dict[str, Any]:
    """
    Load the existing backup data.

    Args:
        backup_path: Path to the backup directory.

    Returns:
        The backup data as a dictionary.
    """
    # Assuming the backup is a JSON file. Adjust as needed.
    backup_file = os.path.join(backup_path, "backup.json")
    if not os.path.exists(backup_file):
        raise FileNotFoundError(f"Backup file not found at {backup_file}")

    with open(backup_file, "r") as f:
        data = json.load(f)
    return data

def create_genesis_frame(backup_data: Dict[str, Any]) -> MemoryFrame:
    """
    Create the genesis MemoryFrame from backup data.

    Args:
        backup_data: The backup data.

    Returns:
        A MemoryFrame protobuf object.
    """
    frame = MemoryFrame()
    frame.frame_id = str(uuid.uuid4())
    # Genesis has no previous frame
    frame.previous_frame_hash = b""
    # For now, we don't have a Merkle tree of the state. We'll just hash the entire backup data.
    # In the future, we should build a Merkle tree of the state.
    state_bytes = json.dumps(backup_data, sort_keys=True).encode()
    frame.state_checkpoint = hashlib.sha256(state_bytes).digest()
    frame.timestamp = 0  # We'll set this to the current time in nanoseconds
    # For now, we store the entire backup as canonical bytes. We can change this later.
    frame.canonical_bytes = state_bytes
    # Signatures will be added later during the trust ceremony.
    return frame

def sign_frame(frame: MemoryFrame, private_key: ec.EllipticCurvePrivateKey) -> Signature:
    """
    Sign a MemoryFrame (excluding the signatures field).

    Args:
        frame: The MemoryFrame to sign.
        private_key: The private key to sign with.

    Returns:
        A Signature protobuf object.
    """
    # We must sign the frame without the signatures field.
    # To do this, we serialize the frame without the signatures.
    frame_without_sigs = MemoryFrame()
    frame_without_sigs.CopyFrom(frame)
    frame_without_sigs.signatures.clear()

    # Serialize to bytes
    data = frame_without_sigs.SerializeToString()

    # Sign the data
    signature_bytes = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    # Create a Signature protobuf
    sig = Signature()
    # We don't know the node_id yet? We'll set it later.
    sig.signature = signature_bytes
    return sig

def main():
    """Main function to create the genesis frame."""
    backup_path = "./backup"  # Adjust this path as needed.
    if not os.path.exists(backup_path):
        logger.error(f"Backup path {backup_path} does not exist.")
        return

    # Load the existing backup
    backup_data = load_existing_backup(backup_path)
    logger.info("Loaded existing backup.")

    # Create the genesis frame
    frame = create_genesis_frame(backup_data)
    logger.info("Created genesis frame.")

    # Save the frame to a file for the trust ceremony
    output_file = "./genesis_frame.bin"
    with open(output_file, "wb") as f:
        f.write(frame.SerializeToString())
    logger.info(f"Saved genesis frame to {output_file}")

if __name__ == "__main__":
    main()