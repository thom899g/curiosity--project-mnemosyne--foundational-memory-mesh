"""
Cryptographic identity module for Mnemosyne nodes.
Manages the node's identity using ECC P-256 keys.
"""

import os
import json
import logging
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IdentityManager:
    """Manages the node's cryptographic identity and signing operations."""

    def __init__(self, node_id: str, key_store_path: str = "./keys"):
        """
        Initialize the identity manager.

        Args:
            node_id: The unique identifier for this node.
            key_store_path: Path to the directory where keys are stored.
        """
        self.node_id = node_id
        self.key_store_path = key_store_path
        os.makedirs(key_store_path, exist_ok=True)
        self.private_key = None
        self.public_key = None
        self._load_or_generate_keys()

    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones."""
        private_key_path = os.path.join(self.key_store_path, f"{self.node_id}_private.pem")
        public_key_path = os.path.join(self.key_store_path, f"{self.node_id}_public.pem")

        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            try:
                with open(private_key_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
                with open(public_key_path, "rb") as f:
                    self.public_key = serialization.load_pem_public_key(f.read())
                logger.info(f"Loaded existing keys for node {self.node_id}")
            except Exception as e:
                logger.error(f"Failed to load keys: {e}. Generating new keys.")
                self._generate_keys()
                self._save_keys()
        else:
            self._generate_keys()
            self._save_keys()

    def _generate_keys(self):
        """Generate a new ECC P-256 key pair."""
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        logger.info(f"Generated new keys for node {self.node_id}")

    def _save_keys(self):
        """Save the keys to disk in PEM format."""
        private_key_path = os.path.join(self.key_store_path, f"{self.node_id}_private.pem")
        public_key_path = os.path.join(self.key_store_path, f"{self.node_id}_public.pem")

        # Serialize private key
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_key_path, "wb") as f:
            f.write(private_pem)

        # Serialize public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, "wb") as f:
            f.write(public_pem)

        logger.info(f"Saved keys for node {self.node_id}")

    def sign(self, data: bytes) -> bytes:
        """
        Sign the given data.

        Args:
            data: The data to sign.

        Returns:
            The signature as bytes.
        """
        if self.private_key is None:
            raise RuntimeError("Private key not loaded.")

        signature = self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify(self, data: bytes, signature: bytes, public_key: ec.EllipticCurvePublicKey) -> bool:
        """
        Verify a signature.

        Args:
            data: The data that was signed.
            signature: The signature to verify.
            public_key: The public key to use for verification.

        Returns:
            True if the signature is valid, False otherwise.
        """
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def get_public_key_bytes(self) -> bytes:
        """Return the public key in bytes (PEM format)."""
        if self.public_key is None:
            raise RuntimeError("Public key not loaded.")
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encrypt_for_recipient(self, plaintext: bytes, recipient_public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Encrypt data for a specific recipient using ECIES.

        Args:
            plaintext: The data to encrypt.
            recipient_public_key: The recipient's public key.

        Returns:
            The encrypted data (ciphertext + nonce + tag) as bytes.
        """
        # Generate an ephemeral key pair for this encryption
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public_key = ephemeral_private_key.public_key()

        # Perform ECDH key exchange
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)

        # Derive a symmetric key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'mnemosyne_encryption'
        ).derive(shared_key)

        # Encrypt the plaintext with AES-GCM
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Serialize the ephemeral public key and prepend it to the ciphertext
        ephemeral_public_key_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return ephemeral_public_key_bytes + nonce + ciphertext

    def decrypt_from_sender(self, ciphertext: bytes, sender_public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Decrypt data from a sender using ECIES.

        Args:
            ciphertext: The encrypted data (ephemeral public key + nonce + ciphertext).
            sender_public_key: The sender's public key (for verification, not used in ECIES decryption).

        Returns:
            The decrypted plaintext.

        Note: In ECIES, the ephemeral public key is sent along with the ciphertext.
        """
        # The first 91 bytes are the ephemeral public key in PEM format (for P-256)
        # We assume the PEM format is used and the key is 91 bytes (standard for P-256).
        # However, note that PEM can vary in length. We'll parse until the PEM header ends.
        # Instead, we can split by the PEM boundary.
        pem_header = b"-----BEGIN PUBLIC KEY-----\n"
        pem_footer = b"\n-----END PUBLIC KEY-----"
        # Find the index of the footer
        footer_start = ciphertext.find(pem_footer)
        if footer_start == -1:
            raise ValueError("Invalid ciphertext: no PEM footer found.")
        ephemeral_public_key_end = footer_start + len(pem_footer)
        ephemeral_public_key_bytes = ciphertext[:ephemeral_public_key_end]
        remaining = ciphertext[ephemeral_public_key_end:]

        # The next 12 bytes are the nonce
        nonce = remaining[:12]
        ciphertext_data = remaining[12:]

        # Load the ephemeral public key
        ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_key_bytes)

        # Perform ECDH key exchange
        shared_key = self.private_key.exchange(ec.ECDH(), ephemeral_public_key)

        # Derive the same symmetric key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'mnemosyne_encryption'
        ).derive(shared_key)

        # Decrypt the ciphertext
        aesgcm = AESGCM(derived_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_data, None)
        return plaintext