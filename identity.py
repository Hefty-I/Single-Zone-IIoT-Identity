"""Assignment 1, step 1: simulate device identity and proof of possession.

This runs locally to make the registration logic easy to see. A protected
device-to-fog connection, batch tree, tokens, and access rules come later.
"""

import hashlib
import hmac
import secrets
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class Device:
    def __init__(self, device_id: str, psk: bytes):
        self.device_id = device_id
        self.psk = psk
        self.did = f"did:example:{uuid.uuid4().hex}"
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self._private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign_challenge(self, challenge: bytes) -> bytes:
        return self._private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))


class Fog:
    def __init__(self, trusted_devices: dict):
        self.trusted_devices = trusted_devices
        self.authenticated = set()
        self.pending_challenges = {}
        self.batch = []

    def authenticate(self, device_id: str, psk: bytes) -> bool:
        record = self.trusted_devices.get(device_id)
        accepted = record is not None and hmac.compare_digest(record["psk"], psk)
        if accepted:
            self.authenticated.add(device_id)
        print(f"Initial authentication: {'PASS' if accepted else 'DENY'}")
        return accepted

    def issue_challenge(self, device_id: str) -> bytes:
        if device_id not in self.authenticated:
            raise ValueError("Device must pass initial authentication first")
        challenge = secrets.token_bytes(32)
        self.pending_challenges[device_id] = challenge
        return challenge

    def register(self, device_id: str, did: str, public_key_bytes: bytes,
                 signature: bytes) -> bool:
        # Taking the challenge out makes it one-time use.
        challenge = self.pending_challenges.pop(device_id, None)
        if device_id not in self.authenticated or challenge is None:
            print("Proof of possession: DENY (no pending challenge)")
            return False

        try:
            public_key = serialization.load_der_public_key(public_key_bytes)
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise ValueError("Expected an ECC public key")
            public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError):
            print("Proof of possession: DENY (signature did not verify)")
            return False

        # Exact assignment leaf formula: H(DID || public key).
        leaf = hashlib.sha256(did.encode("utf-8") + public_key_bytes).hexdigest()
        role = self.trusted_devices[device_id]["role"]
        self.batch.append({"device_id": device_id, "did": did,
                           "public_key": public_key_bytes, "role": role,
                           "leaf": leaf})
        print("Proof of possession: PASS")
        print(f"DID: {did}")
        print(f"Trusted role: {role}")
        print(f"Device leaf: {leaf}")
        print(f"Devices waiting in batch: {len(self.batch)}")
        return True


def main() -> None:
    # A simulated provisioning step gives the device and fog the same secret.
    psk = secrets.token_bytes(32)
    device = Device("temperature_sensor_1", psk)
    fog = Fog({device.device_id: {"psk": psk, "role": "temperature_sensor"}})

    if not fog.authenticate(device.device_id, device.psk):
        return

    print("\nAttempt with the WRONG private key:")
    challenge = fog.issue_challenge(device.device_id)
    impostor_key = ec.generate_private_key(ec.SECP256R1())
    wrong_signature = impostor_key.sign(challenge, ec.ECDSA(hashes.SHA256()))
    assert not fog.register(device.device_id, device.did,
                            device.public_key, wrong_signature)

    print("\nAttempt with the REAL device's private key:")
    fresh_challenge = fog.issue_challenge(device.device_id)
    correct_signature = device.sign_challenge(fresh_challenge)
    assert fog.register(device.device_id, device.did,
                        device.public_key, correct_signature)


if __name__ == "__main__":
    main()
