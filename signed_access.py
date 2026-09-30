"""Assignment 1, step 5: require a fresh device signature for access.

Run beside step1_identity.py, batch.py, registry.py, and access.py.
This demo creates a new epoch, then uses its live device keys for requests.
"""

import json
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from access import decide
from batch import build_tree, make_proof
from registry import (PROOFS_FILE, ROOTS_FILE, next_epoch,
                      read_json, write_json)
from identity import Device, Fog


def signed_bytes(package: dict, resource: str,
                 operation: str, nonce: str) -> bytes:
    """Bind the device identity, epoch, action, and nonce to one signature."""
    message = {
        "did": package["did"],
        "public_key_hex": package["public_key_hex"],
        "epoch": package["epoch"],
        "resource": resource,
        "operation": operation,
        "nonce": nonce,
    }
    return json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")


class LiveFogAccess:
    def __init__(self, roots: dict, records: dict):
        self.roots = roots
        self.records = records
        self.pending = {}  # (DID, epoch) -> (nonce, expiry)
        self.used = set()   # (DID, nonce) pairs already presented

    def issue_nonce(self, package: dict) -> str:
        epoch = package["epoch"]
        known = any(record["did"] == package["did"]
                    for record in self.records.get(epoch, []))
        if not known:
            raise ValueError("Unknown device")
        nonce = secrets.token_hex(16)
        self.pending[(package["did"], epoch)] = (nonce, time.monotonic() + 30)
        return nonce

    def request(self, package: dict, resource: str, operation: str,
                nonce: str, signature: bytes) -> tuple[str, str]:
        try:
            did, epoch = package["did"], package["epoch"]
            if (did, nonce) in self.used:
                return "DENY", "nonce already used (replay)"

            pending = self.pending.pop((did, epoch), None)
            if pending is None or pending[0] != nonce:
                return "DENY", "nonce was not issued for this request"
            if time.monotonic() > pending[1]:
                return "DENY", "nonce expired"
            self.used.add((did, nonce))

            # Find the fog's public key for the registered DID and epoch.
            trusted = next((record for record in self.records.get(epoch, [])
                            if record["did"] == did
                            and record["public_key_hex"] == package["public_key_hex"]),
                           None)
            if trusted is None:
                return "DENY", "no trusted device key"
            public_key = serialization.load_der_public_key(
                bytes.fromhex(trusted["public_key_hex"]))
            public_key.verify(signature,
                              signed_bytes(package, resource, operation, nonce),
                              ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return "DENY", "request signature did not verify"
        except (KeyError, TypeError, ValueError):
            return "DENY", "malformed request"

        # Only now evaluate membership and resource permissions.
        return decide(package, resource, operation, self.roots, self.records)


def create_epoch() -> tuple[dict, dict, dict, str]:
    """Register five new devices; save one new root and five proof packages."""
    roots = read_json(ROOTS_FILE)
    records = read_json(PROOFS_FILE)
    epoch = next_epoch(roots)
    specifications = [
        ("temperature_sensor_1", "temperature_sensor"),
        ("pressure_sensor_1", "pressure_sensor"),
        ("smart_meter_1", "smart_meter"),
        ("valve_controller_1", "valve_controller"),
        ("motor_controller_1", "motor_controller"),
    ]
    psks = {name: secrets.token_bytes(32) for name, _ in specifications}
    fog = Fog({name: {"psk": psks[name], "role": role}
               for name, role in specifications})
    devices = {}

    print(f"=== Registering live devices in {epoch} ===")
    for name, _ in specifications:
        device = Device(name, psks[name])
        devices[name] = device
        assert fog.authenticate(name, device.psk)
        challenge = fog.issue_challenge(name)
        assert fog.register(name, device.did, device.public_key,
                            device.sign_challenge(challenge))

    entries = sorted(fog.batch, key=lambda entry: entry["leaf"])
    levels = build_tree([bytes.fromhex(entry["leaf"]) for entry in entries])
    roots[epoch] = levels[-1][0].hex()
    records[epoch] = [
        {
            "device_id": entry["device_id"],
            "did": entry["did"],
            "public_key_hex": entry["public_key"].hex(),
            "epoch": epoch,
            "proof": make_proof(levels, index),
        }
        for index, entry in enumerate(entries)
    ]
    write_json(ROOTS_FILE, roots)
    write_json(PROOFS_FILE, records)
    return devices, read_json(ROOTS_FILE), read_json(PROOFS_FILE), epoch


def show(label: str, result: tuple[str, str]) -> str:
    decision, reason = result
    print(f"{label}: {decision} ({reason})")
    return decision


def main() -> None:
    devices, roots, records, epoch = create_epoch()
    packages = {record["device_id"]: record for record in records[epoch]}
    gate = LiveFogAccess(roots, records)
    sensor = packages["temperature_sensor_1"]
    motor = packages["motor_controller_1"]

    print("\n=== Signed resource requests ===")
    nonce = gate.issue_nonce(sensor)
    signature = devices["temperature_sensor_1"].sign_challenge(
        signed_bytes(sensor, "temperature_readings", "WRITE", nonce))
    assert show("Real sensor writes temperature",
                gate.request(sensor, "temperature_readings", "WRITE",
                             nonce, signature)) == "ALLOW"
    assert show("Exact same request sent again",
                gate.request(sensor, "temperature_readings", "WRITE",
                             nonce, signature)) == "DENY"

    nonce = gate.issue_nonce(sensor)
    signature = devices["temperature_sensor_1"].sign_challenge(
        signed_bytes(sensor, "production_line", "STOP", nonce))
    assert show("Real sensor tries to stop the line",
                gate.request(sensor, "production_line", "STOP",
                             nonce, signature)) == "DENY"

    nonce = gate.issue_nonce(motor)
    wrong_signature = devices["temperature_sensor_1"].sign_challenge(
        signed_bytes(motor, "production_line", "STOP", nonce))
    assert show("Copied motor proof, wrong private key",
                gate.request(motor, "production_line", "STOP",
                             nonce, wrong_signature)) == "DENY"

    nonce = gate.issue_nonce(motor)
    signature = devices["motor_controller_1"].sign_challenge(
        signed_bytes(motor, "production_line", "STOP", nonce))
    assert show("Real motor controller stops the line",
                gate.request(motor, "production_line", "STOP",
                             nonce, signature)) == "ALLOW"

    nonce = gate.issue_nonce(sensor)
    signature = devices["temperature_sensor_1"].sign_challenge(
        signed_bytes(sensor, "temperature_readings", "WRITE", nonce))
    assert show("Action changed after signing",
                gate.request(sensor, "production_line", "STOP",
                             nonce, signature)) == "DENY"


if __name__ == "__main__":
    main()
