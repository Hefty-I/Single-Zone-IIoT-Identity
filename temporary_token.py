"""Assignment 1, step 7: limited access while a registration batch is open.

Run from the project folder after the revocation step. A simulated clock
demonstrates token expiry instantly, without waiting in real time.
"""

from copy import deepcopy
import json
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from access import TRUSTED_ROLES
from batch import build_tree, make_proof
from registry import (PROOFS_FILE, ROOTS_FILE, RUNTIME, next_epoch,
                      read_json, write_json)
from revocation import RevocableFogAccess, RevocationStore
from signed_access import signed_bytes
from identity import Device, Fog


REVOKED_TOKENS_FILE = RUNTIME / "revoked_tokens.json"
TOKEN_LIFETIME_SECONDS = 30
NONCE_LIFETIME_SECONDS = 30

# The waiting device has fewer permissions than a fully registered device.
PROVISIONAL_POLICY = {
    "temperature_sensor": {("temperature_readings", "WRITE")},
    "pressure_sensor": {("pressure_readings", "WRITE")},
    "smart_meter": {("energy_readings", "WRITE")},
}


def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def temporary_request_bytes(claims: dict, resource: str,
                            operation: str, nonce: str) -> bytes:
    """Bind the temporary token and the exact requested action to one key."""
    return canonical({
        "token_id": claims["token_id"],
        "did": claims["did"],
        "public_key_hex": claims["public_key_hex"],
        "resource": resource,
        "operation": operation,
        "nonce": nonce,
    })


class DemoClock:
    def __init__(self):
        self.value = time.time()

    def now(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class TemporaryTokenFog:
    def __init__(self, fog: Fog, revocations: RevocationStore, clock: DemoClock):
        self.fog = fog
        self.revocations = revocations
        self.clock = clock
        self._signing_key = ec.generate_private_key(ec.SECP256R1())
        self._verifying_key = self._signing_key.public_key()
        self.waiting = {}             # Provisioned device ID -> trusted batch entry
        self.issued_tokens = {}       # Token ID -> original fog-issued claims
        self.pending_nonces = {}      # Token ID -> (nonce, expiry)
        self.used_nonces = set()      # (Token ID, nonce)
        self.finalized = False

    def register_waiting(self, device: Device) -> None:
        """PSK and ECC ownership checks happen before a token is issued."""
        name = device.device_id
        if self.finalized or self.revocations.is_revoked(name):
            raise ValueError("device cannot join this batch")
        if not self.fog.authenticate(name, device.psk):
            raise ValueError("initial authentication failed")
        challenge = self.fog.issue_challenge(name)
        if not self.fog.register(name, device.did, device.public_key,
                                 device.sign_challenge(challenge)):
            raise ValueError("proof of possession failed")
        # This record came from the fog's trusted provisioning and ECC check.
        self.waiting[name] = self.fog.batch[-1]

    def issue_token(self, device_id: str) -> dict:
        if self.finalized or device_id not in self.waiting:
            raise ValueError("device is not waiting in an open batch")
        if self.revocations.is_revoked(device_id):
            raise ValueError("device revoked")
        record = self.waiting[device_id]
        claims = {
            "token_id": secrets.token_hex(16),
            "zone": "single-zone",
            "device_id": device_id,
            "did": record["did"],
            "public_key_hex": record["public_key"].hex(),
            "role": record["role"],
            "expires_at": self.clock.now() + TOKEN_LIFETIME_SECONDS,
        }
        signature = self._signing_key.sign(canonical(claims),
                                            ec.ECDSA(hashes.SHA256()))
        self.issued_tokens[claims["token_id"]] = claims
        return {"claims": claims, "signature_hex": signature.hex()}

    def validate_token(self, token: dict) -> tuple[bool, str]:
        try:
            claims = token["claims"]
            self._verifying_key.verify(
                bytes.fromhex(token["signature_hex"]), canonical(claims),
                ec.ECDSA(hashes.SHA256()))
            original = self.issued_tokens.get(claims["token_id"])
            if original != claims:
                return False, "unknown or changed token"
            record = self.waiting.get(claims["device_id"])
            if (record is None or claims["did"] != record["did"]
                    or claims["public_key_hex"] != record["public_key"].hex()
                    or claims["role"] != record["role"]):
                return False, "token does not match trusted registration"
            if claims["token_id"] in read_json(REVOKED_TOKENS_FILE).get("token_ids", []):
                return False, "token revoked"
            if self.revocations.is_revoked(claims["device_id"]):
                return False, "device revoked"
            if self.finalized:
                return False, "registration batch already finalized"
            if self.clock.now() >= claims["expires_at"]:
                return False, "token expired"
        except InvalidSignature:
            return False, "fog token signature did not verify"
        except (KeyError, TypeError, ValueError, AttributeError):
            return False, "malformed token"
        return True, "valid token"

    def issue_nonce(self, token: dict) -> str:
        valid, reason = self.validate_token(token)
        if not valid:
            raise ValueError(reason)
        token_id = token["claims"]["token_id"]
        nonce = secrets.token_hex(16)
        self.pending_nonces[token_id] = (
            nonce, self.clock.now() + NONCE_LIFETIME_SECONDS)
        return nonce

    def request(self, token: dict, resource: str, operation: str,
                nonce: str, device_signature: bytes) -> tuple[str, str]:
        try:
            token_id = token["claims"]["token_id"]
            if (token_id, nonce) in self.used_nonces:
                return "DENY", "nonce already used (replay)"
            pending = self.pending_nonces.pop(token_id, None)
            if pending is None or pending[0] != nonce:
                return "DENY", "nonce not issued for this token"
            self.used_nonces.add((token_id, nonce))

            valid, reason = self.validate_token(token)
            if not valid:
                return "DENY", reason
            if self.clock.now() >= pending[1]:
                return "DENY", "nonce expired"

            claims = token["claims"]
            record = self.waiting[claims["device_id"]]
            public_key = serialization.load_der_public_key(record["public_key"])
            public_key.verify(
                device_signature,
                temporary_request_bytes(claims, resource, operation, nonce),
                ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return "DENY", "device request signature did not verify"
        except (KeyError, TypeError, ValueError, AttributeError):
            return "DENY", "malformed request"

        role = record["role"]  # Trusted fog record, never a client-supplied role.
        if (resource, operation) not in PROVISIONAL_POLICY.get(role, set()):
            return "DENY", "operation not allowed during temporary access"
        return "ALLOW", "valid token, device signature, nonce, and provisional policy"

    def revoke_token(self, token: dict) -> None:
        """Fog operator action; not exposed as a device request."""
        token_id = token["claims"]["token_id"]
        if token_id not in self.issued_tokens:
            raise ValueError("unknown token")
        data = read_json(REVOKED_TOKENS_FILE)
        revoked = set(data.get("token_ids", []))
        revoked.add(token_id)
        write_json(REVOKED_TOKENS_FILE, {"token_ids": sorted(revoked)})

    def finalize_batch(self) -> tuple[str, dict, dict]:
        """Create one root from waiting devices that are still active."""
        if self.finalized:
            raise ValueError("batch already finalized")
        entries = sorted((record for record in self.fog.batch
                          if not self.revocations.is_revoked(record["device_id"])),
                         key=lambda record: record["leaf"])
        levels = build_tree([bytes.fromhex(record["leaf"]) for record in entries])
        roots = read_json(ROOTS_FILE)
        records = read_json(PROOFS_FILE)
        epoch = next_epoch(roots)
        roots[epoch] = levels[-1][0].hex()
        records[epoch] = [
            {
                "device_id": record["device_id"],
                "role": record["role"],
                "did": record["did"],
                "public_key_hex": record["public_key"].hex(),
                "epoch": epoch,
                "proof": make_proof(levels, index),
            }
            for index, record in enumerate(entries)
        ]
        write_json(ROOTS_FILE, roots)
        write_json(PROOFS_FILE, records)
        self.finalized = True
        print(f"Finalized {epoch}: {len(entries)} active devices, root {roots[epoch]}")
        return epoch, roots, records


def signed_temporary_request(gate: TemporaryTokenFog, device: Device,
                             token: dict, resource: str, operation: str,
                             nonce: str) -> tuple[str, str]:
    signature = device.sign_challenge(
        temporary_request_bytes(token["claims"], resource, operation, nonce))
    return gate.request(token, resource, operation, nonce, signature)


def show(label: str, result: tuple[str, str], expected: str) -> None:
    decision, reason = result
    print(f"{label}: {decision} ({reason})")
    assert decision == expected


def main() -> None:
    revocations = RevocationStore()
    clock = DemoClock()
    label = next_epoch(read_json(ROOTS_FILE)).replace("-", "_")
    roles = {f"{base}_{label}": role for base, role in TRUSTED_ROLES.items()}
    devices = {name: Device(name, secrets.token_bytes(32)) for name in roles}
    trusted = {name: {"psk": device.psk, "role": roles[name]}
               for name, device in devices.items()}
    gate = TemporaryTokenFog(Fog(trusted), revocations, clock)
    sensor_name = f"temperature_sensor_1_{label}"
    pressure_name = f"pressure_sensor_1_{label}"
    motor_name = f"motor_controller_1_{label}"

    print("=== Sensor joins an open batch ===")
    gate.register_waiting(devices[sensor_name])
    sensor_token = gate.issue_token(sensor_name)
    print("Fog-signed token: DID, public key, trusted role, and 30-second expiry")
    print("Devices waiting for inclusion:", len(gate.fog.batch))

    nonce = gate.issue_nonce(sensor_token)
    original_signature = devices[sensor_name].sign_challenge(
        temporary_request_bytes(sensor_token["claims"],
                                "temperature_readings", "WRITE", nonce))
    show("Provisional sensor WRITE",
         gate.request(sensor_token, "temperature_readings", "WRITE",
                      nonce, original_signature), "ALLOW")
    show("Exact request replayed",
         gate.request(sensor_token, "temperature_readings", "WRITE",
                      nonce, original_signature), "DENY")

    nonce = gate.issue_nonce(sensor_token)
    show("Stolen token, different device key",
         signed_temporary_request(gate, devices[motor_name], sensor_token,
                                  "temperature_readings", "WRITE", nonce),
         "DENY")

    nonce = gate.issue_nonce(sensor_token)
    changed = deepcopy(sensor_token)
    changed["claims"]["role"] = "motor_controller"
    show("Token role changed after fog signing",
         signed_temporary_request(gate, devices[sensor_name], changed,
                                  "temperature_readings", "WRITE", nonce),
         "DENY")

    expiring = gate.issue_token(sensor_name)
    nonce = gate.issue_nonce(expiring)
    clock.advance(31)  # Simulate 31 seconds; no actual waiting.
    show("Expired token",
         signed_temporary_request(gate, devices[sensor_name], expiring,
                                  "temperature_readings", "WRITE", nonce),
         "DENY")

    revoked = gate.issue_token(sensor_name)
    nonce = gate.issue_nonce(revoked)
    gate.revoke_token(revoked)
    show("Explicitly revoked token",
         signed_temporary_request(gate, devices[sensor_name], revoked,
                                  "temperature_readings", "WRITE", nonce),
         "DENY")

    print("\n=== More devices join before the batch closes ===")
    for name, device in devices.items():
        if name != sensor_name:
            gate.register_waiting(device)

    motor_token = gate.issue_token(motor_name)
    nonce = gate.issue_nonce(motor_token)
    show("Motor tries STOP with temporary access",
         signed_temporary_request(gate, devices[motor_name], motor_token,
                                  "production_line", "STOP", nonce), "DENY")

    pressure_token = gate.issue_token(pressure_name)
    nonce = gate.issue_nonce(pressure_token)
    revocations.revoke(pressure_name)
    show("Device revoked while holding a token",
         signed_temporary_request(gate, devices[pressure_name], pressure_token,
                                  "pressure_readings", "WRITE", nonce), "DENY")

    epoch, roots, records = gate.finalize_batch()
    assert len(records[epoch]) == 4
    assert all(record["device_id"] != pressure_name for record in records[epoch])
    print("Revoked pressure sensor in new batch: EXCLUDED")

    try:
        gate.issue_nonce(motor_token)
    except ValueError as exc:
        print(f"Temporary token after finalization: DENY ({exc})")
    else:
        raise AssertionError("A finalized device received temporary access")

    motor_package = next(record for record in records[epoch]
                         if record["device_id"] == motor_name)
    permanent_gate = RevocableFogAccess(roots, records, revocations)
    nonce = permanent_gate.issue_nonce(motor_package)
    signature = devices[motor_name].sign_challenge(
        signed_bytes(motor_package, "production_line", "STOP", nonce))
    show("Motor STOP using its permanent Merkle proof",
         permanent_gate.request(motor_package, "production_line", "STOP",
                                nonce, signature), "ALLOW")


if __name__ == "__main__":
    main()
