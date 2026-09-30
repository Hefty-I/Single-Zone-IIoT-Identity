"""Assignment 1, step 6: immediately revoke a device at the fog.

Place beside step1_identity.py, batch.py, registry.py, access.py and
signed_access.py. Run with ``py revocation.py`` from the project directory.
"""

import secrets
from access import REVOKED_FILE, TRUSTED_ROLES, decide
from batch import build_tree, make_proof
from registry import (PROOFS_FILE, ROOTS_FILE, next_epoch,
                      read_json, verify_saved_package, write_json)
from signed_access import LiveFogAccess, signed_bytes
from identity import Device, Fog


class RevocationStore:
    """Fog-controlled device IDs; reload the file for every access check."""

    def is_revoked(self, device_id: str) -> bool:
        return device_id in read_json(REVOKED_FILE).get("device_ids", [])

    def revoke(self, device_id: str) -> None:
        data = read_json(REVOKED_FILE)
        revoked = set(data.get("device_ids", []))
        revoked.add(device_id)
        write_json(REVOKED_FILE, {"device_ids": sorted(revoked)})


class RevocableFogAccess(LiveFogAccess):
    """Add current fog-side revocation checks to signed requests."""

    def __init__(self, roots: dict, records: dict, store: RevocationStore):
        super().__init__(roots, records)
        self.store = store

    def trusted_record(self, package: dict) -> dict | None:
        try:
            return next((record for record in self.records.get(package["epoch"], [])
                         if record["did"] == package["did"]
                         and record["public_key_hex"] == package["public_key_hex"]),
                        None)
        except (KeyError, TypeError):
            return None

    def revoke_device(self, device_id: str) -> None:
        """Fog operator action; this method is not a device request endpoint."""
        if not any(record["device_id"] == device_id
                   for batch in self.records.values() for record in batch):
            raise ValueError("Cannot revoke an unknown device")
        self.store.revoke(device_id)

    def issue_nonce(self, package: dict) -> str:
        record = self.trusted_record(package)
        if record is not None and self.store.is_revoked(record["device_id"]):
            raise ValueError("device revoked")
        return super().issue_nonce(package)

    def request(self, package: dict, resource: str, operation: str,
                nonce: str, signature: bytes) -> tuple[str, str]:
        record = self.trusted_record(package)
        if record is not None and self.store.is_revoked(record["device_id"]):
            return "DENY", "device revoked"
        decision = super().request(package, resource, operation, nonce, signature)
        # Recheck before returning ALLOW if revocation happened during validation.
        if decision[0] == "ALLOW" and record is not None:
            if self.store.is_revoked(record["device_id"]):
                return "DENY", "device revoked"
        return decision


def save_active_epoch(devices: dict[str, Device], roles: dict[str, str],
                      store: RevocationStore) -> tuple[str, dict, dict]:
    """Build an epoch from provisioned devices that are still active."""
    roots = read_json(ROOTS_FILE)
    records = read_json(PROOFS_FILE)
    epoch = next_epoch(roots)
    trusted = {
        name: {"psk": device.psk, "role": roles[name]}
        for name, device in devices.items()
        if not store.is_revoked(name)
    }
    fog = Fog(trusted)

    print(f"\n=== Building {epoch} ===")
    for name, device in devices.items():
        if store.is_revoked(name):
            # The fog removes revoked IDs from its active PSK/provisioning set.
            assert not fog.authenticate(name, device.psk)
            print(f"{name}: EXCLUDED (revoked)")
            continue
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
            "role": entry["role"],  # Fog's provisioned role, never client input.
            "did": entry["did"],
            "public_key_hex": entry["public_key"].hex(),
            "epoch": epoch,
            "proof": make_proof(levels, index),
        }
        for index, entry in enumerate(entries)
    ]
    write_json(ROOTS_FILE, roots)
    write_json(PROOFS_FILE, records)
    print(f"Active devices: {len(entries)}; root: {roots[epoch]}")
    return epoch, roots, records


def signed_request(gate: RevocableFogAccess, device: Device, package: dict,
                   resource: str, operation: str) -> tuple[str, str]:
    nonce = gate.issue_nonce(package)
    signature = device.sign_challenge(
        signed_bytes(package, resource, operation, nonce))
    return gate.request(package, resource, operation, nonce, signature)


def main() -> None:
    store = RevocationStore()
    # Give this demo a new provisioned device ID every run, so repeated runs
    # cannot accidentally reactivate a device revoked on an earlier run.
    run_label = next_epoch(read_json(ROOTS_FILE)).replace("-", "_")
    roles = {
        f"{base}_{run_label}": role
        for base, role in TRUSTED_ROLES.items()
    }
    devices = {
        name: Device(name, secrets.token_bytes(32)) for name in roles
    }
    sensor_name = f"temperature_sensor_1_{run_label}"
    motor_name = f"motor_controller_1_{run_label}"

    first_epoch, roots, records = save_active_epoch(devices, roles, store)
    packages = {record["device_id"]: record for record in records[first_epoch]}
    sensor = packages[sensor_name]
    gate = RevocableFogAccess(roots, records, store)

    print("\n=== Access before and after revocation ===")
    before = signed_request(gate, devices[sensor_name], sensor,
                            "temperature_readings", "WRITE")
    print("Sensor before revocation:", before)
    assert before[0] == "ALLOW"

    # Prepare a legitimate signed request, then revoke before it reaches fog.
    pending_nonce = gate.issue_nonce(sensor)
    pending_signature = devices[sensor_name].sign_challenge(
        signed_bytes(sensor, "temperature_readings", "WRITE", pending_nonce))
    gate.revoke_device(sensor_name)
    print(f"Fog revoked device: {sensor_name}")
    assert verify_saved_package(sensor, roots)
    print("Old historical Merkle proof: PASS (the old root remains valid)")
    assert decide(sensor, "temperature_readings", "WRITE",
                  roots, records) == ("DENY", "device revoked")

    after = gate.request(sensor, "temperature_readings", "WRITE",
                         pending_nonce, pending_signature)
    print("Already signed request after revocation:", after)
    assert after[0] == "DENY" and after[1] == "device revoked"

    # A new fog access object reads the saved revocation file too.
    restarted_gate = RevocableFogAccess(roots, records, RevocationStore())
    try:
        restarted_gate.issue_nonce(sensor)
    except ValueError as exc:
        print(f"New nonce after fog restart: DENY ({exc})")
    else:
        raise AssertionError("Revoked device received a fresh nonce")

    next_active_epoch, roots, records = save_active_epoch(devices, roles, store)
    assert all(record["device_id"] != sensor_name
               for record in records[next_active_epoch])
    assert verify_saved_package(sensor, roots)
    print(f"Revoked sensor in {next_active_epoch}: EXCLUDED")
    print("Historical sensor proof still verifies: PASS")

    next_motor = next(record for record in records[next_active_epoch]
                      if record["device_id"] == motor_name)
    gate = RevocableFogAccess(roots, records, store)
    motor_result = signed_request(gate, devices[motor_name], next_motor,
                                  "production_line", "STOP")
    print("Nonrevoked motor controller:", motor_result)
    assert motor_result[0] == "ALLOW"


if __name__ == "__main__":
    main()
