"""Assignment 1, step 2: finalize one batch and verify Merkle proofs.

Run beside step1_identity.py. The root registry and proof packages are kept
in memory for this learning step; network transport and persistence come later.
"""

import hashlib
import hmac
import secrets

from identity import Device, Fog


def parent_hash(left: bytes, right: bytes) -> bytes:
    """Combine two child hashes in a fixed left-to-right order."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def build_tree(leaves: list[bytes]) -> list[list[bytes]]:
    """Return every tree level, starting with the sorted device leaves."""
    if not leaves:
        raise ValueError("Cannot finalize an empty batch")

    levels = [leaves]
    while len(levels[-1]) > 1:
        current = levels[-1]
        parents = []
        for index in range(0, len(current), 2):
            left = current[index]
            # If a level has an odd number of nodes, duplicate its last node.
            right = current[index + 1] if index + 1 < len(current) else left
            parents.append(parent_hash(left, right))
        levels.append(parents)
    return levels


def make_proof(levels: list[list[bytes]], leaf_index: int) -> list[tuple[str, str]]:
    """Collect each sibling hash and its side on the way to the root."""
    proof = []
    index = leaf_index
    for level in levels[:-1]:
        sibling_index = index ^ 1
        if sibling_index >= len(level):
            sibling_index = index  # Duplicated last node on an odd level.
        side = "right" if index % 2 == 0 else "left"
        proof.append((side, level[sibling_index].hex()))
        index //= 2
    return proof


def verify_proof(leaf: bytes, proof: list[tuple[str, str]],
                 trusted_root: bytes) -> bool:
    current = leaf
    for side, sibling_hex in proof:
        sibling = bytes.fromhex(sibling_hex)
        if side == "right":
            current = parent_hash(current, sibling)
        elif side == "left":
            current = parent_hash(sibling, current)
        else:
            return False
    return hmac.compare_digest(current, trusted_root)


def main() -> None:
    # Each simulated device has its own initial shared secret and trusted role.
    specifications = [
        ("temperature_sensor_1", "temperature_sensor"),
        ("pressure_sensor_1", "pressure_sensor"),
        ("smart_meter_1", "smart_meter"),
        ("valve_controller_1", "valve_controller"),
        ("motor_controller_1", "motor_controller"),
    ]
    secrets_by_name = {name: secrets.token_bytes(32) for name, _ in specifications}
    trusted_devices = {
        name: {"psk": secrets_by_name[name], "role": role}
        for name, role in specifications
    }
    fog = Fog(trusted_devices)

    print("=== Collecting one registration batch ===")
    for name, _ in specifications:
        device = Device(name, secrets_by_name[name])
        assert fog.authenticate(device.device_id, device.psk)
        challenge = fog.issue_challenge(device.device_id)
        signature = device.sign_challenge(challenge)
        assert fog.register(device.device_id, device.did,
                            device.public_key, signature)
        print()

    # Sort once, at the end of the registration window. All five devices
    # will use this one root for this epoch.
    entries = sorted(fog.batch, key=lambda entry: entry["leaf"])
    leaves = [bytes.fromhex(entry["leaf"]) for entry in entries]
    levels = build_tree(leaves)
    epoch = "epoch-1"
    root_registry = {epoch: levels[-1][0].hex()}

    print("=== Batch finalized ===")
    print(f"Epoch: {epoch}")
    print(f"Devices: {len(entries)}")
    print(f"Trusted root: {root_registry[epoch]}")

    # The fog creates a separate proof package for every device.
    device_proofs = {}
    for index, entry in enumerate(entries):
        device_proofs[entry["device_id"]] = {
            "did": entry["did"],
            "public_key": entry["public_key"],
            "epoch": epoch,
            "proof": make_proof(levels, index),
        }

    print("\n=== Verifying each device against the trusted epoch root ===")
    for name, _ in specifications:
        package = device_proofs[name]
        # Recalculate the assignment leaf: H(DID || public key).
        leaf = hashlib.sha256(
            package["did"].encode("utf-8") + package["public_key"]
        ).digest()
        trusted_root = bytes.fromhex(root_registry[package["epoch"]])
        valid = verify_proof(leaf, package["proof"], trusted_root)
        print(f"{name}: {'PASS' if valid else 'DENY'} "
              f"({len(package['proof'])} sibling hashes)")
        assert valid

    # A changed leaf must fail against the original root.
    first_package = device_proofs[specifications[0][0]]
    altered_leaf = hashlib.sha256(b"not the registered device").digest()
    print("\nTampered leaf:",
          "DENY" if not verify_proof(
              altered_leaf, first_package["proof"],
              bytes.fromhex(root_registry[epoch])) else "UNEXPECTED PASS")


if __name__ == "__main__":
    main()
