"""Assignment 1, step 3: save epoch roots and proof packages on disk.

Place this beside step1_identity.py and batch.py. Run it twice to create
epoch-1 and epoch-2; older roots and proofs remain available.
"""

import hashlib
import json
import secrets
from pathlib import Path

from batch import build_tree, make_proof, verify_proof
from identity import Device, Fog


RUNTIME = Path(__file__).resolve().parent / "runtime"
ROOTS_FILE = RUNTIME / "roots.json"
PROOFS_FILE = RUNTIME / "proofs.json"


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def next_epoch(roots: dict) -> str:
    numbers = [
        int(name.removeprefix("epoch-"))
        for name in roots
        if name.startswith("epoch-") and name.removeprefix("epoch-").isdigit()
    ]
    return f"epoch-{max(numbers, default=0) + 1}"


def verify_saved_package(package: dict, roots: dict) -> bool:
    root_hex = roots.get(package["epoch"])
    if root_hex is None:
        return False
    public_key = bytes.fromhex(package["public_key_hex"])
    leaf = hashlib.sha256(package["did"].encode("utf-8") + public_key).digest()
    return verify_proof(leaf, package["proof"], bytes.fromhex(root_hex))


def main() -> None:
    roots = read_json(ROOTS_FILE)
    all_proofs = read_json(PROOFS_FILE)
    epoch = next_epoch(roots)

    specifications = [
        ("temperature_sensor_1", "temperature_sensor"),
        ("pressure_sensor_1", "pressure_sensor"),
        ("smart_meter_1", "smart_meter"),
        ("valve_controller_1", "valve_controller"),
        ("motor_controller_1", "motor_controller"),
    ]
    psks = {name: secrets.token_bytes(32) for name, _ in specifications}
    fog = Fog({
        name: {"psk": psks[name], "role": role}
        for name, role in specifications
    })

    print(f"=== Registering devices for {epoch} ===")
    for name, _ in specifications:
        device = Device(name, psks[name])
        assert fog.authenticate(name, device.psk)
        challenge = fog.issue_challenge(name)
        assert fog.register(name, device.did, device.public_key,
                            device.sign_challenge(challenge))

    entries = sorted(fog.batch, key=lambda entry: entry["leaf"])
    leaves = [bytes.fromhex(entry["leaf"]) for entry in entries]
    levels = build_tree(leaves)
    root_hex = levels[-1][0].hex()

    packages = []
    for index, entry in enumerate(entries):
        packages.append({
            "device_id": entry["device_id"],
            "did": entry["did"],
            "public_key_hex": entry["public_key"].hex(),
            "epoch": epoch,
            "proof": make_proof(levels, index),
        })

    # A finalized epoch gets one root; previous epoch entries are retained.
    roots[epoch] = root_hex
    all_proofs[epoch] = packages
    write_json(ROOTS_FILE, roots)
    write_json(PROOFS_FILE, all_proofs)

    # Read the files back, including any epochs created on earlier runs.
    saved_roots = read_json(ROOTS_FILE)
    saved_proofs = read_json(PROOFS_FILE)
    print("\n=== Saved and reloaded ===")
    print(f"New epoch: {epoch}")
    print(f"New root: {saved_roots[epoch]}")
    print(f"Saved files: {ROOTS_FILE.name}, {PROOFS_FILE.name}")

    for saved_epoch, saved_packages in saved_proofs.items():
        results = [verify_saved_package(package, saved_roots)
                   for package in saved_packages]
        print(f"{saved_epoch}: {sum(results)}/{len(results)} proofs PASS")
        assert all(results)

    # Confirm a changed DID cannot use the same saved public key and proof.
    changed = dict(saved_proofs[epoch][0])
    changed["did"] += "-tampered"
    assert not verify_saved_package(changed, saved_roots)
    print("Tampered saved DID: DENY")


if __name__ == "__main__":
    main()
