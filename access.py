"""Assignment 1, step 4: identity verification plus resource policy.

Run registry.py first so runtime/roots.json and runtime/proofs.json exist.
This local demo checks membership and a trusted fog-side role. Fresh request
signatures, revocation, and network transport are later steps.
"""

from copy import deepcopy

from registry import PROOFS_FILE, ROOTS_FILE, read_json, verify_saved_package


# These roles belong to the fog's trusted provisioning records. The device
# cannot gain a new role by putting a different role in its request.
TRUSTED_ROLES = {
    "temperature_sensor_1": "temperature_sensor",
    "pressure_sensor_1": "pressure_sensor",
    "smart_meter_1": "smart_meter",
    "valve_controller_1": "valve_controller",
    "motor_controller_1": "motor_controller",
}

# Each entry is an exact (resource, operation) permission.
POLICY = {
    "temperature_sensor": {("temperature_readings", "WRITE")},
    "pressure_sensor": {("pressure_readings", "WRITE")},
    "smart_meter": {("energy_readings", "WRITE")},
    "valve_controller": {("valve_position", "SET")},
    "motor_controller": {
        ("production_line", "START"),
        ("production_line", "STOP"),
    },
}


def decide(request: dict, resource: str, operation: str,
           roots: dict, fog_records: dict) -> tuple[str, str]:
    """Return (ALLOW/DENY, reason) from trusted data and a submitted proof."""
    try:
        if not verify_saved_package(request, roots):
            return "DENY", "membership proof failed"

        # Find the fog's own record for this DID and public key. Ignore any
        # device_id or role supplied by the requester; those are not in the
        # Merkle leaf and could be changed without breaking its proof.
        records = fog_records.get(request["epoch"], [])
        trusted = next((record for record in records
                        if record["did"] == request["did"]
                        and record["public_key_hex"] == request["public_key_hex"]),
                       None)
        if trusted is None:
            return "DENY", "no trusted device record"
    except (KeyError, TypeError, ValueError):
        return "DENY", "malformed identity or proof"

    role = TRUSTED_ROLES.get(trusted["device_id"])
    if role is None:
        return "DENY", "no trusted role"
    if (resource, operation) not in POLICY.get(role, set()):
        return "DENY", f"{role} cannot {operation} {resource}"
    return "ALLOW", f"verified {role} may {operation} {resource}"


def show(label: str, request: dict, resource: str, operation: str,
         roots: dict, fog_records: dict) -> str:
    decision, reason = decide(request, resource, operation, roots, fog_records)
    print(f"{label}: {decision} ({reason})")
    return decision


def main() -> None:
    roots = read_json(ROOTS_FILE)
    fog_records = read_json(PROOFS_FILE)
    if not roots or not fog_records:
        raise SystemExit("No saved epochs. Run registry.py first.")

    latest_epoch = max(fog_records,
                       key=lambda name: int(name.removeprefix("epoch-")))
    packages = fog_records[latest_epoch]
    sensor = next(record for record in packages
                  if record["device_id"] == "temperature_sensor_1")
    motor = next(record for record in packages
                 if record["device_id"] == "motor_controller_1")
    print(f"Local membership and policy check against {latest_epoch}")
    print("Live request signatures and revocation are still to be added.\n")

    assert show("Sensor writes temperature", sensor,
                "temperature_readings", "WRITE", roots, fog_records) == "ALLOW"
    assert show("Sensor stops production line", sensor,
                "production_line", "STOP", roots, fog_records) == "DENY"
    assert show("Motor controller stops production line", motor,
                "production_line", "STOP", roots, fog_records) == "ALLOW"

    tampered = deepcopy(sensor)
    tampered["did"] += "-changed"
    assert show("Changed DID", tampered,
                "temperature_readings", "WRITE", roots, fog_records) == "DENY"

    # A copied proof cannot turn the temperature sensor into a motor controller
    # by changing only the unbound device_id field in its submitted package.
    spoofed_role = deepcopy(sensor)
    spoofed_role["device_id"] = "motor_controller_1"
    assert show("Sensor claims motor-controller name", spoofed_role,
                "production_line", "STOP", roots, fog_records) == "DENY"


if __name__ == "__main__":
    main()
