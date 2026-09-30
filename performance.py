"""Assignment 1: repeatable single-zone performance evaluation.

Run: py performance.py
Writes raw and averaged CSV files plus four PNG graphs into results/.
Registration and access logs are suppressed during timing so terminal output
does not dominate measurements. All benchmark roots stay in memory.
"""

import argparse
import csv
from contextlib import redirect_stdout
from pathlib import Path
import secrets
import statistics
import time

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from access import TRUSTED_ROLES
from batch import build_tree, make_proof, verify_proof
from revocation import RevocableFogAccess, RevocationStore
from signed_access import signed_bytes
from identity import Device, Fog
from temporary_token import (DemoClock, TemporaryTokenFog,
                             temporary_request_bytes)


RESULTS = Path(__file__).resolve().parent / "results"
COUNTS = (5, 10, 25, 50, 100)
RUNS = 5
VERIFY_ROUNDS = 100
ACCESS_ROUNDS = 30


class QuietOutput:
    def write(self, value: str) -> int:
        return len(value)

    def flush(self) -> None:
        pass


def milliseconds(start_ns: int, end_ns: int) -> float:
    return (end_ns - start_ns) / 1_000_000


def measure(count: int, trial: int) -> dict:
    """One trial runs the same operations used in the project demos."""
    source_roles = tuple(TRUSTED_ROLES.items())
    run_id = secrets.token_hex(4)
    specifications = [
        (f"{source_roles[index % len(source_roles)][0]}_bench_{run_id}_{index}",
         source_roles[index % len(source_roles)][1])
        for index in range(count)
    ]
    psks = {name: secrets.token_bytes(32) for name, _ in specifications}
    fog = Fog({name: {"psk": psks[name], "role": role}
               for name, role in specifications})
    devices = {}
    registration_ns = 0

    # Include key generation, PSK check, fresh challenge, ECC signing and
    # verification, and addition to the open batch for each device.
    with redirect_stdout(QuietOutput()):
        for name, _ in specifications:
            start = time.perf_counter_ns()
            device = Device(name, psks[name])
            assert fog.authenticate(name, device.psk)
            challenge = fog.issue_challenge(name)
            assert fog.register(name, device.did, device.public_key,
                                device.sign_challenge(challenge))
            registration_ns += time.perf_counter_ns() - start
            devices[name] = device

    start = time.perf_counter_ns()
    entries = sorted(fog.batch, key=lambda entry: entry["leaf"])
    leaves = [bytes.fromhex(entry["leaf"]) for entry in entries]
    levels = build_tree(leaves)
    root = levels[-1][0]
    batch_ns = time.perf_counter_ns() - start

    start = time.perf_counter_ns()
    proofs = [make_proof(levels, index) for index in range(count)]
    proof_ns = time.perf_counter_ns() - start

    start = time.perf_counter_ns()
    for _ in range(VERIFY_ROUNDS):
        for leaf, proof in zip(leaves, proofs):
            assert verify_proof(leaf, proof, root)
    verification_ns = time.perf_counter_ns() - start
    verification_operations = count * VERIFY_ROUNDS

    # Comparison measures only tree/root construction, with the same leaves.
    # Individual arrival recalculates a tree after each new device; the batch
    # approach sorts and builds one tree after the registration window.
    start = time.perf_counter_ns()
    arrived = []
    for entry in fog.batch:
        arrived.append(bytes.fromhex(entry["leaf"]))
        build_tree(sorted(arrived))
    individual_ns = time.perf_counter_ns() - start

    sensor_name = specifications[0][0]  # First role is temperature_sensor.
    sensor = devices[sensor_name]
    revocations = RevocationStore()
    temporary = TemporaryTokenFog(fog, revocations, DemoClock())
    temporary.waiting = {entry["device_id"]: entry for entry in fog.batch}
    token = temporary.issue_token(sensor_name)
    start = time.perf_counter_ns()
    for _ in range(ACCESS_ROUNDS):
        nonce = temporary.issue_nonce(token)
        signature = sensor.sign_challenge(temporary_request_bytes(
            token["claims"], "temperature_readings", "WRITE", nonce))
        decision, _ = temporary.request(token, "temperature_readings",
                                        "WRITE", nonce, signature)
        assert decision == "ALLOW"
    temporary_ns = time.perf_counter_ns() - start

    epoch = f"benchmark-{run_id}"
    roots = {epoch: root.hex()}
    records = {epoch: [
        {"device_id": entry["device_id"], "role": entry["role"],
         "did": entry["did"], "public_key_hex": entry["public_key"].hex(),
         "epoch": epoch, "proof": proofs[index]}
        for index, entry in enumerate(entries)
    ]}
    sensor_proof = next(record for record in records[epoch]
                        if record["device_id"] == sensor_name)
    gate = RevocableFogAccess(roots, records, revocations)
    start = time.perf_counter_ns()
    for _ in range(ACCESS_ROUNDS):
        nonce = gate.issue_nonce(sensor_proof)
        signature = sensor.sign_challenge(signed_bytes(
            sensor_proof, "temperature_readings", "WRITE", nonce))
        decision, _ = gate.request(sensor_proof, "temperature_readings",
                                   "WRITE", nonce, signature)
        assert decision == "ALLOW"
    resource_ns = time.perf_counter_ns() - start

    registration_ms = registration_ns / 1_000_000
    batch_ms = batch_ns / 1_000_000
    proof_ms = proof_ns / 1_000_000
    return {
        "devices": count,
        "trial": trial,
        "registration_ms_per_device": registration_ms / count,
        "batch_processing_ms": batch_ms,
        "proof_generation_ms_per_device": proof_ms / count,
        "batch_registration_total_ms": registration_ms + batch_ms + proof_ms,
        "verification_ms_per_proof": verification_ns / 1_000_000
        / verification_operations,
        "registration_per_second": count * 1_000_000_000 / registration_ns,
        "verification_per_second": verification_operations
        * 1_000_000_000 / verification_ns,
        "temporary_request_ms": temporary_ns / 1_000_000 / ACCESS_ROUNDS,
        "resource_access_ms": resource_ns / 1_000_000 / ACCESS_ROUNDS,
        "individual_rebuild_ms": individual_ns / 1_000_000,
        "batch_root_updates": 1,
        "individual_root_updates": count,
    }


def save_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def save_graph(summary: list[dict], fields: list[str], labels: list[str],
               title: str, ylabel: str, filename: str) -> None:
    fig, axes = plt.subplots(figsize=(7.2, 4.4))
    devices = [row["devices"] for row in summary]
    for field, label in zip(fields, labels):
        axes.plot(devices, [row[field] for row in summary],
                  marker="o", linewidth=2, label=label)
    axes.set(title=title, xlabel="Number of simulated devices", ylabel=ylabel)
    axes.set_xticks(devices)
    axes.grid(True, alpha=0.3)
    if len(fields) > 1:
        axes.legend()
    fig.tight_layout()
    fig.savefig(RESULTS / filename, dpi=180)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=RUNS,
                        help="repeats per device count (default: 5)")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be at least 1")
    RESULTS.mkdir(parents=True, exist_ok=True)

    print(f"Measuring {COUNTS} devices, {args.runs} trials each...")
    raw = []
    for count in COUNTS:
        for trial in range(1, args.runs + 1):
            raw.append(measure(count, trial))
        print(f"  {count} devices: {args.runs} trials finished")

    metric_names = [key for key in raw[0] if key not in ("devices", "trial")]
    summary = [
        {"devices": count, "runs": args.runs,
         **{key: statistics.mean(row[key] for row in raw
                                 if row["devices"] == count)
            for key in metric_names}}
        for count in COUNTS
    ]
    save_csv(RESULTS / "raw_measurements.csv", raw)
    save_csv(RESULTS / "summary.csv", summary)

    save_graph(summary, ["batch_registration_total_ms"], ["Batch"],
               "Batch registration through proof generation",
               "Average total time (ms)", "01_batch_registration.png")
    save_graph(summary, ["verification_ms_per_proof"], ["Verification"],
               "Merkle membership verification latency",
               "Average time per proof (ms)", "02_verification_latency.png")
    save_graph(summary, ["verification_per_second"], ["Verification"],
               "Verification throughput",
               "Verified proofs per second", "03_throughput.png")
    save_graph(summary, ["individual_rebuild_ms", "batch_processing_ms"],
               ["Rebuild on each arrival", "One batch root"],
               "Tree processing: individual vs batch",
               "Average tree work (ms)", "04_batch_vs_individual.png")

    print("\nMean results (your computer's timings will differ):")
    print("Devices | Batch total ms | Verify ms/proof | Verify proofs/s")
    for row in summary:
        print(f"{row['devices']:>7} | {row['batch_registration_total_ms']:>14.3f} "
              f"| {row['verification_ms_per_proof']:>15.5f} "
              f"| {row['verification_per_second']:>15.0f}")
    print("\nSaved 2 CSV files and 4 graphs in results/.")
    print("Individual comparison times repeated tree rebuilding only; it does "
          "not include maintaining old proofs or anchoring each root.")


if __name__ == "__main__":
    main()
