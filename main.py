r"""Run the single-zone IIoT assignment from one command.

On Windows: .\.venv\Scripts\python.exe .\main.py
Use --skip-performance for a quick run without rewriting results/.
"""

import argparse
from pathlib import Path
import subprocess
import sys


PROJECT = Path(__file__).resolve().parent

# Keep registry before access.py: the access demonstration reads saved proofs.
STEPS = (
    ("Protected device-to-fog connection", "protected_connection.py"),
    ("Device identity and ECC challenge", "identity.py"),
    ("Merkle batch and inclusion proofs", "batch.py"),
    ("Stored roots and historical proofs", "registry.py"),
    ("Proof verification and resource rules", "access.py"),
    ("Fresh signatures and replay protection", "signed_access.py"),
    ("Temporary tokens and token attacks", "temporary_token.py"),
    ("Device revocation and next epoch", "revocation.py"),
    ("Performance measurements and graphs", "performance.py"),
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-performance", action="store_true",
        help="run the security demonstrations without replacing results/ files",
    )
    args = parser.parse_args()

    steps = STEPS[:-1] if args.skip_performance else STEPS
    print(f"Running {len(steps)} steps with {sys.executable}", flush=True)
    if not args.skip_performance:
        print("The benchmark will refresh the CSV files and graphs in results/.",
              flush=True)

    for number, (title, script_name) in enumerate(steps, start=1):
        script = PROJECT / script_name
        print(f"\n{'=' * 65}\n{number}/{len(steps)}  {title} ({script_name})\n"
              f"{'=' * 65}", flush=True)
        if not script.is_file():
            print(f"Missing file: {script}", file=sys.stderr)
            return 1
        result = subprocess.run([sys.executable, str(script)], cwd=PROJECT)
        if result.returncode != 0:
            print(f"\nStopped: {script_name} failed with exit code "
                  f"{result.returncode}.", file=sys.stderr, flush=True)
            return result.returncode
        print(f"Completed: {script_name}", flush=True)

    print("\nAll selected steps completed successfully.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
