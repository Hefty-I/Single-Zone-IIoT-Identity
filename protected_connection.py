"""Assignment 1, step 8: send real device/fog messages over localhost TLS.

One fog and five simulated devices connect over TCP on 127.0.0.1. A new
local certificate authority is created for each demonstration. Its certificate
is provisioned directly to the simulated clients so they verify the fog.
Temporary certificate and key files are removed when the program finishes.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
import socket
import ssl
import tempfile
import threading
from pathlib import Path
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from access import TRUSTED_ROLES
from registry import ROOTS_FILE, next_epoch, read_json
from revocation import RevocableFogAccess, RevocationStore
from signed_access import signed_bytes
from identity import Device, Fog
from temporary_token import TemporaryTokenFog, temporary_request_bytes


MAX_MESSAGE_BYTES = 65536
PSK_CONTEXT = b"fog-psk-auth:"  # Keep authentication separate from other HMACs.


class RealClock:
    def now(self) -> float:
        return time.time()


def make_tls_contexts(folder: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """Give server a certificate and clients an explicitly trusted CA."""
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                           "IIoT local demo CA")])
    ca_cert = (x509.CertificateBuilder()
               .subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=1))
               .not_valid_after(now + timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                              critical=True)
               .sign(ca_key, hashes.SHA256()))

    server_key = ec.generate_private_key(ec.SECP256R1())
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                               "localhost")])
    server_cert = (x509.CertificateBuilder()
                   .subject_name(server_name).issuer_name(ca_name)
                   .public_key(server_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=False,
                                                        path_length=None),
                                  critical=True)
                   .add_extension(x509.SubjectAlternativeName(
                       [x509.DNSName("localhost")]), critical=False)
                   .add_extension(x509.ExtendedKeyUsage(
                       [ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .sign(ca_key, hashes.SHA256()))

    cert_path = folder / "fog-cert.pem"
    key_path = folder / "fog-key.pem"
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(str(cert_path), str(key_path))

    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    client_context.load_verify_locations(cadata=ca_cert.public_bytes(
        serialization.Encoding.PEM).decode("ascii"))
    # PROTOCOL_TLS_CLIENT requires a trusted chain and checks 'localhost'.
    return server_context, client_context


class JsonChannel:
    """One size-limited JSON message per line inside the TLS connection."""

    def __init__(self, tls_socket: ssl.SSLSocket):
        self.socket = tls_socket
        self.reader = tls_socket.makefile("rb")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.reader.close()

    def send(self, message: dict) -> None:
        data = json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(data) > MAX_MESSAGE_BYTES:
            raise ValueError("message too large")
        self.socket.sendall(data)

    def receive(self) -> dict:
        data = self.reader.readline(MAX_MESSAGE_BYTES + 1)
        if not data or len(data) > MAX_MESSAGE_BYTES:
            raise ValueError("empty or oversized message")
        message = json.loads(data)
        if not isinstance(message, dict):
            raise ValueError("expected JSON object")
        return message


class ProtectedFogServer:
    def __init__(self, devices: dict[str, Device], roles: dict[str, str]):
        trusted = {name: {"psk": device.psk, "role": roles[name]}
                   for name, device in devices.items()}
        self.fog = Fog(trusted)
        self.revocations = RevocationStore()
        self.temporary = TemporaryTokenFog(self.fog, self.revocations,
                                           RealClock())
        self.permanent = None
        self.roots = None
        self.records = None
        self.errors = []
        self._stopping = threading.Event()
        self._temporary_files = tempfile.TemporaryDirectory(
            prefix="iiot-tls-")
        self.server_context, self.client_context = make_tls_contexts(
            Path(self._temporary_files.name))
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.listener.settimeout(0.2)
        self.address = self.listener.getsockname()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self._stopping.set()
        self.listener.close()
        self.thread.join(timeout=5)
        self._temporary_files.cleanup()
        if self.errors:
            raise RuntimeError(f"TLS fog server error: {self.errors[0]}")

    def _serve(self) -> None:
        while not self._stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self._stopping.is_set():
                    self.errors.append("listener closed unexpectedly")
                break
            try:
                with connection:
                    with self.server_context.wrap_socket(
                            connection, server_side=True) as tls:
                        tls.settimeout(5)
                        with JsonChannel(tls) as channel:
                            self._handle(channel)
            except Exception as exc:
                self.errors.append(repr(exc))

    def _handle(self, channel: JsonChannel) -> None:
        try:
            message = channel.receive()
            kind = message.get("type")
            if kind == "register":
                self._register(channel, message)
            elif kind == "temporary_access":
                self._temporary_access(channel, message)
            elif kind == "get_proof":
                self._get_proof(channel, message)
            elif kind == "permanent_access":
                self._permanent_access(channel, message)
            else:
                channel.send({"status": "DENY", "reason": "unknown operation"})
        except (KeyError, TypeError, ValueError) as exc:
            channel.send({"status": "DENY", "reason": f"bad request: {exc}"})

    def _register(self, channel: JsonChannel, message: dict) -> None:
        name = message["device_id"]
        trusted = self.fog.trusted_devices.get(name)
        if (trusted is None or name in self.temporary.waiting
                or self.revocations.is_revoked(name)
                or self.temporary.finalized):
            channel.send({"status": "DENY", "reason": "device not eligible"})
            return

        challenge = secrets.token_bytes(32)
        channel.send({"status": "PSK_CHALLENGE", "challenge": challenge.hex()})
        response = channel.receive()
        expected = hmac.new(trusted["psk"], PSK_CONTEXT + challenge,
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(response.get("hmac_hex", ""), expected):
            channel.send({"status": "DENY", "reason": "PSK proof failed"})
            return

        # The HMAC proved that the remote device knows its provisioned PSK.
        assert self.fog.authenticate(name, trusted["psk"])
        ecc_challenge = self.fog.issue_challenge(name)
        channel.send({"status": "ECC_CHALLENGE",
                      "challenge": ecc_challenge.hex()})
        answer = channel.receive()
        accepted = self.fog.register(
            name, message["did"], bytes.fromhex(message["public_key_hex"]),
            bytes.fromhex(answer["signature_hex"]))
        if not accepted:
            channel.send({"status": "DENY", "reason": "ECC proof failed"})
            return

        self.temporary.waiting[name] = self.fog.batch[-1]
        token = self.temporary.issue_token(name)
        channel.send({"status": "REGISTERED", "leaf": self.fog.batch[-1]["leaf"],
                      "token": token})

    def _temporary_access(self, channel: JsonChannel, message: dict) -> None:
        try:
            nonce = self.temporary.issue_nonce(message["token"])
        except ValueError as exc:
            channel.send({"status": "DENY", "reason": str(exc)})
            return
        channel.send({"status": "NONCE", "nonce": nonce})
        answer = channel.receive()
        decision, reason = self.temporary.request(
            message["token"], message["resource"], message["operation"],
            nonce, bytes.fromhex(answer["signature_hex"]))
        channel.send({"status": decision, "reason": reason})

    def _get_proof(self, channel: JsonChannel, message: dict) -> None:
        if self.permanent is None:
            channel.send({"status": "DENY", "reason": "batch still open"})
            return
        package = next((record for batch in self.records.values()
                        for record in batch
                        if record["did"] == message["did"]
                        and record["public_key_hex"] == message["public_key_hex"]),
                       None)
        if package is None:
            channel.send({"status": "DENY", "reason": "proof not found"})
            return
        # Merkle proofs are public; actual access still needs a device signature.
        channel.send({"status": "PROOF", "package": package})

    def _permanent_access(self, channel: JsonChannel, message: dict) -> None:
        if self.permanent is None:
            channel.send({"status": "DENY", "reason": "batch still open"})
            return
        try:
            nonce = self.permanent.issue_nonce(message["package"])
        except ValueError as exc:
            channel.send({"status": "DENY", "reason": str(exc)})
            return
        channel.send({"status": "NONCE", "nonce": nonce})
        answer = channel.receive()
        decision, reason = self.permanent.request(
            message["package"], message["resource"], message["operation"],
            nonce, bytes.fromhex(answer["signature_hex"]))
        channel.send({"status": decision, "reason": reason})

    def finalize(self) -> tuple[str, dict]:
        epoch, self.roots, self.records = self.temporary.finalize_batch()
        self.permanent = RevocableFogAccess(self.roots, self.records,
                                             self.revocations)
        return epoch, self.roots


def connect(server: ProtectedFogServer) -> ssl.SSLSocket:
    raw = socket.create_connection(server.address, timeout=5)
    try:
        return server.client_context.wrap_socket(raw, server_hostname="localhost")
    except Exception:
        raw.close()
        raise


def register_device(server: ProtectedFogServer, device: Device) -> dict:
    with connect(server) as tls:
        if not hasattr(server, "tls_version"):
            server.tls_version = tls.version()
        with JsonChannel(tls) as channel:
            channel.send({"type": "register", "device_id": device.device_id,
                          "did": device.did,
                          "public_key_hex": device.public_key.hex()})
            response = channel.receive()
            if response["status"] != "PSK_CHALLENGE":
                return response
            proof = hmac.new(device.psk,
                             PSK_CONTEXT + bytes.fromhex(response["challenge"]),
                             hashlib.sha256).hexdigest()
            channel.send({"hmac_hex": proof})
            response = channel.receive()
            if response["status"] != "ECC_CHALLENGE":
                return response
            signature = device.sign_challenge(bytes.fromhex(response["challenge"]))
            channel.send({"signature_hex": signature.hex()})
            return channel.receive()


def temporary_access(server: ProtectedFogServer, device: Device, token: dict,
                     resource: str, operation: str) -> dict:
    with connect(server) as tls:
        with JsonChannel(tls) as channel:
            channel.send({"type": "temporary_access", "token": token,
                          "resource": resource, "operation": operation})
            response = channel.receive()
            if response["status"] != "NONCE":
                return response
            signature = device.sign_challenge(temporary_request_bytes(
                token["claims"], resource, operation, response["nonce"]))
            channel.send({"signature_hex": signature.hex()})
            return channel.receive()


def get_proof(server: ProtectedFogServer, device: Device) -> dict:
    with connect(server) as tls:
        with JsonChannel(tls) as channel:
            channel.send({"type": "get_proof", "did": device.did,
                          "public_key_hex": device.public_key.hex()})
            response = channel.receive()
            if response["status"] != "PROOF":
                raise ValueError(response)
            return response["package"]


def permanent_access(server: ProtectedFogServer, device: Device,
                     package: dict, resource: str, operation: str) -> dict:
    with connect(server) as tls:
        with JsonChannel(tls) as channel:
            channel.send({"type": "permanent_access", "package": package,
                          "resource": resource, "operation": operation})
            response = channel.receive()
            if response["status"] != "NONCE":
                return response
            signature = device.sign_challenge(signed_bytes(
                package, resource, operation, response["nonce"]))
            channel.send({"signature_hex": signature.hex()})
            return channel.receive()


def show(label: str, result: dict, expected: str) -> None:
    print(f"{label}: {result['status']} ({result.get('reason', '')})")
    assert result["status"] == expected


def main() -> None:
    label = next_epoch(read_json(ROOTS_FILE)).replace("-", "_")
    roles = {f"{base}_{label}": role for base, role in TRUSTED_ROLES.items()}
    devices = {name: Device(name, secrets.token_bytes(32)) for name in roles}
    sensor_name = f"temperature_sensor_1_{label}"
    motor_name = f"motor_controller_1_{label}"

    with ProtectedFogServer(devices, roles) as server:
        print("=== One fog, five devices, real localhost TLS ===")
        fake_sensor = Device(sensor_name, secrets.token_bytes(32))
        show("Wrong PSK over TLS", register_device(server, fake_sensor), "DENY")

        tokens = {}
        for name, device in devices.items():
            response = register_device(server, device)
            assert response["status"] == "REGISTERED"
            tokens[name] = response["token"]
            print(f"{name}: registered, leaf {response['leaf'][:16]}...")
            if name == sensor_name:
                show("Sensor temporary WRITE over TLS",
                     temporary_access(server, device, tokens[name],
                                      "temperature_readings", "WRITE"), "ALLOW")

        print(f"TLS {server.tls_version}: verified fog certificate for localhost")
        assert len(server.fog.batch) == 5
        epoch, roots = server.finalize()
        print(f"{epoch}: 5 registered devices, trusted root {roots[epoch]}")

        show("Temporary token after finalization",
             temporary_access(server, devices[sensor_name],
                              tokens[sensor_name],
                              "temperature_readings", "WRITE"), "DENY")

        motor_proof = get_proof(server, devices[motor_name])
        show("Motor STOP with proof and signature over TLS",
             permanent_access(server, devices[motor_name], motor_proof,
                              "production_line", "STOP"), "ALLOW")
        sensor_proof = get_proof(server, devices[sensor_name])
        show("Sensor STOP denied by policy over TLS",
             permanent_access(server, devices[sensor_name], sensor_proof,
                              "production_line", "STOP"), "DENY")


if __name__ == "__main__":
    main()
