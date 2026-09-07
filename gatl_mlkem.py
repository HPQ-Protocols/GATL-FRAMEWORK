import hashlib
import hmac
import importlib
import importlib.metadata
import os
import subprocess
import tempfile
import threading
from collections import namedtuple
from pathlib import Path

PUBLIC_KEY_BYTES = 1184
CIPHERTEXT_BYTES = 1088
SHARED_KEY_BYTES = 32
SPKI_PREFIX = bytes.fromhex("308204b2300b0609608648016503040402038204a100")
KeyResult = namedtuple("KeyResult", "status context ciphertext candidate_key")

def require_bytes(value, length, label):
    if type(value) is not bytes or len(value) != length:
        raise ValueError("Invalid " + label + " type/length.")
    return value

def key_id(public_key):
    require_bytes(public_key, PUBLIC_KEY_BYTES, "ML-KEM-768 public key")
    return hashlib.sha256(public_key).digest()

class PQCryptoBackend:
    def __init__(self, expected_version="0.3.4"):
        version = importlib.metadata.version("pqcrypto")
        if version != expected_version:
            raise RuntimeError("Expected pqcrypto==" + expected_version + "; found " + version)
        self._module = importlib.import_module("pqcrypto.kem.ml_kem_768")
        for name in ("generate_keypair", "encrypt", "decrypt"):
            if not callable(getattr(self._module, name, None)):
                raise RuntimeError("Unsupported pqcrypto API: " + name)
        self.metadata = {
            "backend": "pqcrypto", "version": version,
            "algorithm": "ML-KEM-768", "interface": "Python_CFFI",
            "public_key_encoding": "FIPS203_raw_1184_bytes",
            "secret_key_encoding": "expanded_raw_2400_bytes",
            "randomness": "backend_system_randomness_no_test_seed",
            "files": [], "benchmark_ready": False,
        }
        distribution = importlib.metadata.distribution("pqcrypto")
        for relative in distribution.files or ():
            if "ml_kem_768" in str(relative) and str(relative).endswith((".py", ".so", ".pyd")):
                path = Path(distribution.locate_file(relative))
                self.metadata["files"].append({
                    "distribution_relative_path": str(relative),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                })
        if not self.metadata["files"]:
            raise RuntimeError("Cannot fingerprint the installed ML-KEM backend.")

    def keygen(self):
        public_key, secret_key = self._module.generate_keypair()
        require_bytes(public_key, PUBLIC_KEY_BYTES, "public key")
        require_bytes(secret_key, 2400, "secret key")
        return public_key, secret_key

    def encaps(self, public_key):
        require_bytes(public_key, PUBLIC_KEY_BYTES, "public key")
        ciphertext, shared_key = self._module.encrypt(public_key)
        require_bytes(ciphertext, CIPHERTEXT_BYTES, "ciphertext")
        require_bytes(shared_key, SHARED_KEY_BYTES, "shared key")
        return ciphertext, shared_key

    def decaps(self, secret_key, ciphertext):
        require_bytes(secret_key, 2400, "secret key")
        require_bytes(ciphertext, CIPHERTEXT_BYTES, "ciphertext")
        return require_bytes(self._module.decrypt(secret_key, ciphertext), SHARED_KEY_BYTES, "shared key")

class OpenSSLBackend:
    def __init__(self, workdir):
        self._workdir = Path(workdir)
        self._workdir.mkdir(parents=True, exist_ok=True)
        version = self._run(["version"]).decode("ascii").strip()
        algorithms = self._run(["list", "-kem-algorithms", "-provider", "default"]).decode("ascii")
        if "ML-KEM-768" not in algorithms:
            raise RuntimeError("OpenSSL default provider does not offer ML-KEM-768.")
        self.metadata = {
            "backend": "openssl_cli", "version": version,
            "algorithm": "ML-KEM-768", "provider": "default",
            "interface": "subprocess_and_temporary_files_correctness_only",
            "public_key_encoding": "raw_1184_extracted_from_checked_DER_SPKI",
            "secret_key_encoding": "DER_private_key_not_raw_2400_bytes",
            "randomness": "OpenSSL_provider_randomness_no_test_seed",
            "benchmark_ready": False,
            "build_details": self._run(["version", "-a"]).decode("ascii").strip(),
        }

    def _run(self, arguments, input_data=None):
        result = subprocess.run(["openssl", *arguments], input=input_data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if result.returncode:
            raise RuntimeError("OpenSSL operation failed: " + arguments[0])
        return result.stdout

    def _write_private(self, path, data):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)

    def keygen(self):
        secret_key = self._run(["genpkey", "-algorithm", "ML-KEM-768", "-outform", "DER",
                                "-provider", "default"])
        public_der = self._run(["pkey", "-inform", "DER", "-pubout", "-outform", "DER",
                                "-provider", "default"], secret_key)
        if not public_der.startswith(SPKI_PREFIX) or len(public_der) != len(SPKI_PREFIX) + PUBLIC_KEY_BYTES:
            raise RuntimeError("Unexpected ML-KEM-768 public-key DER encoding.")
        return public_der[len(SPKI_PREFIX):], secret_key

    def encaps(self, public_key):
        require_bytes(public_key, PUBLIC_KEY_BYTES, "public key")
        with tempfile.TemporaryDirectory(prefix="mlkem_", dir=self._workdir) as temporary:
            directory = Path(temporary)
            public_path, key_path = directory / "public.der", directory / "candidate.bin"
            self._write_private(public_path, SPKI_PREFIX + public_key)
            self._write_private(key_path, b"")
            ciphertext = self._run(["pkeyutl", "-encap", "-pubin", "-keyform", "DER",
                                    "-inkey", str(public_path), "-secret", str(key_path),
                                    "-provider", "default"])
            shared_key = key_path.read_bytes()
        require_bytes(ciphertext, CIPHERTEXT_BYTES, "ciphertext")
        require_bytes(shared_key, SHARED_KEY_BYTES, "shared key")
        return ciphertext, shared_key

    def decaps(self, secret_key, ciphertext):
        if type(secret_key) is not bytes or not secret_key:
            raise ValueError("Invalid DER private key.")
        require_bytes(ciphertext, CIPHERTEXT_BYTES, "ciphertext")
        with tempfile.TemporaryDirectory(prefix="mlkem_", dir=self._workdir) as temporary:
            directory = Path(temporary)
            private_path, key_path = directory / "private.der", directory / "candidate.bin"
            self._write_private(private_path, secret_key)
            self._write_private(key_path, b"")
            self._run(["pkeyutl", "-decap", "-keyform", "DER", "-inkey", str(private_path),
                       "-secret", str(key_path), "-provider", "default"], ciphertext)
            shared_key = key_path.read_bytes()
        return require_bytes(shared_key, SHARED_KEY_BYTES, "shared key")

class VerifiedKEMReceiver:
    def __init__(self, channel, backend, public_key, secret_key):
        if channel._kemkid != key_id(public_key):
            raise ValueError("Transport context is not bound to the provisioned KEM public key.")
        self.channel = channel
        self._backend, self._secret_key = backend, secret_key
        self._kemkid = key_id(public_key)
        self.decapsulation_calls = 0
        self._closed = False
        self._lock = threading.RLock()

    def receive(self, packet):
        with self._lock:
            if self._closed:
                return KeyResult("DROP", None, None, None)
            result = self.channel.receive(packet)
            if result.status != "DELIVERED":
                return KeyResult(result.status, result.context, None, None)
            if result.context.kemkid != self._kemkid or result.context.length != CIPHERTEXT_BYTES:
                raise ValueError("Invalid KEM transport context.")
            require_bytes(result.payload, CIPHERTEXT_BYTES, "reconstructed ciphertext")
            self.decapsulation_calls += 1
            candidate = self._backend.decaps(self._secret_key, result.payload)
            require_bytes(candidate, SHARED_KEY_BYTES, "candidate key")
            return KeyResult("KEY_CANDIDATE", result.context, result.payload, candidate)

    def close(self):
        with self._lock:
            self.channel.close()
            self._secret_key = b""
            self._closed = True
