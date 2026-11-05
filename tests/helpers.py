import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app")
if APP not in sys.path:
    sys.path.insert(0, APP)


def openssl(*args, stdin=b""):
    """Ejecuta openssl para comprobar resultados en los tests."""
    return subprocess.run(["openssl", *args], input=stdin, capture_output=True, check=False)


def base_request(**overrides):
    data = {
        "keyType": "ecp256",
        "digest": "sha256",
        "cipher": "none",
        "keyFormat": "pkcs8",
        "subject": {"CN": "www.ejemplo.es", "O": "Ejemplo S.L.", "C": "ES"},
        "sans": [],
        "cnInSan": True,
        "keyUsage": ["digitalSignature"],
        "extKeyUsage": ["serverAuth"],
    }
    data.update(overrides)
    return data
