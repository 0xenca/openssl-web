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


def e2e_seal(key_info, path, obj):
    """Cliente de prueba del protocolo sgen1 (igual que hace el navegador).

    Devuelve (sobre_cifrado, clave_respuesta)."""
    import base64
    import json as _json

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    kid = base64.b64decode(key_info["kid"])
    server_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), base64.b64decode(key_info["publicKey"]))
    client = ec.generate_private_key(ec.SECP256R1())
    shared = client.exchange(ec.ECDH(), server_pub)
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=kid, info=b"encas-sgen e2e v1").derive(shared)
    iv = os.urandom(12)
    ct = AESGCM(okm[:32]).encrypt(iv, _json.dumps(obj).encode(), f"sgen1|req|{path}".encode())
    epk = client.public_key().public_bytes(serialization.Encoding.X962,
                                           serialization.PublicFormat.UncompressedPoint)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return {"v": 1, "kid": key_info["kid"], "epk": b64(epk), "iv": b64(iv), "ct": b64(ct)}, okm[32:]


def e2e_open(res_key, path, envelope):
    import base64
    import json as _json

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    plain = AESGCM(res_key).decrypt(base64.b64decode(envelope["iv"]), base64.b64decode(envelope["ct"]),
                                    f"sgen1|res|{path}".encode())
    return _json.loads(plain)
