"""Cifrado de las comunicaciones navegador <-> servidor con claves efímeras.

Protocolo "sgen1" (una clave privada de servidor por petición):

  1. GET /api/key
     El servidor genera un par de claves ECDH P-256 nuevo, guarda la clave
     privada SOLO en memoria (identificada por un "kid" aleatorio, caduca en
     KEY_TTL segundos) y devuelve {kid, publicKey}.

  2. El navegador genera su propio par ECDH P-256 efímero, calcula el secreto
     compartido y deriva con HKDF-SHA256 (salt = kid) dos claves AES-256-GCM:
     una para la petición y otra para la respuesta.

  3. POST /api/<operación> con {v, kid, epk, iv, ct}: el cuerpo real va
     cifrado con AES-256-GCM. Los datos adicionales autenticados (AAD) incluyen
     la versión, la dirección y la ruta, de modo que un mensaje no puede
     reutilizarse en otra operación.

  4. El servidor RETIRA la clave privada del almacén (uso único), descifra,
     procesa, cifra la respuesta con la clave de respuesta y descarta la clave
     privada, el secreto compartido y las claves derivadas.

La clave privada del servidor nunca sale de la memoria del proceso, nunca se
reutiliza entre peticiones y, si no se usa, se destruye al caducar.
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1
KEY_TTL = 60            # segundos que vive una clave privada sin usar
MAX_PENDING_KEYS = 4096  # límite de claves pendientes en memoria (anti-abuso)
HKDF_INFO = b"encas-sgen e2e v1"
CURVE = ec.SECP256R1()


class E2EError(ValueError):
    """Error de protocolo de cifrado (mensaje genérico para el cliente)."""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text, field, expected_len=None, max_len=1 << 20):
    if not isinstance(text, str) or len(text) > max_len:
        raise E2EError(f"Campo cifrado no válido: {field}")
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise E2EError(f"Campo cifrado no válido: {field}") from None
    if expected_len is not None and len(data) != expected_len:
        raise E2EError(f"Campo cifrado no válido: {field}")
    return data


def aad(direction: str, path: str) -> bytes:
    return f"sgen{VERSION}|{direction}|{path}".encode("ascii")


def derive_keys(private_key, peer_public_key, kid: bytes):
    """Secreto ECDH -> HKDF-SHA256 -> (clave petición, clave respuesta)."""
    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=kid, info=HKDF_INFO).derive(shared)
    del shared
    return okm[:32], okm[32:]


class KeyStore:
    """Almacén en memoria de claves privadas efímeras de un solo uso."""

    def __init__(self, ttl=KEY_TTL, max_keys=MAX_PENDING_KEYS, clock=time.monotonic):
        self._keys = {}
        self._lock = threading.Lock()
        self.ttl = ttl
        self.max_keys = max_keys
        self.clock = clock

    def __len__(self):
        with self._lock:
            return len(self._keys)

    def _purge(self, now):
        expired = [k for k, (_, exp) in self._keys.items() if exp <= now]
        for k in expired:
            del self._keys[k]

    def new_key(self):
        """Crea un par de claves; guarda la privada y devuelve la pública."""
        private_key = ec.generate_private_key(CURVE)
        public_raw = private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        kid = secrets.token_bytes(16)
        now = self.clock()
        with self._lock:
            self._purge(now)
            # Si se alcanza el límite (p. ej. por abuso), se destruyen las claves
            # pendientes más antiguas: un cliente legítimo usa la suya en
            # milisegundos, así que una avalancha no bloquea el servicio.
            while len(self._keys) >= self.max_keys:
                del self._keys[next(iter(self._keys))]
            self._keys[kid] = (private_key, now + self.ttl)
        return {"v": VERSION, "kid": b64e(kid), "publicKey": b64e(public_raw), "ttl": self.ttl}

    def take(self, kid: bytes):
        """Retira (y por tanto invalida) la clave privada asociada al kid."""
        now = self.clock()
        with self._lock:
            item = self._keys.pop(kid, None)
            self._purge(now)
        if item is None or item[1] <= now:
            raise E2EError("Clave de sesión desconocida o caducada; vuelve a intentarlo")
        return item[0]


class Channel:
    """Resultado de abrir una petición: permite cifrar la respuesta."""

    __slots__ = ("_key", "_path")

    def __init__(self, response_key: bytes, path: str):
        self._key = response_key
        self._path = path

    def seal(self, obj) -> dict:
        if self._key is None:
            raise E2EError("Canal cerrado")
        plaintext = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        iv = secrets.token_bytes(12)
        ct = AESGCM(self._key).encrypt(iv, plaintext, aad("res", self._path))
        del plaintext
        return {"v": VERSION, "iv": b64e(iv), "ct": b64e(ct)}

    def close(self):
        self._key = None


def open_request(store: KeyStore, envelope, path: str):
    """Descifra un sobre {v, kid, epk, iv, ct}. Devuelve (datos, Channel).

    La clave privada del servidor se retira del almacén ANTES de usarla, de
    modo que, pase lo que pase, no puede volver a utilizarse.
    """
    if not isinstance(envelope, dict) or envelope.get("v") != VERSION:
        raise E2EError("Las peticiones deben ir cifradas (protocolo sgen1)")
    kid = b64d(envelope.get("kid"), "kid", 16)
    private_key = store.take(kid)
    try:
        epk_raw = b64d(envelope.get("epk"), "epk", 65)
        iv = b64d(envelope.get("iv"), "iv", 12)
        ct = b64d(envelope.get("ct"), "ct")
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, epk_raw)
        except ValueError:
            raise E2EError("Clave pública del cliente no válida") from None
        req_key, res_key = derive_keys(private_key, peer, kid)
        try:
            plaintext = AESGCM(req_key).decrypt(iv, ct, aad("req", path))
        except InvalidTag:
            raise E2EError("No se ha podido descifrar la petición") from None
        finally:
            del req_key
        try:
            data = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise E2EError("Contenido cifrado no válido") from None
        finally:
            del plaintext
        return data, Channel(res_key, path)
    finally:
        # Destrucción de la clave privada efímera del servidor.
        del private_key
