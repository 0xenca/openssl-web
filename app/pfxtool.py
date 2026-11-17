"""Construcción de ficheros PFX / PKCS#12 en memoria.

Principios (los mismos que ``csrtool``):
  * Nada se escribe en disco: todo el trabajo se hace dentro del proceso con
    el paquete de Debian ``python3-cryptography`` (que usa OpenSSL). No hay
    ficheros temporales, ni subprocesos, ni contraseñas en argumentos.
  * Nada se registra: este módulo no usa ``logging`` ni imprime nada.
  * Toda entrada se valida (tamaños, formatos, número de certificados) y los
    errores se devuelven con mensajes genéricos que no repiten el contenido.

Entradas aceptadas para la clave y los certificados:
  * PEM (``-----BEGIN ...-----``): PKCS#8, PKCS#8 cifrada, RSA/EC tradicional
    (también cifrada), CERTIFICATE y PKCS7 (cadenas .p7b).
  * DER en Base64 (lo que envía el navegador al subir un fichero binario
    .der/.cer/.p7b/.key): se detecta automáticamente.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID

from csrtool import CsrError, suggested_name

MAX_KEY_INPUT = 64 * 1024
MAX_CERT_INPUT = 96 * 1024
MAX_CERTS = 16
MIN_PASSWORD = 4
MAX_PASSWORD = 1023
MAX_FRIENDLY_NAME = 64
EXPIRY_WARNING_DAYS = 30

# Perfiles de cifrado del PFX.
#   modern: PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC) y MAC SHA-256.
#   legacy: pbeWithSHA1And3-KeyTripleDES-CBC y MAC SHA-1, para sistemas
#           antiguos (Windows Server 2016 o anterior, Java 8, macOS antiguos…).
PROFILES = {
    "modern": {
        "label": "AES-256-CBC + PBKDF2-SHA256, MAC SHA-256",
        "algorithm": pkcs12.PBES.PBESv2SHA256AndAES256CBC,
        "mac": hashes.SHA256,
        "rounds": 100_000,
    },
    "legacy": {
        "label": "3DES (pbeWithSHA1And3-KeyTripleDES-CBC), MAC SHA-1",
        "algorithm": pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC,
        "mac": hashes.SHA1,
        "rounds": 2048,
    },
}

EXTENSIONS = ("pfx", "p12")

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]{1,40})-----(.*?)-----END \1-----", re.S)
_B64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")
_CERT_LABELS = ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE")
_PKCS7_LABELS = ("PKCS7", "CERTIFICATE CHAIN")  # algunas CA usan etiquetas no estándar
_KEY_LABELS = ("PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY")


# --------------------------------------------------------------------------
# Lectura de entradas
# --------------------------------------------------------------------------


def _text(value, label, max_len):
    if not isinstance(value, str) or not value.strip():
        raise CsrError(f"Falta {label}")
    if len(value) > max_len:
        raise CsrError(f"{label[0].upper() + label[1:]}: demasiado grande")
    return value.strip()


def _b64der(text, label):
    """Base64 sin cabeceras PEM (fichero DER subido desde el navegador)."""
    if not _B64_RE.match(text):
        raise CsrError(f"{label[0].upper() + label[1:]}: formato no reconocido (se espera PEM o DER)")
    try:
        return base64.b64decode(re.sub(r"\s+", "", text), validate=True)
    except (binascii.Error, ValueError):
        raise CsrError(f"{label[0].upper() + label[1:]}: Base64 no válido") from None


def _check_password(value, label, required):
    if value is None or value == "":
        if required:
            raise CsrError(f"{label}: obligatoria")
        return None
    if not isinstance(value, str) or len(value) > MAX_PASSWORD:
        raise CsrError(f"{label}: no válida")
    if required and len(value) < MIN_PASSWORD:
        raise CsrError(f"{label}: debe tener entre {MIN_PASSWORD} y {MAX_PASSWORD} caracteres")
    if _CTRL_RE.search(value):
        raise CsrError(f"{label}: contiene caracteres no permitidos")
    return value.encode("utf-8")


def _load_key_obj(loader, data, password):
    """Carga una clave probando primero sin contraseña."""
    try:
        return loader(data, password=None), False
    except TypeError:
        # La clave está cifrada: hace falta su contraseña.
        if password is None:
            raise CsrError("La clave privada está cifrada: indica su contraseña") from None
        try:
            return loader(data, password=password), True
        except (ValueError, TypeError):
            raise CsrError("La contraseña de la clave privada no es correcta") from None


def load_private_key(text, password=None):
    """Devuelve (clave, estaba_cifrada). Acepta PEM o DER en Base64."""
    text = _text(text, "la clave privada", MAX_KEY_INPUT)
    if "CERTIFICATE" in text and "PRIVATE KEY" not in text:
        raise CsrError("En el campo de la clave has puesto un certificado")
    try:
        if "-----BEGIN" in text:
            blocks = [m for m in _PEM_RE.finditer(text) if m.group(1) in _KEY_LABELS]
            if not blocks:
                raise CsrError("No se encuentra un bloque '-----BEGIN PRIVATE KEY-----'")
            if len(blocks) > 1:
                raise CsrError("Hay más de una clave privada: indica solo una")
            block = blocks[0]
            try:
                return _load_key_obj(serialization.load_pem_private_key, block.group(0).encode("ascii"), password)
            except ValueError:
                if ":" in block.group(2):  # PEM tradicional cifrado (Proc-Type/DEK-Info)
                    raise
                # Etiqueta que no coincide con el contenido (p. ej. DER envuelto a mano).
                return _load_key_obj(serialization.load_der_private_key, _b64der(block.group(2), "la clave privada"),
                                     password)
        return _load_key_obj(serialization.load_der_private_key, _b64der(text, "la clave privada"), password)
    except CsrError:
        raise
    except (ValueError, UnsupportedAlgorithm, UnicodeError):
        raise CsrError("La clave privada no es válida o su formato no está soportado") from None


def _load_der_certs(der):
    try:
        return [x509.load_der_x509_certificate(der)]
    except ValueError:
        pass
    try:
        return list(pkcs7.load_der_pkcs7_certificates(der))
    except (ValueError, UnsupportedAlgorithm):
        raise CsrError("Un certificado no es válido (se espera X.509 o PKCS#7 en PEM o DER)") from None


def load_certificates(text, label):
    """Lista de certificados de un texto PEM (varios bloques, PKCS7) o DER."""
    text = _text(text, label, MAX_CERT_INPUT)
    if "PRIVATE KEY" in text:
        raise CsrError(f"En {label} hay una clave privada: ponla solo en el campo de la clave")
    if "CERTIFICATE REQUEST" in text:
        raise CsrError(f"En {label} hay un CSR: aquí va el certificado que te ha devuelto la CA")
    certs = []
    try:
        if "-----BEGIN" in text:
            found = False
            for m in _PEM_RE.finditer(text):
                lbl = m.group(1)
                if lbl in _CERT_LABELS:
                    certs.extend(_load_der_certs(_b64der(m.group(2), label)))
                    found = True
                elif lbl in _PKCS7_LABELS:
                    certs.extend(pkcs7.load_der_pkcs7_certificates(_b64der(m.group(2), label)))
                    found = True
            if not found:
                raise CsrError(f"No se encuentra ningún '-----BEGIN CERTIFICATE-----' en {label}")
        else:
            certs = _load_der_certs(_b64der(text, label))
    except CsrError:
        raise
    except (ValueError, UnsupportedAlgorithm):
        raise CsrError(f"Un certificado de {label} no es válido o está dañado") from None
    if len(certs) > MAX_CERTS:
        raise CsrError(f"Máximo {MAX_CERTS} certificados")
    return certs


# --------------------------------------------------------------------------
# Análisis
# --------------------------------------------------------------------------


def _pub_der(public_key):
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def describe_key(key):
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return f"RSA {key.key_size} bits"
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        names = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
        return f"ECDSA {names.get(key.curve.name, key.curve.name)}"
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "Ed25519"
    if isinstance(key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return "Ed448"
    if isinstance(key, (dsa.DSAPrivateKey, dsa.DSAPublicKey)):
        return f"DSA {key.key_size} bits"
    return "Desconocido"


def _utc(cert, attr):
    value = getattr(cert, attr + "_utc", None)
    if value is None:  # cryptography < 42
        value = getattr(cert, attr).replace(tzinfo=datetime.timezone.utc)
    return value


def _cn(name):
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else ""


def _short_name(name):
    return _cn(name) or name.rfc4514_string() or "(sin nombre)"


def _sans(cert):
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return []
    out = [f"DNS:{v}" for v in ext.get_values_for_type(x509.DNSName)]
    out += [f"IP:{v}" for v in ext.get_values_for_type(x509.IPAddress)]
    out += [f"email:{v}" for v in ext.get_values_for_type(x509.RFC822Name)]
    out += [f"URI:{v}" for v in ext.get_values_for_type(x509.UniformResourceIdentifier)]
    return out


def _is_ca(cert):
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        return False


def _issued_by(child, parent):
    """¿``parent`` firmó ``child``? Comprueba nombre y firma."""
    if child.issuer != parent.subject:
        return False
    verify = getattr(child, "verify_directly_issued_by", None)
    if verify is None:
        return True
    try:
        verify(parent)
        return True
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
        return False


def _self_signed(cert):
    return _issued_by(cert, cert)


def cert_info(cert, now):
    not_before, not_after = _utc(cert, "not_valid_before"), _utc(cert, "not_valid_after")
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "cn": _short_name(cert.subject),
        "issuerCn": _short_name(cert.issuer),
        "serial": format(cert.serial_number, "X"),
        "notBefore": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "notAfter": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expired": not_after < now,
        "notYetValid": not_before > now,
        "daysLeft": (not_after - now).days,
        "selfSigned": _self_signed(cert),
        "ca": _is_ca(cert),
        "key": describe_key(cert.public_key()),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
        "sans": _sans(cert),
    }


def _key_matches(key, cert):
    try:
        return _pub_der(key.public_key()) == _pub_der(cert.public_key())
    except (ValueError, UnsupportedAlgorithm):
        return False


def _sign_check(key):
    """Prueba de posesión: firmar y verificar con la pareja de claves."""
    data = b"encas-sgen pfx check"
    pub = key.public_key()
    if isinstance(key, rsa.RSAPrivateKey):
        pub.verify(key.sign(data, padding.PKCS1v15(), hashes.SHA256()), data, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        pub.verify(key.sign(data, ec.ECDSA(hashes.SHA256())), data, ec.ECDSA(hashes.SHA256()))
    elif isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        pub.verify(key.sign(data), data)


def order_chain(leaf, others):
    """Ordena la cadena desde el emisor de ``leaf`` hacia la raíz.

    Devuelve (cadena_ordenada, descartados). Los duplicados y la propia hoja
    se eliminan; los certificados que no forman parte de la cadena se descartan.
    """
    seen = {leaf.fingerprint(hashes.SHA256())}
    pool = []
    for cert in others:
        fp = cert.fingerprint(hashes.SHA256())
        if fp not in seen:
            seen.add(fp)
            pool.append(cert)
    chain = []
    current = leaf
    while pool and not _self_signed(current):
        parent = next((c for c in pool if _issued_by(current, c)), None)
        if parent is None:
            break
        pool.remove(parent)
        chain.append(parent)
        current = parent
    return chain, pool


# --------------------------------------------------------------------------
# Construcción del PFX
# --------------------------------------------------------------------------


def build_pfx(data):
    """Crea un PFX/PKCS#12 en memoria. Devuelve un dict con el fichero e información."""
    if not isinstance(data, dict):
        raise CsrError("Petición no válida")

    profile_name = data.get("profile", "modern")
    if profile_name not in PROFILES:
        raise CsrError("Perfil de compatibilidad no soportado")
    profile = PROFILES[profile_name]
    ext = data.get("extension", "pfx")
    if ext not in EXTENSIONS:
        raise CsrError("Extensión no soportada")

    pfx_password = _check_password(data.get("password"), "Contraseña del PFX", required=True)
    key_password = _check_password(data.get("keyPassword"), "Contraseña de la clave", required=False)

    friendly = data.get("friendlyName") or ""
    if not isinstance(friendly, str) or len(friendly.strip()) > MAX_FRIENDLY_NAME or _CTRL_RE.search(friendly):
        raise CsrError(f"Nombre descriptivo: máximo {MAX_FRIENDLY_NAME} caracteres, sin caracteres de control")
    friendly = friendly.strip()

    key, was_encrypted = load_private_key(data.get("key"), key_password)
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey,
                            ed448.Ed448PrivateKey, dsa.DSAPrivateKey)):
        raise CsrError("Tipo de clave privada no soportado en PFX")

    certs = load_certificates(data.get("cert"), "el certificado")
    chain_in = data.get("chain") or []
    if isinstance(chain_in, str):
        chain_in = [chain_in]
    if not isinstance(chain_in, list) or len(chain_in) > MAX_CERTS:
        raise CsrError("Cadena de certificados no válida")
    extra = []
    for item in chain_in:
        if isinstance(item, str) and item.strip():
            extra.extend(load_certificates(item, "la cadena"))
    if len(certs) + len(extra) > MAX_CERTS:
        raise CsrError(f"Máximo {MAX_CERTS} certificados en total")

    # La hoja es el certificado cuya clave pública coincide con la clave privada.
    leaf = next((c for c in certs if _key_matches(key, c)), None)
    if leaf is None:
        leaf = next((c for c in extra if _key_matches(key, c)), None)
    if leaf is None:
        raise CsrError("La clave privada no corresponde a ningún certificado aportado. "
                       "Comprueba que el certificado es el emitido para el CSR de esa clave")
    try:
        _sign_check(key)
    except (InvalidSignature, ValueError, UnsupportedAlgorithm):
        raise CsrError("La clave privada está dañada (no supera la prueba de firma)") from None

    include_chain = bool(data.get("includeChain", True))
    others = [c for c in certs + extra if c is not leaf]
    chain, discarded = order_chain(leaf, others)

    now = datetime.datetime.now(datetime.timezone.utc)
    leaf_info = cert_info(leaf, now)
    checks = []

    def add(level, msg):
        checks.append({"level": level, "message": msg})

    add("ok", f"La clave privada ({describe_key(key)}) corresponde al certificado")
    if leaf_info["expired"]:
        add("error", f"El certificado CADUCÓ el {leaf_info['notAfter'][:10]}")
    elif leaf_info["notYetValid"]:
        add("warn", f"El certificado aún no es válido (desde {leaf_info['notBefore'][:10]})")
    elif leaf_info["daysLeft"] < EXPIRY_WARNING_DAYS:
        add("warn", f"El certificado caduca en {leaf_info['daysLeft']} días ({leaf_info['notAfter'][:10]})")
    else:
        add("ok", f"Certificado vigente hasta el {leaf_info['notAfter'][:10]} ({leaf_info['daysLeft']} días)")
    if leaf_info["ca"]:
        add("warn", "El certificado principal es de una CA (CA:TRUE), no de un servidor o usuario")

    if not include_chain:
        add("warn", "Has elegido no incluir la cadena: el PFX solo llevará el certificado y la clave")
        chain_out = []
    else:
        chain_out = chain
        if chain:
            add("ok", f"Cadena incluida: {len(chain)} certificado(s) de CA, ordenados desde el emisor")
            for parent in chain:
                if _utc(parent, "not_valid_after") < now:
                    add("warn", f"El certificado de CA «{_short_name(parent.subject)}» está caducado")
        elif leaf_info["selfSigned"]:
            add("ok", "Certificado autofirmado: no necesita cadena")
        else:
            add("warn", f"No se ha incluido la cadena: falta el intermedio «{leaf_info['issuerCn']}». "
                        "Muchos servidores (IIS, Azure, Exchange…) lo necesitan")
        last = chain[-1] if chain else leaf
        if chain and not _self_signed(last):
            add("ok", f"La cadena termina en «{_short_name(last.issuer)}» (la raíz no es necesaria)")
    for cert in discarded:
        add("warn", f"Descartado «{_short_name(cert.subject)}»: no forma parte de la cadena de este certificado")

    name = friendly or leaf_info["cn"] or "certificado"
    encryption = (serialization.PrivateFormat.PKCS12.encryption_builder()
                  .kdf_rounds(profile["rounds"])
                  .key_cert_algorithm(profile["algorithm"])
                  .hmac_hash(profile["mac"]())
                  .build(pfx_password))
    try:
        blob = pkcs12.serialize_key_and_certificates(
            name.encode("utf-8"), key, leaf, chain_out or None, encryption)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise CsrError("No se ha podido crear el PFX con estos datos") from None
    finally:
        key = encryption = pfx_password = key_password = None

    base = suggested_name(friendly or str(data.get("name") or "") or leaf_info["cn"])
    return {
        "filename": f"{base}.{ext}",
        "pfx": base64.b64encode(blob).decode("ascii"),
        "size": len(blob),
        "friendlyName": name,
        "profile": profile_name,
        "profileLabel": profile["label"],
        "keyWasEncrypted": was_encrypted,
        "leaf": leaf_info,
        "leafPem": leaf.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "chain": [cert_info(c, now) for c in chain_out],
        "chainPem": "".join(c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in chain_out),
        "checks": checks,
    }
