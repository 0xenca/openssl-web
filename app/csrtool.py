"""Generación y análisis de CSR usando el binario ``openssl``.

Principios:
  * Nada se escribe en disco: la clave, la configuración y la contraseña se
    pasan a ``openssl`` mediante stdin / descriptores de fichero (pipes).
  * Nada se registra: este módulo no usa ``logging`` ni imprime nada.
  * Toda entrada del usuario se valida con listas blancas antes de llegar a
    ``openssl`` (no se construye ningún fichero de configuración con datos
    del usuario, así que no hay posibilidad de inyección en la configuración).
"""

from __future__ import annotations

import base64
import io
import ipaddress
import os
import re
import subprocess
import zipfile
from dataclasses import dataclass, field

APP_DIR = os.path.dirname(os.path.abspath(__file__))
REQ_CONFIG = os.path.join(APP_DIR, "openssl-req.cnf")
OPENSSL = os.environ.get("OPENSSLWEB_OPENSSL", "openssl")
OPENSSL_TIMEOUT = 120

# --------------------------------------------------------------------------
# Opciones permitidas (listas blancas)
# --------------------------------------------------------------------------

KEY_TYPES = {
    "rsa2048": ("RSA", ["-pkeyopt", "rsa_keygen_bits:2048"]),
    "rsa3072": ("RSA", ["-pkeyopt", "rsa_keygen_bits:3072"]),
    "rsa4096": ("RSA", ["-pkeyopt", "rsa_keygen_bits:4096"]),
    "ecp256": ("EC", ["-pkeyopt", "ec_paramgen_curve:P-256", "-pkeyopt", "ec_param_enc:named_curve"]),
    "ecp384": ("EC", ["-pkeyopt", "ec_paramgen_curve:P-384", "-pkeyopt", "ec_param_enc:named_curve"]),
    "ecp521": ("EC", ["-pkeyopt", "ec_paramgen_curve:P-521", "-pkeyopt", "ec_param_enc:named_curve"]),
}

DIGESTS = {"sha256": "-sha256", "sha384": "-sha384", "sha512": "-sha512"}

CIPHERS = {
    "none": None,
    "aes128": "-aes-128-cbc",
    "aes192": "-aes-192-cbc",
    "aes256": "-aes-256-cbc",
}

KEY_FORMATS = ("pkcs8", "traditional")

KEY_USAGES = {
    "digitalSignature": "digitalSignature",
    "nonRepudiation": "nonRepudiation",
    "keyEncipherment": "keyEncipherment",
    "dataEncipherment": "dataEncipherment",
    "keyAgreement": "keyAgreement",
}

EXT_KEY_USAGES = {
    "serverAuth": "serverAuth",
    "clientAuth": "clientAuth",
    "codeSigning": "codeSigning",
    "emailProtection": "emailProtection",
    "timeStamping": "timeStamping",
}

# Campos del sujeto: clave JSON -> (atributo OpenSSL, longitud máxima)
SUBJECT_FIELDS = (
    ("C", "C", 2),
    ("ST", "ST", 128),
    ("L", "L", 128),
    ("O", "O", 64),
    ("OU", "OU", 64),
    ("CN", "CN", 64),
    ("emailAddress", "emailAddress", 128),
)

MAX_SANS = 100
MAX_CSR_INPUT = 64 * 1024

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_DNS_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_DNS_RE = re.compile(rf"^(\*\.)?({_DNS_LABEL}\.)*{_DNS_LABEL}\.?$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_URI_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+;=%]+$")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")


class CsrError(ValueError):
    """Error de validación o de generación mostrado al usuario."""


# --------------------------------------------------------------------------
# Validación
# --------------------------------------------------------------------------


def _clean_text(value, label, max_len):
    if value is None:
        return ""
    if not isinstance(value, str):
        raise CsrError(f"{label}: valor no válido")
    value = value.strip()
    if _CTRL_RE.search(value):
        raise CsrError(f"{label}: contiene caracteres de control")
    if len(value) > max_len:
        raise CsrError(f"{label}: máximo {max_len} caracteres")
    return value


def validate_dns(name):
    name = name.strip().lower()
    if not name or len(name) > 253 or not _DNS_RE.match(name):
        raise CsrError(f"Nombre DNS no válido: {name!r}")
    return name.rstrip(".")


def validate_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise CsrError(f"Dirección IP no válida: {value!r}") from None


def validate_email(value):
    value = value.strip()
    if len(value) > 254 or not _EMAIL_RE.match(value):
        raise CsrError(f"Correo electrónico no válido: {value!r}")
    return value


def validate_uri(value):
    value = value.strip()
    # La coma no se admite porque separa valores en -addext.
    if len(value) > 1024 or not _URI_RE.match(value) or "," in value:
        raise CsrError(f"URI no válida: {value!r}")
    return value


SAN_VALIDATORS = {
    "DNS": validate_dns,
    "IP": validate_ip,
    "email": validate_email,
    "URI": validate_uri,
}


def _escape_subj(value):
    """Escapa un valor para el argumento ``-subj`` de ``openssl req``."""
    return re.sub(r"([\\/+=,])", r"\\\1", value)


@dataclass
class CsrRequest:
    key_type: str = "rsa2048"
    digest: str = "sha256"
    cipher: str = "none"
    passphrase: str = ""
    key_format: str = "pkcs8"
    subject: dict = field(default_factory=dict)
    sans: list = field(default_factory=list)  # [(tipo, valor)]
    key_usage: list = field(default_factory=list)
    ext_key_usage: list = field(default_factory=list)
    key_usage_critical: bool = True
    must_staple: bool = False


def parse_request(data):
    """Convierte y valida el JSON recibido del navegador."""
    if not isinstance(data, dict):
        raise CsrError("Petición no válida")

    req = CsrRequest()

    req.key_type = data.get("keyType", "rsa2048")
    if req.key_type not in KEY_TYPES:
        raise CsrError("Tipo de clave no soportado")

    req.digest = data.get("digest", "sha256")
    if req.digest not in DIGESTS:
        raise CsrError("Algoritmo SHA no soportado")

    req.cipher = data.get("cipher", "none")
    if req.cipher not in CIPHERS:
        raise CsrError("Cifrado AES no soportado")

    req.key_format = data.get("keyFormat", "pkcs8")
    if req.key_format not in KEY_FORMATS:
        raise CsrError("Formato de clave no soportado")

    if req.cipher != "none":
        pw = data.get("passphrase", "")
        if not isinstance(pw, str) or len(pw) < 4 or len(pw) > 1023:
            raise CsrError("La contraseña debe tener entre 4 y 1023 caracteres")
        if _CTRL_RE.search(pw):
            raise CsrError("La contraseña contiene caracteres no permitidos")
        req.passphrase = pw

    subject_in = data.get("subject") or {}
    if not isinstance(subject_in, dict):
        raise CsrError("Sujeto no válido")
    for key, _attr, max_len in SUBJECT_FIELDS:
        value = _clean_text(subject_in.get(key), key, max_len)
        if value:
            req.subject[key] = value
    if "C" in req.subject:
        req.subject["C"] = req.subject["C"].upper()
        if not _COUNTRY_RE.match(req.subject["C"]):
            raise CsrError("País (C): debe ser un código ISO de 2 letras, p. ej. ES")
    if "emailAddress" in req.subject:
        req.subject["emailAddress"] = validate_email(req.subject["emailAddress"])
    if not req.subject.get("CN"):
        raise CsrError("El Common Name (CN) es obligatorio")

    sans_in = data.get("sans") or []
    if not isinstance(sans_in, list) or len(sans_in) > MAX_SANS:
        raise CsrError(f"Máximo {MAX_SANS} Subject Alternative Names")
    seen = set()
    for item in sans_in:
        if not isinstance(item, dict):
            raise CsrError("SAN no válido")
        san_type = item.get("type")
        raw = item.get("value")
        if san_type not in SAN_VALIDATORS or not isinstance(raw, str):
            raise CsrError("Tipo de SAN no soportado")
        if not raw.strip():
            continue
        value = SAN_VALIDATORS[san_type](raw)
        if (san_type, value) not in seen:
            seen.add((san_type, value))
            req.sans.append((san_type, value))

    if data.get("cnInSan", True):
        cn = req.subject["CN"]
        entry = None
        try:
            entry = ("IP", validate_ip(cn))
        except CsrError:
            try:
                entry = ("DNS", validate_dns(cn))
            except CsrError:
                entry = None
        if entry:
            # El CN siempre como primer SAN (sin duplicarlo).
            if entry in seen:
                req.sans.remove(entry)
            req.sans.insert(0, entry)
            seen.add(entry)

    ku = data.get("keyUsage") or []
    eku = data.get("extKeyUsage") or []
    if not isinstance(ku, list) or not isinstance(eku, list):
        raise CsrError("Key Usage no válido")
    for item in ku:
        if item not in KEY_USAGES:
            raise CsrError("Key Usage no soportado")
        if item not in req.key_usage:
            req.key_usage.append(item)
    for item in eku:
        if item not in EXT_KEY_USAGES:
            raise CsrError("Extended Key Usage no soportado")
        if item not in req.ext_key_usage:
            req.ext_key_usage.append(item)
    if req.key_type.startswith("ec") and "keyEncipherment" in req.key_usage:
        # keyEncipherment no tiene sentido con claves EC
        req.key_usage.remove("keyEncipherment")

    req.key_usage_critical = bool(data.get("keyUsageCritical", True))
    req.must_staple = bool(data.get("mustStaple", False))
    return req


# --------------------------------------------------------------------------
# Ejecución de openssl sin tocar disco
# --------------------------------------------------------------------------


def _run(args, stdin=b"", secret=None):
    """Ejecuta openssl. Si ``secret`` se indica, se entrega por un pipe y el
    marcador ``{fd}`` de los argumentos se sustituye por su descriptor."""
    rfd = wfd = None
    pass_fds = ()
    try:
        if secret is not None:
            rfd, wfd = os.pipe()
            os.write(wfd, secret.encode("utf-8") + b"\n")
            os.close(wfd)
            wfd = None
            args = [a.replace("{fd}", str(rfd)) for a in args]
            pass_fds = (rfd,)
        proc = subprocess.run(
            [OPENSSL, *args],
            input=stdin,
            capture_output=True,
            pass_fds=pass_fds,
            timeout=OPENSSL_TIMEOUT,
            check=False,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C",
                 "OPENSSL_CONF": REQ_CONFIG, "RANDFILE": "/dev/null"},
        )
    except FileNotFoundError:
        raise CsrError("No se encuentra el binario openssl en el servidor") from None
    except subprocess.TimeoutExpired:
        raise CsrError("openssl ha tardado demasiado") from None
    finally:
        for fd in (rfd, wfd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
    return proc


def generate(req: CsrRequest):
    """Genera clave privada + CSR. Devuelve un dict con los PEM."""
    algorithm, opts = KEY_TYPES[req.key_type]

    proc = _run(["genpkey", "-algorithm", algorithm, *opts, "-quiet"])
    if proc.returncode != 0 or b"PRIVATE KEY" not in proc.stdout:
        raise CsrError("Error generando la clave privada")
    plain_key = proc.stdout

    subj = "".join(
        f"/{attr}={_escape_subj(req.subject[key])}"
        for key, attr, _ in SUBJECT_FIELDS
        if key in req.subject
    )
    args = ["req", "-new", "-key", "/dev/stdin", "-config", REQ_CONFIG,
            "-utf8", DIGESTS[req.digest], "-subj", subj]
    if req.sans:
        args += ["-addext", "subjectAltName=" + ",".join(f"{t}:{v}" for t, v in req.sans)]
    if req.key_usage:
        prefix = "critical," if req.key_usage_critical else ""
        args += ["-addext", "keyUsage=" + prefix + ",".join(req.key_usage)]
    if req.ext_key_usage:
        args += ["-addext", "extendedKeyUsage=" + ",".join(req.ext_key_usage)]
    if req.must_staple:
        args += ["-addext", "tlsfeature=status_request"]

    proc = _run(args, stdin=plain_key)
    if proc.returncode != 0 or b"CERTIFICATE REQUEST" not in proc.stdout:
        err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise CsrError("Error generando el CSR" + (f": {err[-1]}" if err else ""))
    csr = proc.stdout

    key = plain_key
    if req.cipher != "none" or req.key_format == "traditional":
        args = ["pkey", "-in", "/dev/stdin"]
        if req.key_format == "traditional":
            args.append("-traditional")
        secret = None
        if req.cipher != "none":
            args += [CIPHERS[req.cipher], "-passout", "fd:{fd}"]
            secret = req.passphrase
        proc = _run(args, stdin=plain_key, secret=secret)
        if proc.returncode != 0 or b"PRIVATE KEY" not in proc.stdout:
            raise CsrError("Error cifrando la clave privada")
        key = proc.stdout

    return {
        "csr": csr.decode("ascii"),
        "key": key.decode("ascii"),
        "name": suggested_name(req.subject["CN"]),
    }


def suggested_name(cn):
    name = cn.strip().lower().replace("*", "wildcard")
    name = re.sub(r"[^a-z0-9._-]+", "_", name).strip("._-")
    return (name or "certificado")[:80]


# --------------------------------------------------------------------------
# ZIP en memoria
# --------------------------------------------------------------------------

_PEM_CSR_RE = re.compile(r"-----BEGIN (NEW )?CERTIFICATE REQUEST-----[A-Za-z0-9+/=\s]+-----END (NEW )?CERTIFICATE REQUEST-----\s*$")
_PEM_KEY_RE = re.compile(r"-----BEGIN ((RSA|EC|ENCRYPTED) )?PRIVATE KEY-----[A-Za-z0-9+/=:,\-\s]+-----END ((RSA|EC|ENCRYPTED) )?PRIVATE KEY-----\s*$")


def file_name(base, kind, ext_mode):
    """Nombre de fichero: ``base.csr``/``base.key`` o ``base-csr.txt``/``base-key.txt``."""
    return f"{base}.{kind}" if ext_mode == "pem" else f"{base}-{kind}.txt"


def build_zip(data):
    """Crea un ZIP en memoria con la clave y/o el CSR recibidos.

    Nada se escribe en disco: se usa un ``BytesIO``."""
    if not isinstance(data, dict):
        raise CsrError("Petición no válida")
    name = suggested_name(str(data.get("name") or "certificado"))
    ext_mode = data.get("format", "pem")
    if ext_mode not in ("pem", "txt"):
        raise CsrError("Formato no soportado")

    files = []
    csr = data.get("csr")
    key = data.get("key")
    if csr:
        if not isinstance(csr, str) or len(csr) > MAX_CSR_INPUT or not _PEM_CSR_RE.match(csr.strip() + "\n"):
            raise CsrError("El CSR no tiene formato PEM válido")
        files.append((file_name(name, "csr", ext_mode), csr))
    if key:
        if not isinstance(key, str) or len(key) > MAX_CSR_INPUT or not _PEM_KEY_RE.match(key.strip() + "\n"):
            raise CsrError("La clave no tiene formato PEM válido")
        files.append((file_name(name, "key", ext_mode), key))
    if not files:
        raise CsrError("No hay nada que comprimir")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files:
            info = zipfile.ZipInfo(filename, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            zf.writestr(info, content.strip() + "\n")
    return f"{name}.zip", buf.getvalue()


# --------------------------------------------------------------------------
# Decodificación de CSR (parser DER propio + verificación con openssl)
# --------------------------------------------------------------------------

OID_NAMES = {
    "2.5.4.3": ("CN", "Common Name"),
    "2.5.4.4": ("SN", "Surname"),
    "2.5.4.5": ("serialNumber", "Serial Number"),
    "2.5.4.6": ("C", "País"),
    "2.5.4.7": ("L", "Localidad"),
    "2.5.4.8": ("ST", "Provincia / Estado"),
    "2.5.4.9": ("street", "Dirección"),
    "2.5.4.10": ("O", "Organización"),
    "2.5.4.11": ("OU", "Unidad organizativa"),
    "2.5.4.12": ("title", "Cargo"),
    "2.5.4.15": ("businessCategory", "Categoría de negocio"),
    "2.5.4.17": ("postalCode", "Código postal"),
    "2.5.4.42": ("GN", "Nombre"),
    "2.5.4.97": ("organizationIdentifier", "Identificador de organización"),
    "1.2.840.113549.1.9.1": ("emailAddress", "Correo electrónico"),
    "0.9.2342.19200300.100.1.25": ("DC", "Domain Component"),
    "0.9.2342.19200300.100.1.1": ("UID", "User ID"),
    "1.3.6.1.4.1.311.60.2.1.1": ("jurisdictionL", "Jurisdicción (localidad)"),
    "1.3.6.1.4.1.311.60.2.1.2": ("jurisdictionST", "Jurisdicción (provincia)"),
    "1.3.6.1.4.1.311.60.2.1.3": ("jurisdictionC", "Jurisdicción (país)"),
}

SIG_ALGS = {
    "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", "SHA-1", "RSA"),
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", "MD5", "RSA"),
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", "SHA-256", "RSA"),
    "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", "SHA-384", "RSA"),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", "SHA-512", "RSA"),
    "1.2.840.113549.1.1.14": ("sha224WithRSAEncryption", "SHA-224", "RSA"),
    "1.2.840.113549.1.1.10": ("RSASSA-PSS", "PSS", "RSA"),
    "1.2.840.10045.4.1": ("ecdsa-with-SHA1", "SHA-1", "ECDSA"),
    "1.2.840.10045.4.3.1": ("ecdsa-with-SHA224", "SHA-224", "ECDSA"),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", "SHA-256", "ECDSA"),
    "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", "SHA-384", "ECDSA"),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", "SHA-512", "ECDSA"),
    "1.3.101.112": ("Ed25519", "—", "Ed25519"),
    "1.3.101.113": ("Ed448", "—", "Ed448"),
}

PK_ALGS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.2.840.113549.1.1.10": "RSA-PSS",
}

CURVES = {
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
    "1.3.132.0.10": ("secp256k1", 256),
}

EKU_NAMES = {
    "1.3.6.1.5.5.7.3.1": "serverAuth (Autenticación de servidor TLS)",
    "1.3.6.1.5.5.7.3.2": "clientAuth (Autenticación de cliente TLS)",
    "1.3.6.1.5.5.7.3.3": "codeSigning (Firma de código)",
    "1.3.6.1.5.5.7.3.4": "emailProtection (Protección de correo)",
    "1.3.6.1.5.5.7.3.8": "timeStamping (Sellado de tiempo)",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
    "2.5.29.37.0": "anyExtendedKeyUsage",
}

KU_BITS = [
    "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
    "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly",
]

EXT_NAMES = {
    "2.5.29.17": "Subject Alternative Name",
    "2.5.29.15": "Key Usage",
    "2.5.29.37": "Extended Key Usage",
    "2.5.29.19": "Basic Constraints",
    "2.5.29.14": "Subject Key Identifier",
    "2.5.29.32": "Certificate Policies",
    "1.3.6.1.5.5.7.1.24": "TLS Feature (OCSP Must-Staple)",
    "1.3.6.1.4.1.311.20.2": "Microsoft Certificate Template Name",
    "1.3.6.1.4.1.311.21.7": "Microsoft Certificate Template",
}


class _Der:
    """Lector DER mínimo (solo lo necesario para PKCS#10)."""

    def __init__(self, data, pos=0, end=None):
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else end

    def more(self):
        return self.pos < self.end

    def read(self):
        if self.pos + 2 > self.end:
            raise CsrError("Estructura ASN.1 truncada")
        start = self.pos
        tag = self.data[self.pos]
        self.pos += 1
        if tag & 0x1F == 0x1F:
            raise CsrError("Etiqueta ASN.1 no soportada")
        length = self.data[self.pos]
        self.pos += 1
        if length & 0x80:
            n = length & 0x7F
            if n == 0 or n > 4 or self.pos + n > self.end:
                raise CsrError("Longitud ASN.1 no válida")
            length = int.from_bytes(self.data[self.pos:self.pos + n], "big")
            self.pos += n
        if self.pos + length > self.end:
            raise CsrError("Estructura ASN.1 truncada")
        value_start = self.pos
        self.pos += length
        return tag, value_start, self.pos, start

    def value(self, item):
        return self.data[item[1]:item[2]]

    def sub(self, item):
        return _Der(self.data, item[1], item[2])


def _oid(raw):
    if not raw:
        raise CsrError("OID vacío")
    first = raw[0]
    parts = [str(min(first // 40, 2)), str(first - 40 * min(first // 40, 2))]
    acc = 0
    for b in raw[1:]:
        acc = (acc << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(acc))
            acc = 0
    return ".".join(parts)


def _string(tag, raw):
    if tag == 0x1E:  # BMPString
        return raw.decode("utf-16-be", "replace")
    if tag == 0x1C:  # UniversalString
        return raw.decode("utf-32-be", "replace")
    if tag in (0x0C, 0x13, 0x16, 0x14, 0x1A):
        return raw.decode("utf-8", "replace")
    return raw.hex(":")


def _parse_name(der):
    out = []
    while der.more():
        rdn = der.read()
        if rdn[0] != 0x31:
            raise CsrError("Nombre distinguido no válido")
        rset = der.sub(rdn)
        while rset.more():
            atv = rset.read()
            a = rset.sub(atv)
            oid = _oid(a.value(a.read()))
            vt = a.read()
            short, label = OID_NAMES.get(oid, (oid, oid))
            out.append({"oid": oid, "short": short, "label": label, "value": _string(vt[0], a.value(vt))})
    return out


def _parse_general_names(der):
    out = []
    while der.more():
        item = der.read()
        tag = item[0]
        raw = der.value(item)
        ctx = tag & 0x1F
        if ctx == 2:
            out.append({"type": "DNS", "value": raw.decode("ascii", "replace")})
        elif ctx == 1:
            out.append({"type": "email", "value": raw.decode("ascii", "replace")})
        elif ctx == 6:
            out.append({"type": "URI", "value": raw.decode("ascii", "replace")})
        elif ctx == 7:
            try:
                out.append({"type": "IP", "value": str(ipaddress.ip_address(raw))})
            except ValueError:
                out.append({"type": "IP", "value": raw.hex(":")})
        elif ctx == 4:
            out.append({"type": "DirName", "value": ", ".join(
                f"{n['short']}={n['value']}" for n in _parse_name(_Der(raw, 0)))})
        elif ctx == 8:
            out.append({"type": "RID", "value": _oid(raw)})
        else:
            out.append({"type": "otherName", "value": raw.hex(":")[:120]})
    return out


def _parse_extension(oid, raw):
    der = _Der(raw)
    if oid == "2.5.29.17":
        names = _parse_general_names(der.sub(der.read()))
        return [f"{g['type']}:{g['value']}" for g in names], names
    if oid == "2.5.29.15":
        bs = der.value(der.read())
        bits = bs[1:]
        names = []
        for i, name in enumerate(KU_BITS):
            byte, bit = divmod(i, 8)
            if byte < len(bits) and bits[byte] & (0x80 >> bit):
                names.append(name)
        return names, None
    if oid == "2.5.29.37":
        seq = der.read()
        s = der.sub(seq)
        names = []
        while s.more():
            o = _oid(s.value(s.read()))
            names.append(EKU_NAMES.get(o, o))
        return names, None
    if oid == "2.5.29.19":
        seq = der.read()
        s = der.sub(seq)
        ca = False
        path = None
        while s.more():
            item = s.read()
            if item[0] == 0x01:
                ca = s.value(item) != b"\x00"
            elif item[0] == 0x02:
                path = int.from_bytes(s.value(item), "big")
        text = f"CA:{'TRUE' if ca else 'FALSE'}"
        if path is not None:
            text += f", pathlen:{path}"
        return [text], None
    if oid == "1.3.6.1.5.5.7.1.24":
        seq = der.read()
        s = der.sub(seq)
        feats = []
        while s.more():
            v = int.from_bytes(s.value(s.read()), "big")
            feats.append("status_request (OCSP Must-Staple)" if v == 5 else str(v))
        return feats, None
    if oid == "2.5.29.14":
        return [der.value(der.read()).hex(":").upper()], None
    if oid == "1.3.6.1.4.1.311.20.2":
        item = der.read()
        return [_string(item[0], der.value(item))], None
    return [raw.hex(":")[:200]], None


def _parse_spki(der):
    alg_item = der.read()
    alg = der.sub(alg_item)
    oid = _oid(alg.value(alg.read()))
    params = alg.read() if alg.more() else None
    bitstr = der.value(der.read())[1:]
    info = {"algorithm": PK_ALGS.get(oid, oid), "bits": None, "detail": ""}
    if oid in ("1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10"):
        k = _Der(bitstr)
        seq = k.read()
        s = k.sub(seq)
        modulus = s.value(s.read()).lstrip(b"\x00")
        exponent = int.from_bytes(s.value(s.read()), "big")
        info["bits"] = int.from_bytes(modulus, "big").bit_length()
        info["detail"] = f"Exponente: {exponent}"
        info["modulus"] = modulus.hex().upper()
    elif oid == "1.2.840.10045.2.1" and params is not None and params[0] == 0x06:
        curve_oid = _oid(alg.value(params))
        name, bits = CURVES.get(curve_oid, (curve_oid, None))
        info["bits"] = bits
        info["detail"] = f"Curva: {name}"
        info["curve"] = name
    elif oid == "1.3.101.112":
        info["bits"] = 256
    elif oid == "1.3.101.113":
        info["bits"] = 456
    return info


def _pem_to_der(text):
    if not isinstance(text, str) or len(text) > MAX_CSR_INPUT:
        raise CsrError("CSR demasiado grande o no válido")
    m = re.search(
        r"-----BEGIN (NEW )?CERTIFICATE REQUEST-----(.*?)-----END (NEW )?CERTIFICATE REQUEST-----",
        text, re.S)
    if not m:
        raise CsrError("No se ha encontrado un bloque '-----BEGIN CERTIFICATE REQUEST-----'")
    body = re.sub(r"\s+", "", m.group(2))
    try:
        der = base64.b64decode(body, validate=True)
    except ValueError:
        raise CsrError("El contenido Base64 del CSR no es válido") from None
    pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + "\n".join(
        body[i:i + 64] for i in range(0, len(body), 64)) + "\n-----END CERTIFICATE REQUEST-----\n"
    return der, pem


def decode(text):
    """Analiza un CSR en PEM. Devuelve un dict con todos los valores."""
    der, pem = _pem_to_der(text)
    try:
        info = _decode_der(der)
    except CsrError:
        raise
    except (IndexError, ValueError, UnicodeError) as exc:
        raise CsrError("El CSR está dañado o no es PKCS#10") from exc

    # Verificación de la firma y volcado textual con openssl (autoritativo).
    proc = _run(["req", "-in", "/dev/stdin", "-noout", "-verify"], stdin=pem.encode("ascii"))
    out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    info["signatureValid"] = proc.returncode == 0 and "verify OK" in out and "fail" not in out.lower()
    proc = _run(["req", "-in", "/dev/stdin", "-noout", "-text", "-nameopt", "multiline,utf8,-esc_msb"],
                stdin=pem.encode("ascii"))
    info["opensslText"] = proc.stdout.decode("utf-8", "replace") if proc.returncode == 0 else ""
    info["pem"] = pem
    info["checks"] = _checks(info)
    return info


def _decode_der(der_bytes):
    top = _Der(der_bytes)
    outer = top.read()
    if outer[0] != 0x30 or top.more():
        raise CsrError("El CSR no es una estructura PKCS#10 válida")
    o = top.sub(outer)
    cri = o.read()
    sig_alg = o.sub(o.read())
    sig_oid = _oid(sig_alg.value(sig_alg.read()))
    sig_bits = o.value(o.read())

    c = o.sub(cri)
    version = int.from_bytes(c.value(c.read()), "big")
    subject = _parse_name(c.sub(c.read()))
    public_key = _parse_spki(c.sub(c.read()))

    extensions = []
    attributes = []
    san_list = []
    if c.more():
        attrs = c.read()
        a = c.sub(attrs)
        while a.more():
            attr = a.sub(a.read())
            aoid = _oid(attr.value(attr.read()))
            vals = attr.sub(attr.read())
            if aoid == "1.2.840.113549.1.9.14":  # extensionRequest
                exts_item = vals.read()
                exts = vals.sub(exts_item)
                while exts.more():
                    e = exts.sub(exts.read())
                    eoid = _oid(e.value(e.read()))
                    critical = False
                    item = e.read()
                    if item[0] == 0x01:
                        critical = e.value(item) != b"\x00"
                        item = e.read()
                    values, extra = _parse_extension(eoid, e.value(item))
                    if eoid == "2.5.29.17":
                        san_list = extra
                    extensions.append({
                        "oid": eoid,
                        "name": EXT_NAMES.get(eoid, eoid),
                        "critical": critical,
                        "values": values,
                    })
            elif aoid == "1.2.840.113549.1.9.7":
                attributes.append({"name": "Challenge Password", "value": "(presente, oculto)"})
            elif aoid == "1.2.840.113549.1.9.2":
                item = vals.read()
                attributes.append({"name": "Unstructured Name", "value": _string(item[0], vals.value(item))})
            else:
                attributes.append({"name": aoid, "value": ""})

    alg_name, hash_name, sig_family = SIG_ALGS.get(sig_oid, (sig_oid, "?", "?"))
    return {
        "version": version + 1,
        "subject": subject,
        "subjectString": ", ".join(f"{s['short']}={s['value']}" for s in subject),
        "publicKey": public_key,
        "signatureAlgorithm": alg_name,
        "signatureHash": hash_name,
        "signatureFamily": sig_family,
        "signatureLength": max(len(sig_bits) - 1, 0),
        "extensions": extensions,
        "attributes": attributes,
        "sans": san_list,
    }


def _checks(info):
    """Comprobaciones de buenas prácticas: lista de (nivel, mensaje)."""
    checks = []

    def add(level, msg):
        checks.append({"level": level, "message": msg})

    add("ok" if info["signatureValid"] else "error",
        "Firma del CSR válida (la clave privada corresponde a la clave pública)"
        if info["signatureValid"] else "La firma del CSR NO es válida")

    cn = [s["value"] for s in info["subject"] if s["short"] == "CN"]
    if not cn:
        add("warn", "El CSR no tiene Common Name (CN)")
    elif len(cn) > 1:
        add("warn", "El CSR tiene varios Common Name")

    pk = info["publicKey"]
    if pk["algorithm"] in ("RSA", "RSA-PSS"):
        if (pk["bits"] or 0) < 2048:
            add("error", f"Clave RSA de {pk['bits']} bits: insuficiente (mínimo 2048)")
        else:
            add("ok", f"Clave RSA de {pk['bits']} bits")
    elif pk["algorithm"] == "EC":
        if pk.get("curve") in ("P-256", "P-384", "P-521"):
            add("ok", f"Clave EC {pk['curve']}")
        else:
            add("warn", f"Curva EC poco habitual: {pk.get('curve')}")
    else:
        add("warn", f"Algoritmo de clave {pk['algorithm']}: muchas CA públicas no lo aceptan")

    if info["signatureHash"] in ("SHA-1", "MD5"):
        add("error", f"Firma con {info['signatureHash']}: algoritmo obsoleto, las CA lo rechazan")
    elif info["signatureHash"] in ("SHA-256", "SHA-384", "SHA-512"):
        add("ok", f"Firma con {info['signatureHash']}")

    dns = [s["value"].lower() for s in info["sans"] if s["type"] == "DNS"]
    ips = [s["value"] for s in info["sans"] if s["type"] == "IP"]
    if not info["sans"]:
        add("warn", "No incluye Subject Alternative Names (los navegadores exigen SAN)")
    elif cn and cn[0].lower() not in dns and cn[0] not in ips:
        add("warn", "El CN no aparece en los Subject Alternative Names")
    else:
        add("ok", f"{len(info['sans'])} Subject Alternative Name(s)")

    c = [s["value"] for s in info["subject"] if s["short"] == "C"]
    if c and not _COUNTRY_RE.match(c[0]):
        add("warn", "El país (C) no es un código ISO de 2 letras en mayúsculas")
    return checks
