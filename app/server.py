#!/usr/bin/env python3
"""Servidor HTTP de Enca's SGEN.

Usa la biblioteca estándar de Python y el paquete de Debian
``python3-cryptography`` (cifrado de las comunicaciones, ver ``e2e.py``).
No registra peticiones ni datos:
  * ``log_message`` y ``log_error`` están anulados.
  * Las claves/CSR solo existen en memoria durante la petición.
  * Toda petición/respuesta de la API con datos va cifrada con una clave
    efímera de un solo uso (ECDH P-256 + AES-256-GCM).
  * Las respuestas de la API llevan ``Cache-Control: no-store``.

Configuración por variables de entorno (ver /etc/opensslweb/opensslweb.env):
  OPENSSLWEB_HOST        dirección de escucha (por defecto 127.0.0.1)
  OPENSSLWEB_PORT        puerto (por defecto 8080)
  OPENSSLWEB_TLS_CERT    certificado PEM para servir HTTPS directamente (opcional)
  OPENSSLWEB_TLS_KEY     clave PEM del certificado anterior (opcional)
  OPENSSLWEB_MAX_JOBS    generaciones simultáneas permitidas (por defecto 4)
"""

from __future__ import annotations

import base64
import gc
import json
import os
import signal
import socket
import ssl
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import csrtool  # noqa: E402
import e2e  # noqa: E402

APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(APP_DIR, "static")
VERSION_FILE = os.path.join(os.path.dirname(APP_DIR), "VERSION")

MAX_BODY = 128 * 1024
REQUEST_TIMEOUT = 60

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
}


def read_version():
    try:
        with open(VERSION_FILE, encoding="utf-8") as fh:
            return fh.read().strip() or "dev"
    except OSError:
        return "dev"


VERSION = read_version()


def load_static():
    cache = {}
    for path, (name, ctype) in STATIC_FILES.items():
        with open(os.path.join(STATIC_DIR, name), "rb") as fh:
            body = fh.read()
        if name == "index.html":
            body = body.replace(b"{{VERSION}}", VERSION.encode("ascii", "replace"))
        cache[path] = (body, ctype)
    return cache


class Handler(BaseHTTPRequestHandler):
    server_version = "opensslweb"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = REQUEST_TIMEOUT

    # ---- sin registros ---------------------------------------------------
    def log_message(self, format, *args):  # noqa: A002 - firma heredada
        return

    def log_error(self, format, *args):  # noqa: A002
        return

    # ---- utilidades ------------------------------------------------------
    def _send(self, status, body, ctype, extra=None, cache=False):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=300" if cache else "no-store")
        if not cache:
            self.send_header("Pragma", "no-cache")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        if self.server.tls:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status, message):
        self._json(status, {"error": message})

    def _read_json(self):
        ctype = self.headers.get("Content-Type", "")
        if not ctype.startswith("application/json"):
            raise csrtool.CsrError("Content-Type debe ser application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            raise csrtool.CsrError("Petición demasiado grande")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise csrtool.CsrError("JSON no válido") from None
        finally:
            del raw

    def _same_origin(self):
        """Protección CSRF básica: si el navegador envía Origin, debe coincidir."""
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        return origin.split("://", 1)[-1] == host

    # ---- métodos HTTP ----------------------------------------------------
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._json(HTTPStatus.OK, {"status": "ok", "version": VERSION})
            return
        if path == "/api/key":
            # Clave pública efímera para cifrar UNA petición (protocolo sgen1).
            if not self._same_origin():
                self._error(HTTPStatus.FORBIDDEN, "Origen no permitido")
                return
            self._json(HTTPStatus.OK, self.server.keys.new_key())
            return
        item = self.server.static.get(path)
        if item is None:
            self._error(HTTPStatus.NOT_FOUND, "No encontrado")
            return
        body, ctype = item
        self._send(HTTPStatus.OK, body, ctype, cache=path not in ("/", "/index.html"))

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        routes = {
            "/api/generate": self._api_generate,
            "/api/decode": self._api_decode,
            "/api/zip": self._api_zip,
        }
        handler = routes.get(path)
        if handler is None:
            self._error(HTTPStatus.NOT_FOUND, "No encontrado")
            return
        if not self._same_origin():
            self._error(HTTPStatus.FORBIDDEN, "Origen no permitido")
            return
        envelope = data = channel = None
        try:
            envelope = self._read_json()
            # Descifrado: la clave privada efímera se retira y destruye aquí.
            data, channel = e2e.open_request(self.server.keys, envelope, path)
            envelope = None
            try:
                status, result = HTTPStatus.OK, handler(data)
            except csrtool.CsrError as exc:
                status, result = HTTPStatus.BAD_REQUEST, {"error": str(exc)}
            data = None
            # La respuesta (también los errores de validación) viaja cifrada.
            self._json(status, channel.seal(result))
            result = None
        except (csrtool.CsrError, e2e.E2EError) as exc:
            # Fallo antes de poder descifrar: mensaje genérico sin datos.
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception:  # noqa: BLE001 - nunca filtrar detalles ni registrar
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error interno")
        finally:
            # Eliminamos cualquier referencia al material recibido y a las claves.
            if channel is not None:
                channel.close()
            envelope = data = channel = None
            gc.collect(0)

    def _api_generate(self, data):
        req = csrtool.parse_request(data)
        if not self.server.jobs.acquire(timeout=30):
            raise csrtool.CsrError("Servidor ocupado, inténtalo de nuevo en unos segundos")
        try:
            return csrtool.generate(req)
        finally:
            self.server.jobs.release()
            req = None

    def _api_decode(self, data):
        if not isinstance(data, dict):
            raise csrtool.CsrError("Petición no válida")
        return csrtool.decode(data.get("csr", ""))

    def _api_zip(self, data):
        filename, body = csrtool.build_zip(data)
        # El nombre del fichero va dentro de la respuesta cifrada, no en cabeceras.
        return {"filename": filename, "zip": base64.b64encode(body).decode("ascii")}


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address, handler, tls_context=None, max_jobs=4):
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, handler)
        self.static = load_static()
        self.jobs = threading.BoundedSemaphore(max_jobs)
        self.keys = e2e.KeyStore()
        self.tls = tls_context is not None
        if tls_context is not None:
            self.socket = tls_context.wrap_socket(self.socket, server_side=True,
                                                  do_handshake_on_connect=False)

    def handle_error(self, request, client_address):
        # Sin trazas: podrían contener datos de la petición.
        return


def build_tls_context(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def main():
    def fail(msg):
        print(f"opensslweb: error de configuración: {msg}", file=sys.stderr, flush=True)
        sys.exit(2)

    host = os.environ.get("OPENSSLWEB_HOST", "127.0.0.1").strip() or "127.0.0.1"
    cert = os.environ.get("OPENSSLWEB_TLS_CERT", "").strip()
    key = os.environ.get("OPENSSLWEB_TLS_KEY", "").strip()
    try:
        port = int(os.environ.get("OPENSSLWEB_PORT", "8080"))
        if not 0 < port < 65536:
            raise ValueError
    except ValueError:
        fail("OPENSSLWEB_PORT debe ser un número entre 1 y 65535")
    try:
        max_jobs = max(1, int(os.environ.get("OPENSSLWEB_MAX_JOBS", "4")))
    except ValueError:
        fail("OPENSSLWEB_MAX_JOBS debe ser un número")
    if bool(cert) != bool(key):
        fail("para HTTPS hay que indicar OPENSSLWEB_TLS_CERT y OPENSSLWEB_TLS_KEY")

    os.umask(0o077)
    try:
        tls_context = build_tls_context(cert, key) if cert else None
    except (OSError, ssl.SSLError) as exc:
        fail(f"no se puede cargar el certificado/clave TLS ({exc.__class__.__name__})")
    try:
        httpd = Server((host, port), Handler, tls_context=tls_context, max_jobs=max_jobs)
    except OSError as exc:
        fail(f"no se puede escuchar en {host}:{port} ({exc.strerror})")

    def stop(*_):
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    scheme = "https" if tls_context else "http"
    print(f"opensslweb {VERSION} escuchando en {scheme}://{host}:{port}", file=sys.stderr, flush=True)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
