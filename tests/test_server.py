"""Tests del servidor HTTP (arranca un servidor real en un puerto efímero)."""

import base64
import contextlib
import http.client
import io
import json
import os
import re
import sys
import threading
import unittest
import zipfile

from tests.helpers import APP, base_request, e2e_open, e2e_seal

import server


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stderr = io.StringIO()
        cls._redirect = contextlib.redirect_stderr(cls.stderr)
        cls._redirect.__enter__()
        cls.httpd = server.Server(("127.0.0.1", 0), server.Handler, max_jobs=2)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls._redirect.__exit__(None, None, None)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        hdrs = dict(headers or {})
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=body, headers=hdrs)
        res = conn.getresponse()
        data = res.read()
        conn.close()
        return res, data

    # ------------------------------------------------------------------
    def test_index_and_security_headers(self):
        res, body = self.request("GET", "/")
        self.assertEqual(res.status, 200)
        self.assertIn("Enca's SGEN".encode(), body)
        self.assertNotIn(b"{{VERSION}}", body)
        csp = res.getheader("Content-Security-Policy")
        self.assertIn("default-src 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertEqual(res.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(res.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(res.getheader("Cache-Control"), "no-store")

    def test_static_files(self):
        for path, ctype in (("/app.css", "text/css"), ("/app.js", "text/javascript"),
                            ("/favicon.svg", "image/svg+xml")):
            with self.subTest(path=path):
                res, body = self.request("GET", path)
                self.assertEqual(res.status, 200)
                self.assertTrue(res.getheader("Content-Type").startswith(ctype))
                self.assertGreater(len(body), 10)

    def test_no_path_traversal(self):
        for path in ("/../server.py", "/static/../csrtool.py", "/%2e%2e/server.py", "/server.py", "/app/server.py"):
            with self.subTest(path=path):
                res, _ = self.request("GET", path)
                self.assertEqual(res.status, 404)

    def test_healthz(self):
        res, body = self.request("GET", "/healthz")
        self.assertEqual(res.status, 200)
        self.assertEqual(json.loads(body)["status"], "ok")

    def get_key(self, headers=None):
        res, body = self.request("GET", "/api/key", headers=headers)
        self.assertEqual(res.status, 200, body)
        self.assertEqual(res.getheader("Cache-Control"), "no-store")
        return json.loads(body)

    def secure(self, path, obj, headers=None):
        """Petición cifrada (protocolo sgen1). Devuelve (status, respuesta descifrada, crudo)."""
        envelope, res_key = e2e_seal(self.get_key(), path, obj)
        res, body = self.request("POST", path, envelope, headers)
        raw = json.loads(body)
        if "ct" not in raw:
            return res.status, raw, body
        return res.status, e2e_open(res_key, path, raw), body

    def test_generate_decode_zip_flow(self):
        req = base_request(keyType="rsa2048", digest="sha384", cipher="aes256", passphrase="contraseña",
                           sans=[{"type": "DNS", "value": "api.ejemplo.es"}])
        status, out, raw = self.secure("/api/generate", req)
        self.assertEqual(status, 200, out)
        self.assertEqual(out["name"], "www.ejemplo.es")
        self.assertIn("ENCRYPTED PRIVATE KEY", out["key"])
        # En la red no viaja nada en claro: ni la clave, ni el CSR, ni el CN.
        for secret in (b"PRIVATE KEY", b"CERTIFICATE REQUEST", b"ejemplo", out["key"][40:80].encode()):
            self.assertNotIn(secret, raw)

        status, info, raw = self.secure("/api/decode", {"csr": out["csr"]})
        self.assertEqual(status, 200, info)
        self.assertTrue(info["signatureValid"])
        self.assertEqual(info["signatureAlgorithm"], "sha384WithRSAEncryption")
        self.assertEqual([s["value"] for s in info["sans"]], ["www.ejemplo.es", "api.ejemplo.es"])
        self.assertNotIn(b"ejemplo", raw)

        for fmt, names in (("pem", ["www.ejemplo.es.csr", "www.ejemplo.es.key"]),
                           ("txt", ["www.ejemplo.es-csr.txt", "www.ejemplo.es-key.txt"])):
            with self.subTest(fmt=fmt):
                status, res, raw = self.secure("/api/zip", {
                    "name": out["name"], "format": fmt, "csr": out["csr"], "key": out["key"]})
                self.assertEqual(status, 200)
                self.assertEqual(res["filename"], "www.ejemplo.es.zip")
                body = base64.b64decode(res["zip"])
                self.assertEqual(sorted(zipfile.ZipFile(io.BytesIO(body)).namelist()), names)
                self.assertNotIn(b"ejemplo", raw)

    def test_validation_error_is_encrypted(self):
        status, out, raw = self.secure("/api/generate", base_request(subject={"CN": ""}))
        self.assertEqual(status, 400)
        self.assertIn("Common Name", out["error"])
        self.assertNotIn(b"Common Name", raw)

    def test_plaintext_requests_rejected(self):
        # Una petición sin cifrar no se procesa.
        res, body = self.request("POST", "/api/generate", base_request())
        self.assertEqual(res.status, 400)
        self.assertIn("cifradas", json.loads(body)["error"])
        self.assertNotIn(b"PRIVATE KEY", body)

    def test_key_is_single_use_and_destroyed(self):
        key = self.get_key()
        self.assertEqual(len(base64.b64decode(key["publicKey"])), 65)
        pending = len(self.httpd.keys)
        envelope, res_key = e2e_seal(key, "/api/decode", {"csr": "x"})
        res, body = self.request("POST", "/api/decode", envelope)
        self.assertEqual(res.status, 400)  # CSR inválido, pero descifrado correctamente
        self.assertIn("error", e2e_open(res_key, "/api/decode", json.loads(body)))
        self.assertEqual(len(self.httpd.keys), pending - 1)  # clave privada eliminada
        # Reenviar el mismo mensaje (replay) ya no funciona: la clave no existe.
        res, body = self.request("POST", "/api/decode", envelope)
        self.assertEqual(res.status, 400)
        self.assertIn("caducada", json.loads(body)["error"])

    def test_every_key_is_different(self):
        keys = {self.get_key()["publicKey"] for _ in range(5)}
        self.assertEqual(len(keys), 5)

    def test_tampering_and_wrong_endpoint(self):
        envelope, _ = e2e_seal(self.get_key(), "/api/decode", {"csr": "x"})
        ct = bytearray(base64.b64decode(envelope["ct"]))
        ct[0] ^= 1
        envelope["ct"] = base64.b64encode(bytes(ct)).decode()
        res, body = self.request("POST", "/api/decode", envelope)
        self.assertEqual(res.status, 400)
        self.assertIn("descifrar", json.loads(body)["error"])
        # Un mensaje cifrado para /api/decode no sirve para /api/generate (AAD).
        envelope, _ = e2e_seal(self.get_key(), "/api/decode", base_request())
        res, body = self.request("POST", "/api/generate", envelope)
        self.assertEqual(res.status, 400)

    def test_bad_requests(self):
        res, _ = self.request("POST", "/api/generate", b"{}", {"Content-Type": "text/plain"})
        self.assertEqual(res.status, 400)
        res, _ = self.request("POST", "/api/generate", b"{no json", {"Content-Type": "application/json"})
        self.assertEqual(res.status, 400)
        res, _ = self.request("POST", "/api/nada", {})
        self.assertEqual(res.status, 404)
        res, _ = self.request("POST", "/api/generate", b"x" * (server.MAX_BODY + 1),
                              {"Content-Type": "application/json"})
        self.assertEqual(res.status, 400)
        for bad in ({"v": 1}, {"v": 1, "kid": "AAAA"}, {"v": 2, "kid": "x"},
                    {"v": 1, "kid": base64.b64encode(b"0" * 16).decode(), "epk": "", "iv": "", "ct": ""}):
            with self.subTest(bad=bad):
                res, _ = self.request("POST", "/api/generate", bad)
                self.assertEqual(res.status, 400)

    def test_cross_origin_rejected(self):
        res, _ = self.request("GET", "/api/key", headers={"Origin": "https://malicioso.example"})
        self.assertEqual(res.status, 403)
        envelope, _ = e2e_seal(self.get_key(), "/api/generate", base_request())
        res, _ = self.request("POST", "/api/generate", envelope, {"Origin": "https://malicioso.example"})
        self.assertEqual(res.status, 403)
        status, _, _ = self.secure("/api/decode", {"csr": "x"}, {"Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(status, 400)  # mismo origen: se procesa (CSR inválido)

    def test_server_logs_nothing(self):
        self.request("GET", "/")
        self.request("GET", "/no-existe")
        self.secure("/api/generate", base_request())
        self.request("POST", "/api/generate", base_request())
        self.request("POST", "/api/generate", b"basura", {"Content-Type": "application/json"})
        self.assertEqual(self.stderr.getvalue(), "")


class ListenAllInterfacesTests(unittest.TestCase):
    """Por defecto la web escucha en todas las interfaces de red."""

    def test_default_host_is_all_interfaces(self):
        self.assertEqual(server.DEFAULT_HOST, "::")
        with open(os.path.join(os.path.dirname(APP), "deploy", "opensslweb.env"), encoding="utf-8") as fh:
            self.assertIn("\nOPENSSLWEB_HOST=::\n", fh.read())

    def test_dual_stack_accepts_ipv4_and_ipv6(self):
        try:
            httpd = server.Server(("::", 0), server.Handler)
        except OSError:
            self.skipTest("IPv6 no disponible en este sistema")
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            for host in ("127.0.0.1", "::1"):
                with self.subTest(host=host):
                    conn = http.client.HTTPConnection(host, port, timeout=10)
                    conn.request("GET", "/healthz")
                    self.assertEqual(conn.getresponse().status, 200)
                    conn.close()
        finally:
            httpd.shutdown()
            httpd.server_close()


class LineEndingsTests(unittest.TestCase):
    """bash, systemd y Debian necesitan saltos de línea Unix (LF)."""

    def test_no_crlf(self):
        root = os.path.dirname(APP)
        for base, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
            for name in files:
                path = os.path.join(base, name)
                with open(path, "rb") as fh:
                    data = fh.read()
                with self.subTest(file=os.path.relpath(path, root)):
                    self.assertNotIn(b"\r\n", data)

    def test_installer_self_heals_crlf(self):
        with open(os.path.join(os.path.dirname(APP), "install.sh"), encoding="utf-8") as fh:
            second = fh.read().splitlines()[1]
        self.assertIn("sed -i 's/\\r$//'", second)
        self.assertTrue(second.split("#")[-1].strip().endswith('"#")'))


class StaticAssetsTests(unittest.TestCase):
    """La interfaz no debe depender de CSS/JS/fuentes externos."""

    def test_title_and_information_section(self):
        with open(os.path.join(APP, "static", "index.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertRegex(html, r"<title>Enca's SGEN")
        info = html[html.index('id="tab-info"'):]
        for text in ("Andre Lopez Araujo", "Dependabot", "SLA", "gratuito",
                     "Garantías técnicas de no almacenamiento", "ataques",
                     "Cifrado de las comunicaciones", "Política de tratamiento de datos",
                     "AES-256-GCM", "ECDH P-256", "60 segundos"):
            with self.subTest(text=text):
                self.assertIn(text, info)
        # Los enlaces internos del índice apuntan a secciones existentes
        for anchor in re.findall(r'href="#(info-[a-z]+)"', html):
            with self.subTest(anchor=anchor):
                self.assertIn(f'id="{anchor}"', html)

    def test_no_external_dependencies(self):
        static = os.path.join(APP, "static")
        pattern = re.compile(r"""(src|href)\s*=\s*["'](https?:)?//|@import|url\(\s*["']?https?:|fetch\(\s*["']https?:""", re.I)
        for name in os.listdir(static):
            with open(os.path.join(static, name), encoding="utf-8") as fh:
                content = fh.read()
            with self.subTest(file=name):
                self.assertIsNone(pattern.search(content))

    def test_no_inline_scripts_or_styles(self):
        with open(os.path.join(APP, "static", "index.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)[^>]*>")
        self.assertNotRegex(html, r"<style")
        self.assertNotRegex(html, r"\son[a-z]+\s*=")
        self.assertNotRegex(html, r"\sstyle\s*=")
        # La CSP (style-src 'self') bloquea atributos style creados desde JS.
        with open(os.path.join(APP, "static", "app.js"), encoding="utf-8") as fh:
            js = fh.read()
        self.assertNotRegex(js, r"""\bstyle\s*:\s*["']|setAttribute\(\s*["']style""")


if __name__ == "__main__":
    unittest.main()
