"""Tests del servidor HTTP (arranca un servidor real en un puerto efímero)."""

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

from tests.helpers import APP, base_request

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

    def test_generate_decode_zip_flow(self):
        res, body = self.request("POST", "/api/generate", base_request(
            keyType="rsa2048", digest="sha384", cipher="aes256", passphrase="contraseña",
            sans=[{"type": "DNS", "value": "api.ejemplo.es"}]))
        self.assertEqual(res.status, 200, body)
        self.assertEqual(res.getheader("Cache-Control"), "no-store")
        out = json.loads(body)
        self.assertEqual(out["name"], "www.ejemplo.es")
        self.assertIn("ENCRYPTED PRIVATE KEY", out["key"])

        res, body = self.request("POST", "/api/decode", {"csr": out["csr"]})
        self.assertEqual(res.status, 200, body)
        info = json.loads(body)
        self.assertTrue(info["signatureValid"])
        self.assertEqual(info["signatureAlgorithm"], "sha384WithRSAEncryption")
        self.assertEqual([s["value"] for s in info["sans"]], ["www.ejemplo.es", "api.ejemplo.es"])

        for fmt, names in (("pem", ["www.ejemplo.es.csr", "www.ejemplo.es.key"]),
                           ("txt", ["www.ejemplo.es-csr.txt", "www.ejemplo.es-key.txt"])):
            with self.subTest(fmt=fmt):
                res, body = self.request("POST", "/api/zip", {
                    "name": out["name"], "format": fmt, "csr": out["csr"], "key": out["key"]})
                self.assertEqual(res.status, 200)
                self.assertEqual(res.getheader("Content-Type"), "application/zip")
                self.assertEqual(res.getheader("Cache-Control"), "no-store")
                self.assertIn('filename="www.ejemplo.es.zip"', res.getheader("Content-Disposition"))
                self.assertEqual(sorted(zipfile.ZipFile(io.BytesIO(body)).namelist()), names)

    def test_validation_error_is_400(self):
        res, body = self.request("POST", "/api/generate", base_request(subject={"CN": ""}))
        self.assertEqual(res.status, 400)
        self.assertIn("Common Name", json.loads(body)["error"])

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

    def test_cross_origin_rejected(self):
        res, _ = self.request("POST", "/api/generate", base_request(), {"Origin": "https://malicioso.example"})
        self.assertEqual(res.status, 403)
        res, _ = self.request("POST", "/api/decode", {"csr": "x"},
                              {"Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(res.status, 400)  # mismo origen: se procesa (CSR inválido)

    def test_server_logs_nothing(self):
        self.request("GET", "/")
        self.request("GET", "/no-existe")
        self.request("POST", "/api/generate", base_request())
        self.request("POST", "/api/generate", b"basura", {"Content-Type": "application/json"})
        self.assertEqual(self.stderr.getvalue(), "")


class StaticAssetsTests(unittest.TestCase):
    """La interfaz no debe depender de CSS/JS/fuentes externos."""

    def test_title_and_information_section(self):
        with open(os.path.join(APP, "static", "index.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertRegex(html, r"<title>Enca's SGEN")
        info = html[html.index('id="tab-info"'):]
        for text in ("Andre Lopez Araujo", "Dependabot", "SLA", "gratuito",
                     "Garantías técnicas de no almacenamiento", "ataques"):
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
