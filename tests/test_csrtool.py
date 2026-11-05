"""Tests de generación, validación, ZIP y desglose (requieren el binario openssl)."""

import io
import os
import tempfile
import unittest
import zipfile

from tests.helpers import base_request, openssl

import csrtool


def gen(**overrides):
    return csrtool.generate(csrtool.parse_request(base_request(**overrides)))


def pubkey_of_key(key_pem, passphrase=None):
    args = ["pkey", "-in", "/dev/stdin", "-pubout"]
    if passphrase:
        args += ["-passin", f"pass:{passphrase}"]
    return openssl(*args, stdin=key_pem.encode()).stdout


def pubkey_of_csr(csr_pem):
    return openssl("req", "-in", "/dev/stdin", "-noout", "-pubkey", stdin=csr_pem.encode()).stdout


class GenerateTests(unittest.TestCase):
    def test_all_key_types_and_digests(self):
        expected = {
            "rsa2048": ("RSA", 2048), "rsa3072": ("RSA", 3072), "rsa4096": ("RSA", 4096),
            "ecp256": ("EC", 256), "ecp384": ("EC", 384), "ecp521": ("EC", 521),
        }
        hashes = {"sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
        digests = list(hashes)
        for i, (key_type, (alg, bits)) in enumerate(expected.items()):
            digest = digests[i % len(digests)]
            with self.subTest(key_type=key_type, digest=digest):
                res = gen(keyType=key_type, digest=digest)
                self.assertIn("-----BEGIN CERTIFICATE REQUEST-----", res["csr"])
                self.assertIn("-----BEGIN PRIVATE KEY-----", res["key"])
                info = csrtool.decode(res["csr"])
                self.assertTrue(info["signatureValid"])
                self.assertEqual(info["publicKey"]["algorithm"], alg)
                self.assertEqual(info["publicKey"]["bits"], bits)
                self.assertEqual(info["signatureHash"], hashes[digest])
                # La clave privada corresponde al CSR
                self.assertEqual(pubkey_of_key(res["key"]), pubkey_of_csr(res["csr"]))

    def test_every_digest_on_rsa(self):
        for digest, name in (("sha256", "sha256WithRSAEncryption"),
                             ("sha384", "sha384WithRSAEncryption"),
                             ("sha512", "sha512WithRSAEncryption")):
            with self.subTest(digest=digest):
                info = csrtool.decode(gen(keyType="rsa2048", digest=digest)["csr"])
                self.assertEqual(info["signatureAlgorithm"], name)

    def test_aes_encryption(self):
        for cipher, dek in (("aes128", "AES-128-CBC"), ("aes192", "AES-192-CBC"), ("aes256", "AES-256-CBC")):
            with self.subTest(cipher=cipher):
                pw = "clave segura ñ " + cipher
                res = gen(keyType="rsa2048", cipher=cipher, passphrase=pw)
                self.assertIn("-----BEGIN ENCRYPTED PRIVATE KEY-----", res["key"])
                # Se descifra con la contraseña correcta...
                self.assertEqual(pubkey_of_key(res["key"], pw), pubkey_of_csr(res["csr"]))
                # ...y no con una incorrecta
                bad = openssl("pkey", "-in", "/dev/stdin", "-passin", "pass:mala", stdin=res["key"].encode())
                self.assertNotEqual(bad.returncode, 0)
                # Comprobar el algoritmo AES usado
                asn = openssl("asn1parse", "-in", "/dev/stdin", stdin=res["key"].encode()).stdout.decode()
                self.assertIn(dek.lower().replace("-cbc", "-cbc"), asn.lower())

    def test_traditional_format(self):
        res = gen(keyType="rsa2048", keyFormat="traditional")
        self.assertIn("-----BEGIN RSA PRIVATE KEY-----", res["key"])
        res = gen(keyType="ecp384", keyFormat="traditional")
        self.assertIn("-----BEGIN EC PRIVATE KEY-----", res["key"])
        res = gen(keyType="ecp256", keyFormat="traditional", cipher="aes256", passphrase="abcdefgh")
        self.assertIn("-----BEGIN EC PRIVATE KEY-----", res["key"])
        self.assertIn("Proc-Type: 4,ENCRYPTED", res["key"])
        self.assertIn("DEK-Info: AES-256-CBC", res["key"])
        self.assertEqual(pubkey_of_key(res["key"], "abcdefgh"), pubkey_of_csr(res["csr"]))

    def test_subject_and_special_characters(self):
        subject = {
            "CN": "*.ejemplo.es", "O": "Ejemplo, S.A. / I+D = ñandú", "OU": "Sistemas",
            "L": "A Coruña", "ST": "Galicia", "C": "es", "emailAddress": "admin@ejemplo.es",
        }
        info = csrtool.decode(gen(subject=subject)["csr"])
        got = {s["short"]: s["value"] for s in info["subject"]}
        self.assertEqual(got["CN"], "*.ejemplo.es")
        self.assertEqual(got["O"], "Ejemplo, S.A. / I+D = ñandú")
        self.assertEqual(got["L"], "A Coruña")
        self.assertEqual(got["C"], "ES")
        self.assertEqual(got["emailAddress"], "admin@ejemplo.es")
        self.assertEqual(len(info["subject"]), 7)

    def test_sans_and_extensions(self):
        res = gen(
            keyType="rsa2048",
            sans=[
                {"type": "DNS", "value": "ejemplo.es"},
                {"type": "DNS", "value": "WWW.ejemplo.es"},  # duplicado del CN
                {"type": "IP", "value": "192.0.2.10"},
                {"type": "IP", "value": "2001:db8::1"},
                {"type": "email", "value": "it@ejemplo.es"},
                {"type": "URI", "value": "https://ejemplo.es/id"},
                {"type": "DNS", "value": "   "},
            ],
            keyUsage=["digitalSignature", "keyEncipherment"],
            extKeyUsage=["serverAuth", "clientAuth"],
            mustStaple=True,
        )
        info = csrtool.decode(res["csr"])
        sans = [(s["type"], s["value"]) for s in info["sans"]]
        self.assertEqual(sans, [
            ("DNS", "www.ejemplo.es"), ("DNS", "ejemplo.es"), ("IP", "192.0.2.10"),
            ("IP", "2001:db8::1"), ("email", "it@ejemplo.es"), ("URI", "https://ejemplo.es/id"),
        ])
        exts = {e["name"]: e for e in info["extensions"]}
        self.assertTrue(exts["Key Usage"]["critical"])
        self.assertEqual(exts["Key Usage"]["values"], ["digitalSignature", "keyEncipherment"])
        self.assertEqual(len(exts["Extended Key Usage"]["values"]), 2)
        self.assertIn("TLS Feature (OCSP Must-Staple)", exts)
        self.assertTrue(all(c["level"] == "ok" for c in info["checks"]), info["checks"])

    def test_cn_not_in_san_when_disabled(self):
        info = csrtool.decode(gen(cnInSan=False, sans=[{"type": "DNS", "value": "otro.es"}])["csr"])
        self.assertEqual([s["value"] for s in info["sans"]], ["otro.es"])
        self.assertTrue(any(c["level"] == "warn" for c in info["checks"]))

    def test_ec_drops_key_encipherment(self):
        req = csrtool.parse_request(base_request(keyType="ecp256", keyUsage=["digitalSignature", "keyEncipherment"]))
        self.assertEqual(req.key_usage, ["digitalSignature"])

    def test_no_extensions(self):
        info = csrtool.decode(gen(cnInSan=False, keyUsage=[], extKeyUsage=[])["csr"])
        self.assertEqual(info["extensions"], [])
        self.assertTrue(info["signatureValid"])

    def test_nothing_written_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = {k: os.environ.get(k) for k in ("TMPDIR", "TMP", "TEMP")}
            try:
                for k in old:
                    os.environ[k] = tmp
                tempfile.tempdir = None
                gen(keyType="rsa2048", cipher="aes256", passphrase="abcdefgh")
                csrtool.build_zip({"name": "x", "csr": gen()["csr"]})
                self.assertEqual(os.listdir(tmp), [])
            finally:
                for k, v in old.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
                tempfile.tempdir = None

    def test_suggested_name(self):
        self.assertEqual(csrtool.suggested_name("*.Ejemplo.es"), "wildcard.ejemplo.es")
        self.assertEqual(csrtool.suggested_name("../../etc/passwd"), "etc_passwd")
        self.assertEqual(csrtool.suggested_name("///"), "certificado")


class ValidationTests(unittest.TestCase):
    def assertRejected(self, **overrides):
        with self.assertRaises(csrtool.CsrError):
            csrtool.parse_request(base_request(**overrides))

    def test_rejections(self):
        self.assertRejected(subject={"CN": ""})
        self.assertRejected(subject={"CN": "a" * 65})
        self.assertRejected(subject={"CN": "ok.es", "C": "ESP"})
        self.assertRejected(subject={"CN": "ok.es", "C": "E1"})
        self.assertRejected(subject={"CN": "ok.es\n/CN=evil"})
        self.assertRejected(subject={"CN": "ok.es", "O": "x\x00y"})
        self.assertRejected(subject={"CN": "ok.es", "emailAddress": "no-es-correo"})
        self.assertRejected(subject="CN=x")
        self.assertRejected(keyType="rsa1024")
        self.assertRejected(keyType="dsa")
        self.assertRejected(digest="sha1")
        self.assertRejected(digest="md5")
        self.assertRejected(cipher="des3")
        self.assertRejected(keyFormat="der")
        self.assertRejected(cipher="aes256", passphrase="abc")
        self.assertRejected(cipher="aes256", passphrase="abcd\nefgh")
        self.assertRejected(cipher="aes256")
        self.assertRejected(sans=[{"type": "DNS", "value": "mal dominio.es"}])
        self.assertRejected(sans=[{"type": "DNS", "value": "a,DNS:inyectado.es"}])
        self.assertRejected(sans=[{"type": "DNS", "value": "-mal.es"}])
        self.assertRejected(sans=[{"type": "IP", "value": "300.1.1.1"}])
        self.assertRejected(sans=[{"type": "email", "value": "x@y,DNS:z"}])
        self.assertRejected(sans=[{"type": "URI", "value": "https://a.es/x,DNS:b.es"}])
        self.assertRejected(sans=[{"type": "otherName", "value": "x"}])
        self.assertRejected(sans=[{"type": "DNS", "value": f"h{i}.es"} for i in range(101)])
        self.assertRejected(keyUsage=["keyCertSign"])
        self.assertRejected(extKeyUsage=["anyExtendedKeyUsage"])
        self.assertRejected(keyUsage="digitalSignature")

    def test_accepts_minimal(self):
        req = csrtool.parse_request({"subject": {"CN": "solo-cn.es"}})
        self.assertEqual(req.sans, [("DNS", "solo-cn.es")])
        req = csrtool.parse_request({"subject": {"CN": "10.0.0.1"}})
        self.assertEqual(req.sans, [("IP", "10.0.0.1")])
        req = csrtool.parse_request({"subject": {"CN": "Mi Empresa"}})
        self.assertEqual(req.sans, [])

    def test_passphrase_ignored_without_cipher(self):
        req = csrtool.parse_request(base_request(passphrase="x"))
        self.assertEqual(req.passphrase, "")


class ZipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = gen(keyType="rsa2048", cipher="aes128", passphrase="abcdefgh")

    def read_zip(self, body):
        zf = zipfile.ZipFile(io.BytesIO(body))
        self.assertIsNone(zf.testzip())
        return {i.filename: zf.read(i).decode() for i in zf.infolist()}

    def test_zip_pem(self):
        name, body = csrtool.build_zip({"name": "www.ejemplo.es", "format": "pem",
                                        "csr": self.res["csr"], "key": self.res["key"]})
        self.assertEqual(name, "www.ejemplo.es.zip")
        files = self.read_zip(body)
        self.assertEqual(sorted(files), ["www.ejemplo.es.csr", "www.ejemplo.es.key"])
        self.assertEqual(files["www.ejemplo.es.csr"].strip(), self.res["csr"].strip())
        self.assertEqual(files["www.ejemplo.es.key"].strip(), self.res["key"].strip())

    def test_zip_txt(self):
        _, body = csrtool.build_zip({"name": "web", "format": "txt",
                                     "csr": self.res["csr"], "key": self.res["key"]})
        self.assertEqual(sorted(self.read_zip(body)), ["web-csr.txt", "web-key.txt"])

    def test_zip_single(self):
        _, body = csrtool.build_zip({"name": "web", "csr": self.res["csr"]})
        self.assertEqual(list(self.read_zip(body)), ["web.csr"])
        _, body = csrtool.build_zip({"name": "web", "key": self.res["key"]})
        self.assertEqual(list(self.read_zip(body)), ["web.key"])

    def test_zip_traditional_key(self):
        res = gen(keyType="rsa2048", keyFormat="traditional", cipher="aes256", passphrase="abcdefgh")
        _, body = csrtool.build_zip({"name": "t", "csr": res["csr"], "key": res["key"]})
        self.assertIn("Proc-Type", self.read_zip(body)["t.key"])

    def test_zip_rejections(self):
        for data in (
            {"name": "x"},
            {"name": "x", "csr": "hola"},
            {"name": "x", "key": "-----BEGIN PRIVATE KEY-----\n<script>\n-----END PRIVATE KEY-----"},
            {"name": "x", "csr": self.res["csr"], "format": "exe"},
            {"name": "x", "csr": self.res["csr"] + "A" * 70000},
            [],
        ):
            with self.subTest(data=str(data)[:60]):
                with self.assertRaises(csrtool.CsrError):
                    csrtool.build_zip(data)

    def test_zip_name_sanitized(self):
        name, body = csrtool.build_zip({"name": "../../etc/x", "csr": self.res["csr"]})
        self.assertEqual(name, "etc_x.zip")
        self.assertEqual(list(self.read_zip(body)), ["etc_x.csr"])


class DecodeTests(unittest.TestCase):
    def openssl_csr(self, *extra, key_type="rsa:2048"):
        cfg = csrtool.REQ_CONFIG
        proc = openssl("req", "-new", "-newkey", key_type, "-nodes", "-keyout", "/dev/null",
                       "-config", cfg, "-subj", "/CN=legacy.example/O=Legacy", *extra)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.decode()

    def test_sha1_is_flagged(self):
        info = csrtool.decode(self.openssl_csr("-sha1"))
        self.assertEqual(info["signatureHash"], "SHA-1")
        self.assertTrue(any(c["level"] == "error" and "SHA-1" in c["message"] for c in info["checks"]))

    def test_without_san_is_warned(self):
        info = csrtool.decode(self.openssl_csr())
        self.assertEqual(info["sans"], [])
        self.assertTrue(any("Subject Alternative" in c["message"] and c["level"] == "warn" for c in info["checks"]))

    def test_new_header_and_whitespace(self):
        csr = gen()["csr"]
        legacy = "  \r\n" + csr.replace("BEGIN CERTIFICATE", "BEGIN NEW CERTIFICATE") \
            .replace("END CERTIFICATE", "END NEW CERTIFICATE").replace("\n", "\r\n") + "\n\n"
        info = csrtool.decode(legacy)
        self.assertTrue(info["signatureValid"])

    def test_tampered_signature(self):
        csr = gen(keyType="rsa2048")["csr"]
        der = __import__("base64").b64decode("".join(csr.strip().splitlines()[1:-1]))
        der = der[:-5] + bytes([der[-5] ^ 0xFF]) + der[-4:]
        b64 = __import__("base64").b64encode(der).decode()
        pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + b64 + "\n-----END CERTIFICATE REQUEST-----\n"
        info = csrtool.decode(pem)
        self.assertFalse(info["signatureValid"])
        self.assertEqual(info["checks"][0]["level"], "error")

    def test_challenge_password_hidden(self):
        cfg = (
            "[req]\ndistinguished_name=dn\nattributes=attrs\nprompt=no\n"
            "[dn]\nCN=c.example\n[attrs]\nchallengePassword=supersecreto\n"
        )
        rfd, wfd = os.pipe()
        os.write(wfd, cfg.encode())
        os.close(wfd)
        try:
            import subprocess
            proc = subprocess.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt",
                                   "ec_paramgen_curve:P-256", "-nodes", "-keyout", "/dev/null",
                                   "-config", f"/dev/fd/{rfd}"], pass_fds=(rfd,), capture_output=True)
        finally:
            os.close(rfd)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        info = csrtool.decode(proc.stdout.decode())
        self.assertEqual(info["attributes"][0]["name"], "Challenge Password")
        self.assertNotIn("supersecreto", str(info["attributes"]))

    def test_invalid_inputs(self):
        for text in ("", "hola", "-----BEGIN CERTIFICATE REQUEST-----\n!!!!\n-----END CERTIFICATE REQUEST-----",
                     "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----",
                     "-----BEGIN CERTIFICATE REQUEST-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END CERTIFICATE REQUEST-----",
                     "x" * 70000, None, 12):
            with self.subTest(text=str(text)[:40]):
                with self.assertRaises(csrtool.CsrError):
                    csrtool.decode(text)

    def test_openssl_text_included(self):
        info = csrtool.decode(gen()["csr"])
        self.assertIn("Certificate Request:", info["opensslText"])
        self.assertTrue(info["pem"].startswith("-----BEGIN CERTIFICATE REQUEST-----\n"))


if __name__ == "__main__":
    unittest.main()
