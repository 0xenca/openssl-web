"""Tests de construcción de PFX / PKCS#12 (en memoria, sin disco)."""

import base64
import os
import re
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from tests.helpers import base_request, make_ca_chain, openssl

import csrtool
import pfxtool


def gen(**overrides):
    return csrtool.generate(csrtool.parse_request(base_request(**overrides)))


def pem_to_b64der(pem):
    return re.sub(r"-----[A-Z ]+-----|\s+", "", pem)


class PfxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entry = gen(keyType="ecp256")
        cls.leaf, cls.inter, cls.root = make_ca_chain(cls.entry["csr"])

    def build(self, **overrides):
        data = {"key": self.entry["key"], "cert": self.leaf, "chain": [self.inter],
                "password": "secreto-pfx", "profile": "modern"}
        data.update(overrides)
        return pfxtool.build_pfx(data)

    def load(self, res, password=b"secreto-pfx"):
        return pkcs12.load_pkcs12(base64.b64decode(res["pfx"]), password)

    def test_modern_pfx_roundtrip(self):
        res = self.build()
        self.assertEqual(res["filename"], "www.ejemplo.es.pfx")
        p12 = self.load(res)
        self.assertEqual(p12.cert.friendly_name, b"www.ejemplo.es")
        self.assertEqual(len(p12.additional_certs), 1)
        key = serialization.load_pem_private_key(self.entry["key"].encode(), None)
        self.assertEqual(p12.key.private_numbers(), key.private_numbers())
        info = openssl("pkcs12", "-in", "/dev/stdin", "-info", "-noout", "-passin", "pass:secreto-pfx",
                       stdin=base64.b64decode(res["pfx"]))
        text = (info.stdout + info.stderr).decode()
        self.assertEqual(info.returncode, 0, text)
        self.assertIn("AES-256-CBC", text)
        self.assertIn("MAC: sha256", text)
        self.assertEqual([c["level"] for c in res["checks"]].count("error"), 0)
        self.assertFalse(res["keyWasEncrypted"])

    def test_legacy_profile(self):
        res = self.build(profile="legacy", extension="p12", friendlyName="Mi servidor")
        self.assertEqual(res["filename"], "mi_servidor.p12")
        self.assertEqual(self.load(res).cert.friendly_name, b"Mi servidor")
        info = openssl("pkcs12", "-in", "/dev/stdin", "-info", "-noout", "-passin", "pass:secreto-pfx",
                       stdin=base64.b64decode(res["pfx"]))
        text = (info.stdout + info.stderr).decode()
        self.assertIn("TripleDES", text)
        self.assertIn("MAC: sha1", text)

    def test_wrong_pfx_password_fails_to_open(self):
        with self.assertRaises(ValueError):
            self.load(self.build(), b"otra")

    def test_chain_ordering_dedup_and_fullchain(self):
        # fullchain.pem (hoja + intermedia + raíz) en un único campo, desordenada y con duplicados.
        res = self.build(cert=self.root + self.leaf + self.inter, chain=[self.inter, self.leaf])
        self.assertEqual([c["cn"] for c in res["chain"]], ["Intermedia de prueba", "Raiz de prueba"])
        self.assertEqual(res["leaf"]["cn"], "www.ejemplo.es")
        self.assertEqual(len(self.load(res).additional_certs), 2)

    def test_unrelated_cert_is_discarded(self):
        other = gen(keyType="ecp256")
        _, foreign_inter, _ = make_ca_chain(other["csr"])
        res = self.build(chain=[self.inter, foreign_inter])
        self.assertEqual(len(res["chain"]), 1)
        self.assertTrue(any("Descartado" in c["message"] for c in res["checks"]))

    def test_without_chain_and_missing_intermediate_warning(self):
        res = self.build(chain=[])
        self.assertTrue(any(c["level"] == "warn" and "intermedio" in c["message"] for c in res["checks"]))
        res = self.build(includeChain=False)
        self.assertEqual(res["chain"], [])
        self.assertEqual(self.load(res).additional_certs, [])

    def test_pkcs7_chain_and_der_inputs(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import pkcs7
        certs = [x509.load_pem_x509_certificate(c.encode()) for c in (self.inter, self.root)]
        p7b_pem = pkcs7.serialize_certificates(certs, serialization.Encoding.PEM).decode()
        p7b_der = base64.b64encode(pkcs7.serialize_certificates(certs, serialization.Encoding.DER)).decode()
        for chain in (p7b_pem, p7b_der):
            with self.subTest(chain=chain[:20]):
                self.assertEqual(len(self.build(chain=[chain])["chain"]), 2)
        # Certificado y clave en DER (Base64, como los envía el navegador al subir un fichero binario).
        key = serialization.load_pem_private_key(self.entry["key"].encode(), None)
        key_der = base64.b64encode(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption())).decode()
        res = self.build(key=key_der, cert=pem_to_b64der(self.leaf))
        self.assertEqual(res["leaf"]["cn"], "www.ejemplo.es")
        # Etiquetas PEM que no coinciden con el contenido: PKCS#7 como CERTIFICATE, RSA tradicional como PRIVATE KEY.
        p7_as_cert = "-----BEGIN CERTIFICATE-----\n" + p7b_der + "\n-----END CERTIFICATE-----\n"
        self.assertEqual(len(self.build(chain=[p7_as_cert])["chain"]), 2)
        rsa_entry = gen(keyType="rsa2048", keyFormat="traditional")
        rsa_leaf, rsa_inter, _ = make_ca_chain(rsa_entry["csr"])
        mislabeled = rsa_entry["key"].replace("RSA PRIVATE KEY", "PRIVATE KEY")
        res = pfxtool.build_pfx({"key": mislabeled, "cert": rsa_leaf, "chain": rsa_inter, "password": "abcd"})
        self.assertIn("RSA 2048", res["checks"][0]["message"])

    def test_encrypted_and_traditional_keys(self):
        for fmt in ("pkcs8", "traditional"):
            with self.subTest(fmt=fmt):
                entry = gen(keyType="rsa2048", cipher="aes256", passphrase="clave-key", keyFormat=fmt)
                leaf, inter, _ = make_ca_chain(entry["csr"])
                data = {"key": entry["key"], "cert": leaf, "chain": inter, "password": "secreto-pfx"}
                with self.assertRaisesRegex(csrtool.CsrError, "cifrada"):
                    pfxtool.build_pfx(data)
                with self.assertRaisesRegex(csrtool.CsrError, "no es correcta"):
                    pfxtool.build_pfx(dict(data, keyPassword="mala"))
                res = pfxtool.build_pfx(dict(data, keyPassword="clave-key"))
                self.assertTrue(res["keyWasEncrypted"])
                self.assertIn("RSA 2048", res["checks"][0]["message"])
        # Con una clave sin cifrar, una contraseña de clave sobrante se ignora.
        self.build(keyPassword="sobra")

    def test_key_does_not_match_certificate(self):
        other = gen(keyType="ecp256")
        with self.assertRaisesRegex(csrtool.CsrError, "no corresponde"):
            self.build(key=other["key"])

    def test_expired_certificate_flagged(self):
        leaf, inter, _ = make_ca_chain(self.entry["csr"], leaf_days=-1)
        res = self.build(cert=leaf, chain=[inter])
        self.assertTrue(res["leaf"]["expired"])
        self.assertTrue(any(c["level"] == "error" and "CADUC" in c["message"] for c in res["checks"]))
        leaf, inter, _ = make_ca_chain(self.entry["csr"], leaf_days=10)
        res = self.build(cert=leaf, chain=[inter])
        self.assertTrue(any(c["level"] == "warn" and "caduca en" in c["message"] for c in res["checks"]))

    def test_rejections(self):
        cases = [
            ({"password": ""}, "obligatoria"),
            ({"password": "abc"}, "entre 4"),
            ({"password": "abcd\x00"}, "no permitidos"),
            ({"profile": "rc2"}, "Perfil"),
            ({"extension": "exe"}, "Extensión"),
            ({"friendlyName": "x" * 65}, "Nombre descriptivo"),
            ({"key": ""}, "Falta la clave"),
            ({"key": self.leaf}, "certificado"),
            ({"key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}, "no es válida"),
            ({"key": self.entry["key"] + self.entry["key"]}, "más de una"),
            ({"cert": ""}, "Falta el certificado"),
            ({"cert": self.entry["csr"]}, "CSR"),
            ({"cert": self.entry["key"]}, "clave privada"),
            ({"cert": "¿esto qué es?"}, "formato no reconocido"),
            ({"cert": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"}, "no es válido"),
            ({"cert": "x" * (pfxtool.MAX_CERT_INPUT + 1)}, "demasiado grande"),
            ({"chain": [self.inter] * (pfxtool.MAX_CERTS + 1)}, "no válida"),
            ({"chain": {"a": 1}}, "no válida"),
        ]
        for overrides, message in cases:
            with self.subTest(overrides=str(overrides)[:60]):
                with self.assertRaisesRegex(csrtool.CsrError, message):
                    self.build(**overrides)
        with self.assertRaises(csrtool.CsrError):
            pfxtool.build_pfx([])

    def test_error_messages_do_not_echo_input(self):
        secret = "SECRETO-NO-REPETIR"
        for overrides in ({"cert": secret}, {"key": secret}, {"password": secret + "\x01"}):
            with self.subTest(overrides=overrides):
                with self.assertRaises(csrtool.CsrError) as ctx:
                    self.build(**overrides)
                self.assertNotIn(secret, str(ctx.exception))

    def test_nothing_written_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = {k: os.environ.get(k) for k in ("TMPDIR", "TMP", "TEMP")}
            try:
                for k in old:
                    os.environ[k] = tmp
                tempfile.tempdir = None
                self.build()
                self.build(profile="legacy")
                self.assertEqual(os.listdir(tmp), [])
            finally:
                for k, v in old.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
                tempfile.tempdir = None


if __name__ == "__main__":
    unittest.main()
