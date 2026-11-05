"""Tests unitarios del cifrado de comunicaciones (claves efímeras de un solo uso)."""

import gc
import sys
import unittest

from tests.helpers import e2e_open, e2e_seal

import e2e


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class KeyStoreTests(unittest.TestCase):
    def test_roundtrip(self):
        store = e2e.KeyStore()
        envelope, res_key = e2e_seal(store.new_key(), "/api/x", {"hola": "mundo ñ"})
        data, channel = e2e.open_request(store, envelope, "/api/x")
        self.assertEqual(data, {"hola": "mundo ñ"})
        reply = channel.seal({"ok": True})
        self.assertEqual(e2e_open(res_key, "/api/x", reply), {"ok": True})
        channel.close()
        with self.assertRaises(e2e.E2EError):
            channel.seal({"otra": 1})

    def test_single_use(self):
        store = e2e.KeyStore()
        envelope, _ = e2e_seal(store.new_key(), "/p", {})
        e2e.open_request(store, envelope, "/p")
        self.assertEqual(len(store), 0)
        with self.assertRaises(e2e.E2EError):
            e2e.open_request(store, envelope, "/p")

    def test_key_removed_even_if_decryption_fails(self):
        store = e2e.KeyStore()
        envelope, _ = e2e_seal(store.new_key(), "/p", {})
        envelope["iv"] = "AAAAAAAAAAAAAAAA"
        with self.assertRaises(e2e.E2EError):
            e2e.open_request(store, envelope, "/p")
        self.assertEqual(len(store), 0)

    def test_private_key_object_is_freed(self):
        store = e2e.KeyStore()
        info = store.new_key()
        kid = next(iter(store._keys))
        private_key = store._keys[kid][0]
        held = sys.getrefcount(private_key)
        envelope, _ = e2e_seal(info, "/p", {})
        data, channel = e2e.open_request(store, envelope, "/p")
        channel.close()
        del data, channel
        gc.collect()
        # Solo queda la referencia de este test: el servidor ya no la conserva
        # y, al soltarla, OpenSSL libera (y borra) el material de la clave.
        self.assertEqual(sys.getrefcount(private_key), held - 1)

    def test_expiry(self):
        clock = FakeClock()
        store = e2e.KeyStore(ttl=60, clock=clock)
        envelope, _ = e2e_seal(store.new_key(), "/p", {})
        clock.now += 61
        with self.assertRaises(e2e.E2EError):
            e2e.open_request(store, envelope, "/p")
        store.new_key()
        clock.now += 61
        store.new_key()  # al crear otra se purgan las caducadas
        self.assertEqual(len(store), 1)

    def test_limit_evicts_oldest(self):
        store = e2e.KeyStore(max_keys=3)
        first = store.new_key()
        for _ in range(3):
            store.new_key()
        self.assertEqual(len(store), 3)
        envelope, _ = e2e_seal(first, "/p", {})
        with self.assertRaises(e2e.E2EError):
            e2e.open_request(store, envelope, "/p")

    def test_wrong_path_rejected(self):
        store = e2e.KeyStore()
        envelope, _ = e2e_seal(store.new_key(), "/api/decode", {})
        with self.assertRaises(e2e.E2EError):
            e2e.open_request(store, envelope, "/api/generate")

    def test_malformed(self):
        store = e2e.KeyStore()
        good, _ = e2e_seal(store.new_key(), "/p", {})
        for bad in (None, [], {}, {"v": 2}, dict(good, kid="!!"), dict(good, epk="AAAA"),
                    dict(good, kid="AAAAAAAAAAAAAAAAAAAAAA==")):
            with self.subTest(bad=str(bad)[:50]):
                with self.assertRaises(e2e.E2EError):
                    e2e.open_request(store, bad, "/p")

    def test_invalid_client_point(self):
        store = e2e.KeyStore()
        envelope, _ = e2e_seal(store.new_key(), "/p", {})
        import base64
        envelope["epk"] = base64.b64encode(b"\x04" + b"\x01" * 64).decode()  # no está en la curva
        with self.assertRaises(e2e.E2EError):
            e2e.open_request(store, envelope, "/p")


if __name__ == "__main__":
    unittest.main()
