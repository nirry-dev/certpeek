"""End-to-end: run certpeek against a local TLS server using a self-signed cert.

Exercises the real path — fetch an untrusted certificate, decode it, and run the
separate validating connection — with no network, using the fixture cert.
"""

import os
import socket
import ssl
import threading
import unittest

from certpeek import inspect

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
CERT = os.path.join(FIXTURES, "cert.pem")
KEY = os.path.join(FIXTURES, "key.pem")


class TlsServer:
    def __init__(self):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(CERT, KEY)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            try:
                tls = self.ctx.wrap_socket(conn, server_side=True)
                try:
                    tls.recv(1)
                finally:
                    tls.close()
            except OSError:  # a client that aborts the handshake (e.g. the validating probe)
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass


class TestIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = TlsServer()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_inspects_a_self_signed_cert(self):
        r = inspect("127.0.0.1", self.server.port, server_name="certpeek.test", timeout=5)
        self.assertTrue(r.connected)
        self.assertIsNone(r.error)
        self.assertEqual(r.subject_cn, "certpeek.test")
        self.assertIn("certpeek.test", r.sans)
        self.assertTrue(r.self_signed)
        self.assertFalse(r.trusted)
        self.assertIn("self-signed", r.flags)
        self.assertGreater(r.days_left, 3000)  # issued for ~3650 days
        self.assertFalse(r.ok)

    def test_connection_error(self):
        r = inspect("127.0.0.1", 1, timeout=3)  # nothing listening on port 1
        self.assertFalse(r.connected)
        self.assertIsNotNone(r.error)
        self.assertFalse(r.ok)


if __name__ == "__main__":
    unittest.main()
