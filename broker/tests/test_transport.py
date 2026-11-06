from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import unittest

from azure.core.credentials import AzureNamedKeyCredential
from kvpp_broker.errors import InvalidRequest, StorageUnavailable
from kvpp_broker.storage import AzureTableStore


@contextmanager
def failing_endpoint(mode):
    requests = []
    release = threading.Event()
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append(self.path)
            if mode == "timeout":
                release.wait(timeout=30)
            if mode != "server-error":
                self.close_connection = True
                return
            body = b'{"odata.error":{"code":"InternalError","message":{"value":"Synthetic failure"}}}'
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/brokerlocal", requests
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class AzureSdkTransportTests(unittest.TestCase):
    def assert_no_resend(self, mode):
        with failing_endpoint(mode) as (endpoint, requests):
            store = AzureTableStore.from_endpoint(endpoint, "Synthetic", AzureNamedKeyCredential("brokerlocal", "Yg=="), allow_local_emulator=True)
            try:
                started = time.monotonic()
                with self.assertRaises(StorageUnavailable):
                    store.commit("owner-fixture", {"owner": None}, {"owner": {"schema": 1, "kind": "owner", "revision": 1, "epoch": 0}})
                self.assertEqual(len(requests), 1, "the SDK must not resend an ambiguous POST")
                if mode == "timeout":
                    self.assertGreater(time.monotonic() - started, 10)
                    self.assertLess(time.monotonic() - started, 25)
            finally:
                store.client.close()

    def test_500_transaction_is_not_retried_by_sdk(self):
        self.assert_no_resend("server-error")

    def test_lost_transaction_response_is_not_retried_by_sdk(self):
        self.assert_no_resend("drop")

    def test_transaction_read_deadline_is_bounded(self):
        self.assert_no_resend("timeout")

    def test_http_storage_requires_explicit_loopback_emulator(self):
        for endpoint, emulator in [("http://attacker.invalid/account", True), ("http://127.0.0.1:10002/account", False),
                ("https:///missing-host", False), ("https://user@storage.invalid", False)]:
            with self.assertRaises(InvalidRequest):
                AzureTableStore.from_endpoint(endpoint, "Synthetic", None, allow_local_emulator=emulator)


if __name__ == "__main__":
    unittest.main()
