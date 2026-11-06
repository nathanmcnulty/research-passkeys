from contextlib import contextmanager
from socketserver import ThreadingMixIn
import threading
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler, make_server


class ThreadedServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class SilentHandler(WSGIRequestHandler):
    def log_message(self, *args):
        pass


@contextmanager
def api_server(application):
    # Synthetic access tokens and loopback transport only; no deployment helper.
    with make_server("127.0.0.1", 0, application, server_class=ThreadedServer, handler_class=SilentHandler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            thread.join(timeout=10)
