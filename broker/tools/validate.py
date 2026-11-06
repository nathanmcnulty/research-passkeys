"""Run every broker test against a fresh loopback-only disk-backed Azurite.

No Azure configuration or ambient cloud credentials are read. The short account
key is a public fixture, scoped to this disposable local emulator process.
"""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def main():
    root = Path(__file__).resolve().parents[1]
    script = root / "tools/node_modules/azurite/dist/src/table/main.js"
    if not script.is_file():
        raise SystemExit("Run npm ci --prefix broker/tools first.")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="kvpp-broker-azurite-") as directory:
        with open(Path(directory) / "emulator.log", "w+", encoding="utf-8") as log:
            env = {**os.environ, "AZURITE_ACCOUNTS": "brokerlocal:Yg=="}
            process = subprocess.Popen(["node", str(script), "--tableHost", "127.0.0.1", "--tablePort", str(port),
                "--location", directory, "--disableTelemetry", "--silent"], env=env, stdout=log, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            try:
                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None or time.monotonic() > deadline:
                        log.seek(0)
                        raise RuntimeError("Local emulator did not start: " + log.read())
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.1)
                env = {**os.environ, "KVPP_TABLE_EMULATOR_ENDPOINT": f"http://127.0.0.1:{port}/brokerlocal"}
                return subprocess.call([sys.executable, "-m", "unittest", "discover", "-s", str(root / "tests"), "-v"], env=env)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


if __name__ == "__main__":
    sys.exit(main())
