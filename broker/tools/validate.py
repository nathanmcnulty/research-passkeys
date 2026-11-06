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
            process = None
            def stop():
                if process is None or process.poll() is not None:
                    return
                process.stdin.write("shutdown\n")
                process.stdin.flush()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                    raise RuntimeError("Local emulator did not flush and stop normally.")
                finally:
                    process.stdin.close()
                if process.returncode:
                    raise RuntimeError("Local emulator exited abnormally.")

            def start():
                nonlocal process
                process = subprocess.Popen(["node", str(root / "tools/azurite-runner.cjs"), str(script), "--tableHost", "127.0.0.1", "--tablePort", str(port),
                    "--location", directory, "--disableTelemetry", "--silent"], env=env, stdout=log, stderr=subprocess.STDOUT,
                    stdin=subprocess.PIPE, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
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

            try:
                start()
                test_env = {**os.environ, "KVPP_TABLE_EMULATOR_ENDPOINT": f"http://127.0.0.1:{port}/brokerlocal"}
                result = subprocess.call([sys.executable, "-m", "unittest", "discover", "-s", str(root / "tests"), "-v"], env=test_env)
                if result:
                    return result
                probe = str(root / "tools/restart_probe.py")
                fixture = str(Path(directory) / "restart-fixture.json")
                subprocess.run([sys.executable, probe, "prepare", fixture], env=test_env, check=True)
                stop()
                start()
                subprocess.run([sys.executable, probe, "verify", fixture], env=test_env, check=True)
                return 0
            finally:
                stop()


if __name__ == "__main__":
    sys.exit(main())
