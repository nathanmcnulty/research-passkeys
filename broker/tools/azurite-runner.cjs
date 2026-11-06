// Azurite's process-message shutdown handler flushes its Loki database.
// Windows terminate() bypasses SIGINT and its five-second autosave interval.
const { fork } = require("node:child_process");
const readline = require("node:readline");
const child = fork(process.argv[2], process.argv.slice(3), {
  stdio: ["ignore", "inherit", "inherit", "ipc"], windowsHide: true
});
let stopping = false;
function stop() {
  if (stopping) return;
  stopping = true;
  child.send("shutdown", () => {
    if (child.connected) child.disconnect();
  });
  setTimeout(() => child.kill("SIGKILL"), 8000).unref();
}
const input = readline.createInterface({ input: process.stdin });
input.on("line", line => { if (line === "shutdown") stop(); });
input.on("close", stop);
child.on("error", () => process.exit(1));
child.on("exit", code => {
  input.removeAllListeners();
  input.close();
  process.exit(code ?? 1);
});
