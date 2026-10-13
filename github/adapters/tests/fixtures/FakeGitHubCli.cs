// Offline process fixture. No GitHub, authentication, networking, or real credentials.
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;

public static class FakeGitHubCli
{
    public static int Main(string[] args)
    {
        if (Environment.GetEnvironmentVariable("POWERSHELL_TELEMETRY_OPTOUT") != "1" ||
            Environment.GetEnvironmentVariable("DOTNET_CLI_TELEMETRY_OPTOUT") != "1")
            return 98;

        if (args.Length == 1 && args[0] == "--fixture-hold-pipes")
        {
            string pidFile = Environment.GetEnvironmentVariable("PASSKEY_TEST_CHILD_PID");
            if (String.IsNullOrEmpty(pidFile)) return 95;
            Console.Out.Write("SYNTHETIC-CHILD-OUTPUT");
            Console.Out.Flush();
            File.WriteAllText(pidFile + ".ready", Process.GetCurrentProcess().Id + "\n");
            Thread.Sleep(12000);
            return 0;
        }

        string mode = Environment.GetEnvironmentVariable("PASSKEY_TEST_CLI_MODE") ?? "record";
        if (mode == "no-read")
        {
            Thread.Sleep(6000);
            return 0;
        }

        string input = Console.In.ReadToEnd();
        if (mode.StartsWith("http-"))
        {
            string status = mode.Substring(5);
            Console.Out.Write("HTTP/2.0 " + status + " Fixture\r\nSYNTHETIC-HEADER: do-not-leak\r\n\r\n");
            Console.Error.Write("SYNTHETIC-SECRET-ERROR");
            return 1;
        }
        if (mode == "success")
        {
            if (input != "SYNTHETIC-INPUT") return 7;
            Console.Out.Write("SYNTHETIC-STDOUT");
            Console.Error.Write("SYNTHETIC-STDERR");
            return 0;
        }
        if (mode == "failure")
        {
            Console.Error.Write("SYNTHETIC-STDERR");
            return 9;
        }
        if (mode == "inherited-pipes")
        {
            // Make a fresh per-stage drain deadline observably different from the original deadline.
            Thread.Sleep(2000);
            ProcessStartInfo child = new ProcessStartInfo();
            child.FileName = Assembly.GetExecutingAssembly().Location;
            child.Arguments = "--fixture-hold-pipes";
            child.UseShellExecute = false;
            child.CreateNoWindow = true;
            string pidFile = Environment.GetEnvironmentVariable("PASSKEY_TEST_CHILD_PID");
            if (String.IsNullOrEmpty(pidFile)) return 95;
            // Default, non-redirected standard handles are inherited from this captured process.
            using (Process process = Process.Start(child))
            {
                try
                {
                    // This identity/completion marker is written immediately before normal parent exit.
                    File.WriteAllText(pidFile, process.Id + "\n" + process.StartTime.ToUniversalTime().Ticks + "\n" +
                        Process.GetCurrentProcess().Id + "\n");
                }
                catch
                {
                    if (!process.HasExited) process.Kill();
                    process.WaitForExit();
                    throw;
                }
            }
            return 0;
        }
        if (mode != "record") return 97;

        string log = Environment.GetEnvironmentVariable("PASSKEY_TEST_CALLS");
        if (String.IsNullOrEmpty(log)) return 96;
        // Only the public command-line tail is recorded. Stdin is deliberately discarded.
        File.AppendAllText(log, String.Join(" ", args) + "\n");
        if (args.Length > 0 && args[0] == "api") Console.Out.Write("HTTP/2.0 200 OK\r\n\r\n");
        return 0;
    }
}
