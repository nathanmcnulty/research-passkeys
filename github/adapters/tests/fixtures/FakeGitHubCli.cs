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
            Console.Out.Write("SYNTHETIC-CHILD-OUTPUT");
            Console.Out.Flush();
            Thread.Sleep(6000);
            return 0;
        }

        string mode = Environment.GetEnvironmentVariable("PASSKEY_TEST_CLI_MODE") ?? "record";
        if (mode == "no-read")
        {
            Thread.Sleep(6000);
            return 0;
        }

        string input = Console.In.ReadToEnd();
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
            ProcessStartInfo child = new ProcessStartInfo();
            child.FileName = Assembly.GetExecutingAssembly().Location;
            child.Arguments = "--fixture-hold-pipes";
            child.UseShellExecute = false;
            child.CreateNoWindow = true;
            // Default, non-redirected standard handles are inherited from this captured process.
            using (Process process = Process.Start(child))
            {
                try
                {
                    string pidFile = Environment.GetEnvironmentVariable("PASSKEY_TEST_CHILD_PID");
                    if (String.IsNullOrEmpty(pidFile)) throw new InvalidOperationException("Missing fixture child tracking path.");
                    File.WriteAllText(pidFile, process.Id + "\n" + process.StartTime.ToUniversalTime().Ticks + "\n");
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
        return 0;
    }
}
