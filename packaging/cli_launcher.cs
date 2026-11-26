// panoptes-cli.exe - terminal launcher for the ready-to-run Windows download.
// Runs the Python runtime shipped next to it (runtime\python.exe -m panoptes) in the current console and
// passes every argument through, so `panoptes-cli search jdoe42` works like the `panoptes` command.
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

[assembly: System.Reflection.AssemblyTitle("Panoptes CLI")]
[assembly: System.Reflection.AssemblyProduct("Panoptes OSINT")]
[assembly: System.Reflection.AssemblyDescription("Panoptes terminal launcher")]
[assembly: System.Reflection.AssemblyVersion("1.0.1.0")]

static class CliLauncher
{
    // Windows command-line quoting (the rules CommandLineToArgvW and the C runtime use).
    static string Quote(string a)
    {
        if (a.Length > 0 && a.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) return a;
        var sb = new StringBuilder("\"");
        int slashes = 0;
        foreach (char c in a)
        {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { sb.Append('\\', slashes * 2 + 1); sb.Append('"'); }
            else { sb.Append('\\', slashes); sb.Append(c); }
            slashes = 0;
        }
        sb.Append('\\', slashes * 2);
        sb.Append('"');
        return sb.ToString();
    }

    static int Main(string[] args)
    {
        string here = AppDomain.CurrentDomain.BaseDirectory;
        string python = Path.Combine(here, "runtime", "python.exe");
        if (!File.Exists(python))
        {
            Console.Error.WriteLine("Panoptes runtime not found next to panoptes-cli.exe. Download Panoptes again.");
            return 1;
        }
        var cmd = new StringBuilder("-m panoptes");
        foreach (string a in args) { cmd.Append(' '); cmd.Append(Quote(a)); }
        var psi = new ProcessStartInfo(python, cmd.ToString()) { UseShellExecute = false };
        psi.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8";
        using (Process p = Process.Start(psi))
        {
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; };  // let Python handle Ctrl+C itself
            p.WaitForExit();
            return p.ExitCode;
        }
    }
}
