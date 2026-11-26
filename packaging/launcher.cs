// Panoptes.exe - a tiny native launcher for the desktop app.
// In the ready-to-run download it starts the Python runtime shipped next to it (runtime\pythonw.exe).
// In a source install it starts the installed Panoptes package with your own pythonw. Either way there is no
// self-extracting interpreter (what PyInstaller does), so antivirus ML heuristics have nothing to object to.
using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("Panoptes")]
[assembly: System.Reflection.AssemblyProduct("Panoptes OSINT")]
[assembly: System.Reflection.AssemblyDescription("Panoptes desktop app launcher")]
[assembly: System.Reflection.AssemblyVersion("1.0.1.0")]

static class Launcher
{
    const string BakedPython = "@@PYTHONW@@";
    const string Repo = "@@REPO@@";

    [STAThread]
    static void Main(string[] args)
    {
        string extra = string.Join(" ", Array.ConvertAll(args, a => "\"" + a.Replace("\"", "") + "\""));
        string here = AppDomain.CurrentDomain.BaseDirectory;
        string portable = Path.Combine(here, "runtime", "pythonw.exe");
        bool isPortable = File.Exists(portable);
        string workDir = isPortable ? here : (Directory.Exists(Repo) ? Repo : Environment.CurrentDirectory);
        string[] candidates = isPortable ? new[] { portable } : new[] { BakedPython, "pythonw.exe", "pyw.exe" };
        foreach (string exe in candidates)
        {
            try
            {
                if (exe.Length == 0 || exe.StartsWith("@@") || (exe.Contains("\\") && !File.Exists(exe))) continue;
                var psi = new ProcessStartInfo(exe, "-m panoptes.gui " + extra)
                {
                    UseShellExecute = false,
                    WorkingDirectory = workDir,
                };
                Process p = Process.Start(psi);
                // If Python starts but Panoptes can't import, it exits almost immediately - tell the user why.
                if (p != null && p.WaitForExit(5000) && p.ExitCode != 0)
                {
                    MessageBox.Show("Panoptes failed to start (exit code " + p.ExitCode + ").\n\n" +
                        (isPortable ? "Try downloading Panoptes again - the runtime folder may be incomplete.\n\n"
                                    : "Check that it's installed:\n    pip install -e \"" + Repo + "[all]\"\n\n") +
                        "Logs: %USERPROFILE%\\.panoptes\\logs", "Panoptes", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                return;
            }
            catch (Exception) { }
        }
        MessageBox.Show("Panoptes needs Python 3.11+ with the Panoptes package installed.\n\n" +
            "    pip install -e \"" + Repo + "[all]\"", "Panoptes", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
