// Panoptes.exe - a tiny native launcher for the desktop app.
// It starts the installed Panoptes package with pythonw (no console window). Because it doesn't bundle or
// self-extract an interpreter (what PyInstaller does), antivirus ML heuristics have nothing to object to, and
// it always runs the current code - no rebuild needed after updates.
using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("Panoptes")]
[assembly: System.Reflection.AssemblyProduct("Panoptes OSINT")]
[assembly: System.Reflection.AssemblyDescription("Panoptes desktop app launcher")]
[assembly: System.Reflection.AssemblyVersion("1.0.0.0")]

static class Launcher
{
    const string BakedPython = "@@PYTHONW@@";
    const string Repo = "@@REPO@@";

    [STAThread]
    static void Main(string[] args)
    {
        string extra = string.Join(" ", Array.ConvertAll(args, a => "\"" + a.Replace("\"", "") + "\""));
        string[] candidates = { BakedPython, "pythonw.exe", "pyw.exe" };
        foreach (string exe in candidates)
        {
            try
            {
                if (exe.Contains("\\") && !File.Exists(exe)) continue;
                var psi = new ProcessStartInfo(exe, "-m panoptes.gui " + extra)
                {
                    UseShellExecute = false,
                    WorkingDirectory = Directory.Exists(Repo) ? Repo : Environment.CurrentDirectory,
                };
                Process p = Process.Start(psi);
                // If Python starts but Panoptes can't import, it exits almost immediately - tell the user why.
                if (p != null && p.WaitForExit(5000) && p.ExitCode != 0)
                {
                    MessageBox.Show("Panoptes failed to start (exit code " + p.ExitCode + ").\n\n" +
                        "Check that it's installed:\n    pip install -e \"" + Repo + "[all]\"\n\n" +
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
