
#!/usr/bin/env python3
"""
export_windows_hives.py

Saves Windows registry hives:
 - HKLM\SAM
 - HKLM\SECURITY
 - HKLM\SOFTWARE
 - HKLM\SYSTEM

Default output folder: %USERPROFILE%\Downloads\RegisFile

Requires Administrator privileges.
"""

import os
import sys
import subprocess
import shutil

def is_windows():
    return os.name == 'nt'

def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def relaunch_as_admin():
    import ctypes
    params = " ".join(['"{}"'.format(arg) for arg in sys.argv])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return True
    except Exception as e:
        print("Elevation failed:", e)
        return False

def safe_mkdir(path):
    os.makedirs(path, exist_ok=True)

def run_reg_save(key, dest_path):
    cmd = ["reg", "save", key, dest_path, "/y"]
    proc = subprocess.run(cmd, capture_output=True, text=True, shell=False)
    return proc.returncode, proc.stdout, proc.stderr

def try_copy_config_file(filename, dest_path):
    src = os.path.join(os.environ.get("SystemRoot", r"C:\\Windows"), "System32", "config", filename)
    if os.path.exists(src):
        try:
            shutil.copy2(src, dest_path)
            return True, None
        except Exception as e:
            return False, str(e)
    else:
        return False, "source file not found: " + src

def main():
    if not is_windows():
        print("This script only runs on Windows.")
        sys.exit(1)

    if not is_admin():
        print("Administrator privileges required. Attempting to relaunch with elevation...")
        if relaunch_as_admin():
            sys.exit(0)  # elevated instance will continue
        else:
            print("Could not elevate. Please run this script as Administrator.")
            sys.exit(1)

    # Default output folder: Downloads\RegisFile
    if len(sys.argv) >= 2:
        out_folder = sys.argv[1]
    else:
        downloads = os.path.join(os.path.expanduser("~"), "Downloads")
        out_folder = os.path.join(downloads, "RegisFile")

    # If RegisFile exists, remove it (overwrite behavior)
    if os.path.exists(out_folder):
        shutil.rmtree(out_folder)
    safe_mkdir(out_folder)

    print(f"Saving registry hives to: {out_folder}")

    hives = {
        "HKLM\\SAM": "SAM",
        "HKLM\\SECURITY": "SECURITY",
        "HKLM\\SOFTWARE": "SOFTWARE",
        "HKLM\\SYSTEM": "SYSTEM",
    }

    results = {}

    for regkey, fname in hives.items():
        destfile = os.path.join(out_folder, fname)  # no .hiv extension
        print(f"\nSaving {regkey} -> {destfile} ...")
        ret, out, err = run_reg_save(regkey, destfile)
        results[regkey] = (ret, out.strip(), err.strip())
        if ret == 0:
            print("  OK")
        else:
            print(f"  FAILED (code {ret})")
            if out:
                print("  stdout:", out.strip())
            if err:
                print("  stderr:", err.strip())

    # Optional: attempt to copy raw files
    print("\nAttempting to copy raw hive files from %SystemRoot%\\System32\\config (optional; may fail if locked):")
    for fname in ["SAM", "SECURITY", "SOFTWARE", "SYSTEM"]:
        dest = os.path.join(out_folder, fname + ".raw")
        ok, info = try_copy_config_file(fname, dest)
        if ok:
            print(f"  Copied {fname} to {dest}")
        else:
            print(f"  Could not copy {fname}: {info}")

    # Summary
    print("\nSummary:")
    for regkey, (ret, out, err) in results.items():
        status = "OK" if ret == 0 else "FAILED"
        print(f" - {regkey}: {status}")
    print("\nFinished. Hive files are inside RegisFile. Handle them securely!")

if __name__ == "__main__":
    main()

