# app.py
from flask import Flask, render_template, redirect, url_for, request, flash
import json
import os
import sys
import subprocess
import shutil
import getpass
from datetime import datetime
from sysinfo_script import gather_system_info
from browser_scan import parse_brave_history   # <-- Import your function

python_executable = sys.executable

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # For flash messages


@app.route("/")
def main():
    return render_template("main.html")


@app.route("/live-system-analysis")
def live_system_analysis():
    gather_system_info()
    with open("SysInfo.json", "r") as json_file:
        system_info = json.load(json_file)
    return render_template("system_info.html", system_info=system_info)


@app.route("/forensic-image-analysis", methods=["GET", "POST"])
def forensic_image_analysis():
    if request.method == "POST":
        image_path = request.form.get("image_path")

        if not image_path or not os.path.exists(image_path):
            flash("Invalid file path")
            return redirect(url_for('forensic_image_analysis'))

        try:
            result = subprocess.run(
                [python_executable, 'forensics_script.py', image_path],
                capture_output=True, text=True
            )

            print("Subprocess stdout:", result.stdout)
            print("Subprocess stderr:", result.stderr)
            print("Subprocess returncode:", result.returncode)

            if os.path.exists('forensics1.json'):
                with open("forensics1.json", "r") as json_file:
                    forensic_data = json.load(json_file)

                return render_template("forensics_info.html", system_info=forensic_data)
            else:
                flash("Error: Forensic data not generated.")
                return redirect(url_for('forensic_image_analysis'))

        except Exception as e:
            flash(f"An error occurred during analysis: {e}")
            return redirect(url_for('forensic_image_analysis'))

    return render_template("forensics.html")


# NEW ROUTE for Browser Scanning
@app.route("/browser-scanning")
def browser_scanning():
    try:
        scan_result = parse_brave_history(limit=100)

        # Save results to JSON
        with open("browser_scan.json", "w") as json_file:
            json.dump(scan_result, json_file, indent=4)

        return render_template("browser_scan.html", scan_data=scan_result)

    except Exception as e:
        flash(f"Browser scan failed: {e}")
        return redirect(url_for("main"))


if __name__ == "__main__":
    app.run(debug=False)
