import os
import sqlite3
import shutil
import json
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Example malicious domains (expand this as needed)
MALICIOUS_DOMAINS = {
    "phishing.com": "Phishing site",
    "malware-test.com": "Malware distribution site",
    "scam-example.org": "Known scam domain",
    "badbank-login.net": "Credential harvesting site"
}

UNMALICOUS_DOMAINS = {
    "google.com",
}

def is_malicious(url):
    """Check if URL domain is in the malicious list or if it uses plain HTTP."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Rule 1: Check domain blacklist
        if domain in MALICIOUS_DOMAINS:
            return MALICIOUS_DOMAINS[domain]

        # Rule 2: Flag all non-HTTPS traffic
        if parsed.scheme == "http":
            return "Unencrypted HTTP connection (insecure)"
        
    except Exception:
        return None

    return None


def parse_brave_history(limit=50):
    user_profile = os.path.expanduser("~")
    history_path = os.path.join(
        user_profile,
        r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History"
    )

    if not os.path.exists(history_path):
        return {"error": "Brave history not found"}

    # Copy to temp file to avoid lock errors
    temp_path = "temp_brave_history.db"
    shutil.copy2(history_path, temp_path)

    conn = sqlite3.connect(temp_path)
    cursor = conn.cursor()

    # Brave uses Chrome time format: microseconds since 1601-01-01
    def chrome_time_to_datetime(chrome_time):
        if chrome_time:
            return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)
        return None

    cursor.execute(f"""
        SELECT urls.url, urls.title, urls.last_visit_time
        FROM urls
        ORDER BY last_visit_time DESC
        LIMIT {limit}
    """)

    history_data = []
    malicious_hits = []

    for url, title, last_visit_time in cursor.fetchall():
        visit_time = chrome_time_to_datetime(last_visit_time).isoformat()
        entry = {
            "url": url,
            "title": title,
            "last_visit": visit_time
        }
        history_data.append(entry)

        reason = is_malicious(url)
        if reason:
            malicious_hits.append({
                "url": url,
                "title": title,
                "last_visit": visit_time,
                "reason": reason
            })

    conn.close()
    os.remove(temp_path)

    result = {
        "browser": "Brave",
        "history_checked": len(history_data),
        "history": history_data
    }

    if malicious_hits:
        result["malicious_sites"] = malicious_hits
    else:
        result["message"] = "You didn't visit any malicious website!"

    return result

if __name__ == "__main__":
    brave_history = parse_brave_history(limit=100)
    print(json.dumps(brave_history, indent=4))
