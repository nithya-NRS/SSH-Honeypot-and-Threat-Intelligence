from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import requests
import getpass
import urllib3
import os

app = Flask(__name__)
CORS(app)

# ==========================================
# PROJECT PATH
# ==========================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

# ==========================================
# SPLUNK CONNECTION
# ==========================================

SPLUNK_HOST = "https://localhost:8089"

SPLUNK_USERNAME = input("Enter your Splunk username: ")

SPLUNK_PASSWORD = getpass.getpass(
    "Enter your Splunk password: "
)

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

# ==========================================
# SPLUNK QUERY FUNCTION
# ==========================================

def run_splunk_query(search):

    url = f"{SPLUNK_HOST}/services/search/jobs"

    data = {
        "search": f"search {search}",
        "output_mode": "json",
        "exec_mode": "oneshot"
    }

    try:

        response = requests.post(
            url,
            auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
            data=data,
            verify=False,
            timeout=30
        )

        if response.status_code != 200:

            print("\n========== SPLUNK ERROR ==========")
            print("Status Code:", response.status_code)
            print("Response:")
            print(response.text)
            print("==================================\n")

        response.raise_for_status()

        result = response.json()

        return result

    except requests.exceptions.RequestException as e:

        print("\n========== SPLUNK CONNECTION ERROR ==========")
        print(e)
        print("=============================================\n")

        return {
            "results": [],
            "error": str(e)
        }

    except Exception as e:

        print("\n========== ERROR ==========")
        print(e)
        print("===========================\n")

        return {
            "results": [],
            "error": str(e)
        }


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/")
def dashboard():

    return send_from_directory(
        BASE_DIR,
        "index.html"
    )


# ==========================================
# STATIC FILES
# ==========================================

@app.route("/<path:filename>")
def static_files(filename):

    return send_from_directory(
        BASE_DIR,
        filename
    )


# ==========================================
# TOTAL EVENTS
# ==========================================

@app.route("/api/total-events")
def total_events():

    result = run_splunk_query(
        'index=main sourcetype=custom_honeypot '
        '| stats count as total_events'
    )

    return jsonify(result)


# ==========================================
# SOURCE IPs
# ==========================================

@app.route("/api/source-ips")
def source_ips():

    result = run_splunk_query(
        'index=main sourcetype=custom_honeypot '
        '| stats count by src_ip '
        '| sort - count'
    )

    return jsonify(result)


# ==========================================
# SSH SESSIONS
# ==========================================

@app.route("/api/ssh-sessions")
def ssh_sessions():

    result = run_splunk_query(
        'index=main sourcetype=custom_honeypot '
        'event_type="connection" '
        '| stats dc(session) as ssh_sessions'
    )

    return jsonify(result)


# ==========================================
# COMMAND ACTIVITY
# ==========================================

@app.route("/api/commands")
def commands():

    result = run_splunk_query(
        'index=main sourcetype=custom_honeypot '
        'event_type="command" '
        '| table timestamp session src_ip username command mitre_technique'
    )

    return jsonify(result)


# ==========================================
# SUSPICIOUS COMMANDS
# ==========================================

@app.route("/api/suspicious-commands")
def suspicious_commands():

    result = run_splunk_query(
        'index=main sourcetype=custom_honeypot '
        'event_type="command" '
        'mitre_technique=* '
        '| table timestamp session src_ip username command mitre_technique'
    )

    return jsonify(result)


# ==========================================
# ATTACK TIMELINE
# ==========================================

@app.route("/api/attack-timeline")
def attack_timeline():

    result = run_splunk_query(
        'index=main sourcetype=custom_honeypot '
        '| timechart span=1h count as events'
    )

    return jsonify(result)


# ==========================================
# EVENT TYPE DISTRIBUTION
# ==========================================

@app.route("/api/event-types")
def event_types():

    result = run_splunk_query(
        'index=main sourcetype=custom_honeypot '
        '| stats count by event_type '
        '| sort - count'
    )

    return jsonify(result)


# ==========================================
# MITRE ATT&CK DATA
# ==========================================

@app.route("/api/mitre")
def mitre():

    result = run_splunk_query(
        'index=main sourcetype=custom_honeypot '
        'mitre_technique=* '
        '| stats count by mitre_technique '
        '| sort - count'
    )

    return jsonify(result)


# ==========================================
# TEST SPLUNK CONNECTION
# ==========================================

@app.route("/api/test")
def test_connection():

    result = run_splunk_query(
        'index=main sourcetype=custom_honeypot '
        '| stats count as total_events'
    )

    return jsonify({
        "status": "success",
        "message": "Splunk connection is working",
        "data": result
    })


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    print()
    print("========================================")
    print("       SSH HONEYPOT SIEM")
    print("========================================")
    print()
    print("Dashboard:")
    print("http://127.0.0.1:5000")
    print()
    print("Test API:")
    print("http://127.0.0.1:5000/api/test")
    print()
    print("Splunk:")
    print("Connected through REST API")
    print()
    print("Custom Honeypot:")
    print("Python SSH Honeypot")
    print()
    print("========================================")
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )