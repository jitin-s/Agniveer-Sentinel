"""
AGNI-SHIELD
Mock Military Security Management System
================================================
INTENTIONALLY VULNERABLE - FOR LOCAL CRS TESTING ONLY

Suggested CRS detections:
1. Hardcoded credentials
2. Hardcoded secret/API key
3. SQL injection
4. Command injection
5. Path traversal
6. Insecure deserialization
7. Weak cryptography
8. Weak password hashing
9. Debug mode
10. Missing authentication
11. IDOR / broken access control
12. Unsafe file upload
13. SSRF
14. Sensitive information disclosure
15. Weak session configuration
16. XSS
17. Missing security headers
18. Insecure CORS
19. Logging sensitive information
20. Improper input validation
"""

from flask import Flask, request, jsonify, send_file
import sqlite3
import subprocess
import os
import pickle
import hashlib
import base64
import requests
import logging

app = Flask(__name__)

# ============================================================
# VULNERABILITY 1: Hardcoded military credentials
# ============================================================

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Army@12345"

COMMAND_CENTER_KEY = "IND-ARMY-SECRET-2026-AGNI"

# ============================================================
# VULNERABILITY 2: Debug mode enabled
# ============================================================

app.config["DEBUG"] = True

# ============================================================
# DATABASE
# ============================================================

DB = "military_mock.db"


def init_db():

    conn = sqlite3.connect(DB)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS personnel (
            id INTEGER PRIMARY KEY,
            name TEXT,
            rank TEXT,
            unit TEXT,
            clearance TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS missions (
            id INTEGER PRIMARY KEY,
            mission_name TEXT,
            location TEXT,
            classification TEXT,
            status TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO personnel
        VALUES (1, 'Arjun Singh', 'Major', 'Cyber Command', 'TOP_SECRET')
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO personnel
        VALUES (2, 'Ravi Kumar', 'Captain', 'Signals Unit', 'SECRET')
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO missions
        VALUES (
            1,
            'Operation Vajra Shield',
            'Northern Sector',
            'TOP_SECRET',
            'ACTIVE'
        )
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO users
        VALUES (
            1,
            'commander',
            'password123',
            'ADMIN'
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# VULNERABILITY 3: SQL Injection
# ============================================================

@app.route("/api/personnel")
def personnel_search():

    name = request.args.get("name", "")

    conn = sqlite3.connect(DB)

    cursor = conn.cursor()

    # INTENTIONALLY VULNERABLE
    query = f"""
        SELECT id, name, rank, unit, clearance
        FROM personnel
        WHERE name LIKE '%{name}%'
    """

    cursor.execute(query)

    rows = cursor.fetchall()

    conn.close()

    return jsonify(rows)


# ============================================================
# VULNERABILITY 4: IDOR / Broken Access Control
# ============================================================

@app.route("/api/mission/<int:mission_id>")
def mission(mission_id):

    conn = sqlite3.connect(DB)

    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM missions WHERE id = ?",
        (mission_id,)
    )

    result = cursor.fetchone()

    conn.close()

    # No authorization check.
    return jsonify(result)


# ============================================================
# VULNERABILITY 5: Command Injection
# ============================================================

@app.route("/api/network-check")
def network_check():

    target = request.args.get("target", "127.0.0.1")

    # INTENTIONALLY VULNERABLE
    command = "ping -c 1 " + target

    result = subprocess.getoutput(command)

    return jsonify({
        "target": target,
        "result": result
    })


# ============================================================
# VULNERABILITY 6: Path Traversal
# ============================================================

@app.route("/api/report")
def report():

    filename = request.args.get("file", "daily_report.txt")

    # INTENTIONALLY VULNERABLE
    filepath = os.path.join("reports", filename)

    try:

        return send_file(filepath)

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 404


# ============================================================
# VULNERABILITY 7: Unsafe Deserialization
# ============================================================

@app.route("/api/import", methods=["POST"])
def import_configuration():

    encoded = request.data

    try:

        decoded = base64.b64decode(encoded)

        # INTENTIONALLY UNSAFE
        configuration = pickle.loads(decoded)

        return jsonify({
            "status": "imported",
            "configuration": str(configuration)
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 400


# ============================================================
# VULNERABILITY 8: Weak Password Hashing
# ============================================================

@app.route("/api/login", methods=["POST"])
def login():

    username = request.form.get("username")
    password = request.form.get("password")

    # Weak MD5
    password_hash = hashlib.md5(
        password.encode()
    ).hexdigest()

    conn = sqlite3.connect(DB)

    cursor = conn.cursor()

    cursor.execute(
        f"""
        SELECT id, username, role
        FROM users
        WHERE username = '{username}'
        AND password = '{password_hash}'
        """
    )

    user = cursor.fetchone()

    conn.close()

    if user:

        return jsonify({
            "authenticated": True,
            "user": user
        })

    return jsonify({
        "authenticated": False
    }), 401


# ============================================================
# VULNERABILITY 9: SSRF
# ============================================================

@app.route("/api/fetch-intel")
def fetch_intel():

    url = request.args.get("url")

    try:

        response = requests.get(
            url,
            timeout=5
        )

        return jsonify({
            "status": response.status_code,
            "data": response.text
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        })


# ============================================================
# VULNERABILITY 10: Reflected XSS
# ============================================================

@app.route("/api/search")
def search():

    query = request.args.get("q", "")

    # Intentionally returning unsanitized input
    return f"""
    <html>
        <body>
            <h1>Military Intelligence Search</h1>

            <p>Search results for:
                {query}
            </p>
        </body>
    </html>
    """


# ============================================================
# VULNERABILITY 11: Sensitive information disclosure
# ============================================================

@app.route("/api/debug")
def debug_info():

    return jsonify({

        "database": DB,

        "admin_username": ADMIN_USERNAME,

        "admin_password": ADMIN_PASSWORD,

        "command_center_key": COMMAND_CENTER_KEY,

        "environment": dict(os.environ)

    })


# ============================================================
# VULNERABILITY 12: Arbitrary file upload
# ============================================================

@app.route("/api/upload", methods=["POST"])
def upload():

    uploaded_file = request.files.get("file")

    if not uploaded_file:

        return jsonify({
            "error": "No file"
        }), 400

    filename = uploaded_file.filename

    # No filename validation
    # No extension validation
    # No content validation

    save_path = os.path.join(
        "uploads",
        filename
    )

    os.makedirs(
        "uploads",
        exist_ok=True
    )

    uploaded_file.save(save_path)

    return jsonify({
        "uploaded": True,
        "path": save_path
    })


# ============================================================
# VULNERABILITY 13: Missing authentication
# ============================================================

@app.route("/api/top-secret")
def top_secret():

    return jsonify({

        "classification": "TOP_SECRET",

        "operation": "VAJRA_SHIELD",

        "status": "ACTIVE",

        "message":
            "This endpoint should require authentication."
    })


# ============================================================
# VULNERABILITY 14: Sensitive data in logs
# ============================================================

@app.route("/api/authenticate", methods=["POST"])
def authenticate():

    username = request.form.get("username")

    password = request.form.get("password")

    # DO NOT DO THIS IN REAL APPLICATIONS
    logging.warning(
        "Authentication attempt: username=%s password=%s",
        username,
        password
    )

    return jsonify({
        "status": "logged"
    })


# ============================================================
# VULNERABILITY 15: Weak authorization
# ============================================================

@app.route("/api/admin/delete/<int:personnel_id>",
           methods=["DELETE"])
def delete_personnel(personnel_id):

    # No authentication
    # No authorization

    conn = sqlite3.connect(DB)

    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM personnel WHERE id = ?",
        (personnel_id,)
    )

    conn.commit()

    conn.close()

    return jsonify({
        "deleted": personnel_id
    })


# ============================================================
# VULNERABILITY 16: Insecure CORS
# ============================================================

@app.after_request
def add_headers(response):

    response.headers["Access-Control-Allow-Origin"] = "*"

    # Missing many security headers intentionally

    return response


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/")
def index():

    return jsonify({

        "system": "AGNI-SHIELD",

        "organization":
            "Mock Indian Military Cyber Defense",

        "environment":
            "LOCAL TRAINING LAB",

        "warning":
            "INTENTIONALLY VULNERABLE",

        "crs_target":
            True

    })


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    init_db()

    os.makedirs(
        "reports",
        exist_ok=True
    )

    with open(
        "reports/daily_report.txt",
        "w"
    ) as f:

        f.write(
            "AGNI-SHIELD DAILY SECURITY REPORT\n"
        )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
