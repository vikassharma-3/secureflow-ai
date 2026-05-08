# app/app.py  — intentionally vulnerable Flask app for demo
import sqlite3
import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# VULNERABILITY: Hardcoded secret (Gitleaks/Trufflehog will catch this)
SECRET_KEY = "super_secret_key_12345"
DB_PASSWORD = "admin123"

def get_db():
    conn = sqlite3.connect("users.db")
    return conn

@app.route("/user")
def get_user():
    # VULNERABILITY: SQL injection (Semgrep will catch this)
    username = request.args.get("username")
    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchall()
    return jsonify(result)

@app.route("/ping")
def ping():
    # VULNERABILITY: Command injection (Semgrep will catch this)
    host = request.args.get("host", "localhost")
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)