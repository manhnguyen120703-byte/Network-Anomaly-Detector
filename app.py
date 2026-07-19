# app.py
from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3
import logging

app = Flask(__name__)
DB_NAME = "anomaly_detector.db"

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    conn = get_db_connection()
    total_reqs = conn.execute("SELECT COUNT(*) FROM tls_logs").fetchone()[0]
    total_warnings = conn.execute("SELECT COUNT(*) FROM tls_logs WHERE is_blocked = 1").fetchone()[0]
    blacklist = conn.execute("SELECT * FROM blacklist").fetchall()
    conn.close()
    return render_template('index.html', total_reqs=total_reqs, total_warnings=total_warnings, blacklist=blacklist)

@app.route('/api/logs')
def api_logs():
    conn = get_db_connection()
    logs = conn.execute("SELECT * FROM tls_logs ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    return jsonify([dict(row) for row in logs])

@app.route('/blacklist/add', methods=['POST'])
def add_blacklist():
    domain = request.form.get('domain', '').strip().lower()
    reason = request.form.get('reason', '').strip()
    if domain:
        conn = get_db_connection()
        conn.execute("INSERT OR REPLACE INTO blacklist (domain, reason) VALUES (?, ?)", (domain, reason))
        conn.commit()
        conn.close()
    return redirect(url_for('index'))

@app.route('/blacklist/delete/<domain>')
def delete_blacklist(domain):
    conn = get_db_connection()
    conn.execute("DELETE FROM blacklist WHERE domain = ?", (domain,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

def start_web():
    print("[+] Web Server: Đang chạy tại http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

if __name__ == "__main__":
    start_web()
