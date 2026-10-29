#!/usr/bin/env python3
from flask import Flask, render_template
import sqlite3

app = Flask(__name__)
DB_PATH = "/opt/monitor.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    conn = get_db()
    cur = conn.cursor()
    
    # Последние события
    cur.execute("""
        SELECT * FROM events
        ORDER BY id DESC
        LIMIT 100
    """)
    events = cur.fetchall()
    
    # Активные алерты (не критические)
    cur.execute("""
        SELECT * FROM alerts
        WHERE status='ACTIVE' AND severity != 'CRITICAL'
        ORDER BY id DESC
    """)
    alerts = cur.fetchall()
    
    # КРИТИЧЕСКИЕ алерты отдельно
    cur.execute("""
        SELECT * FROM alerts
        WHERE status='ACTIVE' AND severity='CRITICAL'
        ORDER BY id DESC
    """)
    critical_alerts = cur.fetchall()
    
    # Статистика событий
    cur.execute("SELECT COUNT(*) FROM events")
    total_events = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM events WHERE event_type='SSH_FAILED'")
    ssh_failed = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM events WHERE event_type='AUTH_FAILED'")
    auth_failed = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM alerts WHERE status='ACTIVE'")
    active_alerts = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM alerts WHERE status='ACTIVE' AND severity='CRITICAL'")
    critical_alerts_count = cur.fetchone()[0]
    
    conn.close()
    
    return render_template(
        "index.html",
        events=events,
        alerts=alerts,
        critical_alerts=critical_alerts,
        total_events=total_events,
        ssh_failed=ssh_failed,
        auth_failed=auth_failed,
        active_alerts=active_alerts,
        critical_alerts_count=critical_alerts_count
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)