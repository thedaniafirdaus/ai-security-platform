import sqlite3


def initialise_database():
    connection = sqlite3.connect("security.db")
    cursor = connection.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        event_id TEXT PRIMARY KEY,
        user TEXT,
        country TEXT,
        hour INTEGER,
        device TEXT,
        files_accessed INTEGER,
        timestamp TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        event_id TEXT,
        user TEXT,
        timestamp TEXT,
        detection_name TEXT,
        risk_score INTEGER,
        risk_factors TEXT,
        severity TEXT,
        status TEXT,
        FOREIGN KEY (event_id) REFERENCES events(event_id)
    )
    """)

    connection.commit()
    connection.close()


def get_connection():
    return sqlite3.connect("security.db")


def save_event(cursor, event):
    cursor.execute("""
    INSERT OR IGNORE INTO events
    (event_id, user, country, hour, device, files_accessed, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        event["event_id"],
        event["user"],
        event["country"],
        event["hour"],
        event["device"],
        event["files_accessed"],
        event["timestamp"]
    ))


def save_alert(cursor, alert):
    cursor.execute("""
    INSERT OR IGNORE INTO alerts
    (alert_id, event_id, user, timestamp, detection_name, risk_score, risk_factors, severity, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["alert_id"],
        alert["event_id"],
        alert["user"],
        alert["timestamp"],
        alert["detection_name"],
        alert["risk_score"],
        ", ".join(alert["risk_factors"]),
        alert["severity"],
        alert["status"]
    ))

def get_all_alerts():
    connection = get_connection()
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("SELECT * FROM alerts")

    rows = cursor.fetchall()

    alerts = []

    for row in rows:
        alerts.append(dict(row))

    connection.close()

    return alerts