from database import get_connection, save_event, save_alert, initialise_database

initialise_database()

events = [
    {
        "event_id": "EVT-1",
        "user": "Sarah",
        "country": "Romania",
        "hour": 2,
        "device": "Windows PC",
        "files_accessed": 638,
        "timestamp": "2026-09-11 02:14:00"
    },
    {
        "event_id": "EVT-2",
        "user": "Sarah",
        "country": "United Kingdom",
        "hour": 10,
        "device": "MacBook",
        "files_accessed": 18,
        "timestamp": "2026-09-11 10:05:00"
    },
    {
        "event_id": "EVT-3",
        "user": "John",
        "country": "United Kingdom",
        "hour": 9,
        "device": "Windows PC",
        "files_accessed": 30,
        "timestamp": "2026-09-11 09:12:00"
    },
    {
        "event_id": "EVT-4",
        "user": "John",
        "country": "Germany",
        "hour": 23,
        "device": "MacBook",
        "files_accessed": 400,
        "timestamp": "2026-09-11 23:08:00"
    }
]


baselines = {
    "Sarah": {
        "country": "United Kingdom",
        "start_hour": 8,
        "end_hour": 18,
        "device": "MacBook",
        "usual_files": 20
    },

    "John": {
        "country": "United Kingdom",
        "start_hour": 7,
        "end_hour": 16,
        "device": "Windows PC",
        "usual_files": 35
    }
}


def analyse_login(event, baseline):
    risk_score = 0
    risk_factors = []

    if event["country"] != baseline["country"]:
        risk_score += 30
        risk_factors.append("Unusual country")

    if event["hour"] < baseline["start_hour"] or event["hour"] > baseline["end_hour"]:
        risk_score += 20
        risk_factors.append("Outside normal working hours")

    if event["device"] != baseline["device"]:
        risk_score += 20
        risk_factors.append("Unusual device")

    if event["files_accessed"] > baseline["usual_files"] * 5:
        risk_score += 30
        risk_factors.append("Unusual file access volume")

    result = {
    "detection_name": "Possible Account Compromise",
    "risk_score": risk_score,
    "risk_factors": risk_factors
}


    return result

def get_severity(risk_score):

    if risk_score >= 70:
        return "CRITICAL"

    elif risk_score >= 40:
        return "SUSPICIOUS"

    else:
        return "NORMAL"

def create_alert(event, detection_name, risk_score, risk_factors, severity):
    alert = {
        "event_id": event["event_id"],
        "user": event["user"],
        "timestamp": event["timestamp"],
        "detection_name": detection_name,
        "risk_score": risk_score,
        "risk_factors": risk_factors,
        "severity": severity,
        "status": "OPEN",
    }
    return alert

alerts = []
alert_counter = 1

connection = get_connection()
cursor = connection.cursor()

for event in events:

    save_event(cursor, event)

    user = event["user"]
    baseline = baselines[user]

    result = analyse_login(event, baseline)
    detection_name = result["detection_name"]
    risk_score = result["risk_score"]
    risk_factors = result["risk_factors"]

    severity = get_severity(risk_score)

    if risk_score >= 40:
        alert = create_alert(
                event,
                detection_name,
                risk_score,
                risk_factors,
                severity
            )    

        alert["alert_id"] = f"ALT-{alert_counter}"
        alert_counter += 1

        alerts.append(alert)

        save_alert(cursor, alert)


    print("--------------------")
    print(f'User: {event["user"]}')
    print(f'Country: {event["country"]}')
    print(f'Hour: {event["hour"]}')
    print(f'Device: {event["device"]}')
    print(f'Files Accessed: {event["files_accessed"]}')
    print(f"Risk Score: {risk_score}/100")

    print("Risk Factors:")

    for factor in risk_factors:
        print(f"- {factor}")

    print(f"Severity: {severity}")


connection.commit()
connection.close()


print("====================")
print("SECURITY ALERTS")
print("====================")

for alert in alerts:
    print(f'Alert ID: {alert["alert_id"]}')
    print(f'Event ID: {alert["event_id"]}')
    print(f'Timestamp: {alert["timestamp"]}')
    print(f'User: {alert["user"]}')
    print(f'Detection: {alert["detection_name"]}')
    print(f'Severity: {alert["severity"]}')
    print(f'Status: {alert["status"]}')
    print(f'Risk Score: {alert["risk_score"]}/100')
    print("Risk Factors:")

    for factor in alert["risk_factors"]:
        print(f"- {factor}")

    print("--------------------")