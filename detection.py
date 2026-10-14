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

    return {
        "detection_name": "Possible Account Compromise",
        "risk_score": risk_score,
        "risk_factors": risk_factors
    }


def get_severity(risk_score):
    if risk_score >= 70:
        return "CRITICAL"
    elif risk_score >= 40:
        return "SUSPICIOUS"
    else:
        return "NORMAL"