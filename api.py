from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from database import get_all_alerts, get_connection, save_event, save_alert
from detection import baselines, analyse_login, get_severity


app = FastAPI()
class SecurityEvent(BaseModel):
    event_id: str
    user: str
    country: str
    hour: int = Field(ge=0, le=23)
    device: str
    files_accessed: int = Field(ge=0)
    timestamp: str

@app.get("/")
def home():
    
    return {"message": "AI Security Platform is running"}

@app.get("/alerts")
def get_alerts():
    alerts = get_all_alerts()

    return {"alerts": alerts}

@app.post("/events")
def create_event(event: SecurityEvent):

    event_data = event.model_dump()

    if event_data["user"] not in baselines:
        raise HTTPException(
            status_code=404,
            detail="No behavioural baseline found for this user"
        )

    baseline = baselines[event_data["user"]]

    result = analyse_login(event_data, baseline)

    severity = get_severity(result["risk_score"])

    return {
        "message": "Security event saved and analysed",
        "event": event_data,
        "detection": result,
        "severity": severity
    }