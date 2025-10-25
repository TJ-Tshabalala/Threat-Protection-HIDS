import os
import httpx
import json
import typing
from typing import List, Annotated

from dotenv import load_dotenv
load_dotenv()


from fastapi import FastAPI, Depends, HTTPException, status
from sqlmodel import Session, select
from database import create_db_and_tables, get_session

from models import (
    HidsAlert,
    HidsAlertCreate,
    HidsAlertRead,
    ThreatAnalysis,
    ThreatAnalysisResponse
)

# Configuration
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

app = FastAPI(
    title="HIDS Alert Analysis API",
    description="API to ingest HIDS alerts and perform LLM-based threat analysis.",
    version="1.0.0"
)

# Dependency for the DB Session
SessionDep = Annotated[Session, Depends(get_session)]

# --- Startup Event ---
@app.on_event("startup")
def on_startup():
    """Create database tables on startup."""
    create_db_and_tables()
    print("Database and tables initialized.")

# --- Helper Function for LLM Analysis ---
async def analyze_with_ollama(alert: HidsAlert) -> ThreatAnalysisResponse:
    """
        Sends the HIDS alert log to Ollama for structured threat analysis.
        Uses Pydantic's JSON Schema for reliable structured output.
    """

    # The system prompt guides the LLM to act as a threat analyst
    system_prompt = (
        "You are an expert cyber threat analyst. Your task is to analyze"
        "the provided HIDS alert log. Summarize the threat, provide a severity rating"
        "from 1-10 and give a clear, actionable recommendation. "
        "The output MUST strictly conform to the provided JSON schema"
    )

    prompt =(
        f"Analyze the following HIDS Alert (Rule ID: {alert.rule_id}, "
        f"Description: {alert.description}, Agent: {alert.agent_id}): \n\n"
        f"--- FULL LOG START ---\n{alert.full_log}\n--- FULL LOG END---"
    )

    # Prepare the payload for Ollama's /api/generate endpoint
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "system": system_prompt,
        "format": "json",
        "options": {
            "temperature":0.1 # Lower temperature for better/factual responses
        },
        "stream": False,
        # IMPORTANT: Use .schema_json() for Pydantic V1/SQLModel setup
        "response_model": ThreatAnalysisResponse.schema_json() 
    }

    try:
        # Use an async HTTP client for non-blocking requests
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(OLLAMA_URL, json=payload)
            response.raise_for_status()

        ollama_response = response.json()
        llm_output_str = ollama_response.get("response","")
        
        if not llm_output_str:
            raise ValueError("Ollama response was empty.")
        
        # Handle cases where LLMs wrap the json
        llm_output_str = llm_output_str.strip().strip("```json").strip("```")

        # Parse the JSON data into the Pydantic model
        llm_analysis_data = json.loads(llm_output_str)

        # Parse the JSON data into the Pydantic model
        analysis_model = ThreatAnalysisResponse.parse_obj(llm_analysis_data)

        return analysis_model
    
    except httpx.HTTPError as e:
        print(f"HTTP Error during Ollama call: {e}")
        # FIX: Safely construct detail message to avoid AttributeError on e.response.text
        detail_msg = f"Failed to communicate with Ollama service. Error: {e}"
        if e.response is not None:
             detail_msg += f". Upstream Response: {e.response.text.strip()}"
        
        raise HTTPException(
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail_msg
        )
        
    except Exception as e:
        print(f"Ollama Analysis Error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to parse structured response from LLM: {e}"
        )
    # The analyze_with_ollama function ends here.


# --- API Endpoints ---

@app.get("/")
def read_root():
    """Basic health check route."""
    return {"message": "HIDS Alert Analysis API is running."}

@app.post("/alerts", response_model=HidsAlertRead, status_code=status.HTTP_201_CREATED)
@app.post("/alerts/", response_model=HidsAlertRead, status_code=status.HTTP_201_CREATED)
async def ingest_alert(alert_create: HidsAlertCreate, session: SessionDep):
    """
        Receives a new alert, stores it in the database and triggers LLM analysis
    """

    # 1. Store the alert
    db_alert = HidsAlert.from_orm(alert_create)
    session.add(db_alert)
    session.commit()
    session.refresh(db_alert)
    
    # FIX: Check if ID was generated before proceeding (to avoid Pylance/NoneType issues)
    if db_alert.id is None:
        raise HTTPException(status_code=500, detail="Database insertion failed to return an alert ID.")


    # 2. Trigger asynchronous threat analysis
    try:
        analysis_response = await analyze_with_ollama(db_alert)
    except HTTPException as e:
        # Log the error but continue to return the stored alert
        print(f"Error analyzing alert {db_alert.id}: {e.detail}")

        # TODO: A real-world app would queue this for background tasks & retries
        return HidsAlertRead.from_orm(db_alert)
    

    # 3. Store the results
    # The ThreatAnalysisResponse includes summary, recommendation, and model info
    db_analysis = ThreatAnalysis(
        alert_id=db_alert.id, # Use id directly, it's guaranteed to be an int now
        threat_summary=analysis_response.threat_summary,
        recommendation=analysis_response.recommendation,
        llm_model=OLLAMA_MODEL
    )

    session.add(db_analysis)
    session.commit()

    return HidsAlertRead.from_orm(db_alert)

@app.get("/alerts", response_model=List[HidsAlertRead])
@app.get("/alerts/", response_model=List[HidsAlertRead])
def read_alerts(session: SessionDep, offset: int=0, limit: int=100):
    """
        Get a list of HIDS alerts from the database.
    """
    alerts = session.exec(select(HidsAlert).offset(offset).limit(limit)).all()
    return alerts

@app.get("/alerts/{alert_id}/analysis")
def read_alert_analysis(alert_id: int, session: SessionDep):
    """
        Get the LLM generated threat analysis for a specific alert.
    """

    alert = session.get(HidsAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found!")
    
    # Use select statement to get the analysis linked by alert_id
    analysis = session.exec(select(ThreatAnalysis).where(ThreatAnalysis.alert_id == alert_id)).first()

    if not analysis:
        # If no analysis is found, indicate that it's pending or failed
        return {"message": "Analysis is not yet available for this alert"}
    
    return analysis