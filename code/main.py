import os
import httpx
import json
import time
from typing import List, Annotated, Literal

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Depends, HTTPException, status
from sqlmodel import Session, select
from database import create_db_and_tables, get_session
# Ensure your database.py has the necessary functions:
# from database import create_db_and_tables, get_session 

# Ensure your models.py is updated with the changes above
from models import (
    HidsAlert,
    HidsAlertCreate,
    HidsAlertRead,
    ThreatAnalysis,
    ThreatAnalysisResponse, # MUST include severity_score
    TriageResult
)

# Configuration
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

app = FastAPI(
    title="Automated Cyber Triage API (LLM + Flowchart Logic)",
    description="API to ingest HIDS alerts, perform LLM analysis, and automate risk-based escalation.",
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

# ====================================================================
# --- FLOWCHART LOGIC FUNCTIONS (RISK SCORE AND ACTIONS) ---
# ====================================================================

def get_flowchart_severity(numeric_score: int) -> Literal["High", "Medium", "Low"]:
    """
    Implements the 1-10 severity scale logic: 1-3=Low, 4-6=Medium, 7-10=High.
    """
    if numeric_score >= 7:
        return "High"
    elif numeric_score >= 4:
        return "Medium"
    else: # 1-3
        return "Low"

def document_and_update_knowledge_base(incident_summary: str):
    """
    SIMULATION: Automates the "Document" and "Update Knowledge Base" steps.
    """
    print(f"LLM Triage: Generating documentation for the Knowledge Base...")
    time.sleep(0.1) # Simulate call delay
    
    print(f"--- RESOLUTION REPORT --- (Summary: {incident_summary})")
    print("Action: Auto-documented and Knowledge Base entry created.")
    return True

def execute_triage_flow(alert: HidsAlert, llm_analysis: ThreatAnalysisResponse) -> TriageResult:
    """
    Translates the UML Flowchart logic using the LLM's severity score.
    """
    
    # Extract data needed for the flowchart decisions
    severity_score = llm_analysis.severity_score
    flowchart_severity = get_flowchart_severity(severity_score)
    
    # SIMULATION: Use a proxy for the 'Can Resolve' and 'Login Fail' checks.
    # We use the LLM recommendation's clarity as a proxy for "Can Resolve".
    can_be_resolved = "remediation" in llm_analysis.recommendation.lower() or "containment" in llm_analysis.recommendation.lower()
    
    # We'll check the alert description for login failure events
    is_login_fail = "login fail" in alert.description.lower()
    
    
    # 1. Authenticate / Login Fail Check (Flowchart start)
    # Since the full flow isn't in the input, we'll check for the high-impact login fail end state
    if is_login_fail:
        # NOTE: Since we don't track login_fail_count per user, we treat a new login fail alert as an escalation trigger
        return TriageResult(
            severity="Critical",
            action="Lock User Out",
            reason=f"LLM identified a Critical Login Failure event (Score: {severity_score}).",
            escalation_target="Identity Management System"
        )
        
    # 2. High Alert Logic (High Alert? -> Yes -> Escalate)
    if flowchart_severity == "High":
        return TriageResult(
            severity="High",
            action="Escalate",
            reason=f"LLM classified the event as High severity (Score: {severity_score}).",
            escalation_target="SOC Tier 2 / PagerDuty"
        )
        
    # 3. Low/Medium Logic (Low/Medium?)
    elif flowchart_severity == "Medium":
        if can_be_resolved:
            # Medium -> Cmi Resolve? -> Yes -> Resolve -> Document
            summary = f"Medium alert (Score: {severity_score}) resolved via LLM recommendation: {llm_analysis.recommendation}"
            document_and_update_knowledge_base(summary)
            return TriageResult(
                severity="Medium",
                action="Resolve & Document",
                reason="Medium alert with LLM-provided resolution path.",
                documented=True
            )
        else:
            # Medium -> Cmi Resolve? -> No -> Escalate
            return TriageResult(
                severity="Medium",
                action="Escalate",
                reason=f"Medium alert (Score: {severity_score}) requires human review: LLM recommendation is unclear or complex.",
                escalation_target="SOC Tier 1 / Ticketing System"
            )
            
    elif flowchart_severity == "Low":
        # Low -> Resolve -> Document
        summary = f"Low alert (Score: {severity_score}) auto-resolved based on LLM analysis: {llm_analysis.recommendation}"
        document_and_update_knowledge_base(summary)
        return TriageResult(
            severity="Low",
            action="Resolve & Document",
            reason="Low severity alert automatically resolved.",
            documented=True
        )
        
    # Fallback
    raise HTTPException(status_code=500, detail="Triage logic failed to determine a valid severity path.")

# ====================================================================
# --- OLLAMA AND INGESTION FUNCTIONS ---
# ====================================================================

async def analyze_with_ollama(alert: HidsAlert) -> ThreatAnalysisResponse:
    # ... (Your existing analyze_with_ollama function, ensure the system prompt 
    # explicitly asks for the severity_score: 1-10) ...
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
        analysis_model = ThreatAnalysisResponse.model_validate(llm_analysis_data) # Use model_validate for modern pydantic
        # analysis_model = ThreatAnalysisResponse.parse_obj(llm_analysis_data) # Use parse_obj for older pydantic/sqlmodel

        return analysis_model
    
    except httpx.HTTPError as e:
        print(f"HTTP Error during Ollama call: {e}")
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


# ====================================================================
# --- API Endpoints ---
# ====================================================================

@app.get("/")
def read_root():
    """Basic health check route."""
    return {"message": "HIDS Alert Analysis API is running."}

@app.post("/alerts", response_model=HidsAlertRead, status_code=status.HTTP_201_CREATED)
@app.post("/alerts/", response_model=HidsAlertRead, status_code=status.HTTP_201_CREATED)
async def ingest_alert(alert_create: HidsAlertCreate, session: SessionDep):
    """
        Receives a new alert, stores it, performs LLM analysis, and executes the flowchart triage.
    """

    # 1. Store the alert
    db_alert = HidsAlert.model_validate(alert_create) # Use model_validate for modern pydantic
    session.add(db_alert)
    session.commit()
    session.refresh(db_alert)
    
    if db_alert.id is None:
        raise HTTPException(status_code=500, detail="Database insertion failed to return an alert ID.")

    # 2. Trigger asynchronous threat analysis
    try:
        analysis_response = await analyze_with_ollama(db_alert)
    except HTTPException as e:
        # If LLM analysis fails, store the alert but cannot perform triage
        print(f"Error analyzing alert {db_alert.id}: {e.detail}. Skipping triage.")
        return HidsAlertRead.model_validate(db_alert)
    
    # 3. Execute Flowchart Triage Logic based on LLM output
    triage_result = execute_triage_flow(db_alert, analysis_response)
    
    # 4. Store the LLM Analysis and the Final Triage Action
    db_analysis = ThreatAnalysis(
        alert_id=db_alert.id, 
        threat_summary=analysis_response.threat_summary,
        recommendation=analysis_response.recommendation,
        severity_score=analysis_response.severity_score, # Store the score
        llm_model=OLLAMA_MODEL
    )
    
    # Update the HIDS Alert with the final decision
    db_alert.triage_action = triage_result.action 

    session.add(db_analysis)
    session.add(db_alert) # Save the updated alert
    session.commit()
    session.refresh(db_alert)

    # NOTE: In a real system, you would execute the 'Escalate' action (e.g., webhook call) here.
    if triage_result.action == "Escalate" or triage_result.action == "Lock User Out":
        print(f"ACTION REQUIRED: Sending webhook to {triage_result.escalation_target} for {triage_result.action}")

    return HidsAlertRead.model_validate(db_alert)

@app.get("/alerts", response_model=List[HidsAlertRead])
@app.get("/alerts/", response_model=List[HidsAlertRead])
def read_alerts(session: SessionDep, offset: int=0, limit: int=100):
    """
        Get a list of HIDS alerts from the database.
    """
    alerts = session.exec(select(HidsAlert).offset(offset).limit(limit)).all()
    return alerts

@app.get("/alerts/{alert_id}/analysis", response_model=ThreatAnalysis)
def read_alert_analysis(alert_id: int, session: SessionDep):
    """
        Get the LLM generated threat analysis and severity score for a specific alert.
    """

    alert = session.get(HidsAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found!")
    
    # Use select statement to get the analysis linked by alert_id
    analysis = session.exec(select(ThreatAnalysis).where(ThreatAnalysis.alert_id == alert_id)).first()

    if not analysis:
        return {"message": "Analysis is not yet available for this alert"}
    
    return analysis