# Assuming this is in your models.py

from sqlmodel import SQLModel, Field, Relationship
from typing import List, Optional

# --- LLM Analysis Output Model ---
class ThreatAnalysisResponse(SQLModel):
    """
    Schema for the structured JSON output from the LLM.
    """
    threat_summary: str
    recommendation: str
    # CRITICAL UPDATE: Add the severity score here
    severity_score: int = Field(..., ge=1, le=10, description="Threat score from 1 (low) to 10 (high).")

# --- Database Models ---

class HidsAlertBase(SQLModel):
    rule_id: int
    description: str
    agent_id: str
    full_log: str

class HidsAlert(HidsAlertBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    
    # Relationship to analysis results
    analysis: List["ThreatAnalysis"] = Relationship(back_populates="alert")
    
    # New Field for Automated Triage Action
    triage_action: Optional[str] = None # Stores the final action (Escalate, Resolve, Lock User Out)

class HidsAlertCreate(HidsAlertBase):
    pass

class HidsAlertRead(HidsAlertBase):
    id: int
    triage_action: Optional[str] = None

class ThreatAnalysisBase(SQLModel):
    threat_summary: str
    recommendation: str
    llm_model: str
    # CRITICAL UPDATE: Store the severity score in the DB
    severity_score: int
    
class ThreatAnalysis(ThreatAnalysisBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    alert_id: int = Field(foreign_key="hidsalert.id")
    
    alert: HidsAlert = Relationship(back_populates="analysis")

# --- Triage Models (New from flowchart logic) ---

class TriageResult(SQLModel):
    """Output model for the final triage decision."""
    severity: str
    action: str
    reason: str
    escalation_target: str | None = None
    documented: bool = False