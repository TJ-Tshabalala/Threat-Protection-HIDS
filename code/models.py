from datetime import datetime
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship

# --- 1. Threat Analysis Definitions ---

class ThreatAnalysisBase(SQLModel):
    """Base model for the LLM-generated threat analysis."""
    # Ensure foreign_key is correct
    alert_id: int = Field(foreign_key="hidsalert.id", unique=True, index=True) 
    threat_summary: str
    recommendation: str
    llm_model: str
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow, nullable=False)

# DB Table Model
class ThreatAnalysis(ThreatAnalysisBase, table=True):
    """Database table model, includes primary key."""
    id: Optional[int] = Field(default=None, primary_key=True)
    
    # Relationship to HidsAlert (Referenced by its string name "HidsAlert")
    alert: "HidsAlert" = Relationship(back_populates="analysis") 

# Pydantic Model for LLM Response (for a structured LLM output)
class ThreatAnalysisResponse(ThreatAnalysisBase):
    """Pydantic model for the expected structured LLM response."""
    # LLM doesn't generate alert_id, so remove it for the input validation
    # This model is primarily for the output structure
    pass 

# --- 2. HIDS Alert Definitions ---

class HidsAlertBase(SQLModel):
    """Base model for HIDS Alert data."""
    rule_id: int = Field(index=True)
    level: int = Field(index=True,max_length=2)
    description: str
    full_log: str
    agent_id: str = Field(index=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    
# DB Table Model
class HidsAlert(HidsAlertBase, table=True):
    """Database table model, includes primary key."""
    id: Optional[int] = Field(default=None, primary_key=True)
    
    # Relationship to ThreatAnalysis (Referenced by its string name "ThreatAnalysis")
    analysis: Optional["ThreatAnalysis"] = Relationship(back_populates="alert")

# Pydantic Model for API Input (Create)
class HidsAlertCreate(HidsAlertBase):
    """Pydantic model for receiving new alerts via POST."""
    pass

# Pydantic Model for API Response (Read - includes the ID)
class HidsAlertRead(HidsAlertBase):
    """Pydantic model for returning alerts from the API."""
    id: int
    
# --- 3. Circular Dependency Resolution ---
# THIS STEP IS CRUCIAL FOR SQLMODEL/PYDANTIC
HidsAlert.update_forward_refs()
ThreatAnalysis.update_forward_refs()