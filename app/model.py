from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime

class Agent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    agent_id: str
    hostname: Optional[str] = None
    ip: Optional[str] = None
    last_heartbeat: Optional[datetime] = None
    registered_at: datetime = Field(default_factory=datetime.utcnow)

class Event(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    agent_id: str
    event_type: str
    severity: int = 1
    payload: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)