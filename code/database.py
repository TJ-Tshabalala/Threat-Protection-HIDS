from sqlmodel import create_engine, Session
from models import HidsAlert, ThreatAnalysis, SQLModel
from typing import Generator

# SQLite db file path
sqlite_file_name = "security_log.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

# Create the SQLModel engine
engine = create_engine(sqlite_url, echo=True) # Set to False/True to see generated SQL

def create_db_and_tables():
    """
        Initialize the db and create tables if they do not exist
    """
    SQLModel.metadata.create_all(engine)

def get_session() -> Generator[Session, None, None]:
    """Dependency to provide a db session for requested endpoints"""
    with Session(engine) as session:
        yield session