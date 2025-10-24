from sqlmodel import SQLModel, create_engine, Session
import os

DATABASE_URL = os.environ.get("TPH_DATABASE_URL", "sqlite:///./tph.db")
engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})

def init_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    return Session(engine)