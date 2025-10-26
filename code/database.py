# database.py

from sqlmodel import create_engine, Session, SQLModel
import os

# SQLite is file-based and easy to use.
# It creates a file named 'database.db' in the project directory.
sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

engine = create_engine(sqlite_url, echo=True)

def create_db_and_tables():
    """Initializes the database and creates tables defined in models.py."""
    SQLModel.metadata.create_all(engine)

def get_session():
    """Dependency to provide a database session."""
    with Session(engine) as session:
        yield session