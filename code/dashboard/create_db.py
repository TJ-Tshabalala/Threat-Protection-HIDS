# create_db.py
import sqlite3

def create_database():
    """Creates the SQLite database and the incidents table."""
    conn = sqlite3.connect('cyber_incidents.db')
    cursor = conn.cursor()

    # Define the table schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            incident_id TEXT NOT NULL UNIQUE,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            analyst_assigned TEXT
        );
    ''')

    conn.commit()
    conn.close()
    print("Database 'cyber_incidents.db' and table 'incidents' created successfully.")

if __name__ == "__main__":
    create_database()