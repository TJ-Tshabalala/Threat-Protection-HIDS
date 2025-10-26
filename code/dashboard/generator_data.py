# generate_data.py
import sqlite3
import random
from datetime import datetime, timedelta

def generate_dummy_data(num_records=50):
    """Generates and inserts dummy cyber incident data into the database."""
    conn = sqlite3.connect('cyber_incidents.db')
    cursor = conn.cursor()

    attack_types = ["Malware", "Phishing", "DDoS", "Brute Force", "SQL Injection", "Ransomware", "Insider Threat"]
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    statuses = ["Open", "In Progress", "Pending Review", "Closed", "False Positive"]
    analysts = ["Alice", "Bob", "Charlie", "Diana"]

    base_time = datetime.now() - timedelta(days=3)
    
    data = []
    for i in range(1, num_records + 1):
        incident_id = f"INC-{i:05d}"
        
        # Simulate 'real-time' data by varying the timestamp
        timestamp = base_time + timedelta(minutes=random.randint(1, 4320))
        
        attack_type = random.choice(attack_types)
        severity = random.choice(severities)
        status = random.choice(statuses)
        analyst = random.choice(analysts) if status != "Open" else "Unassigned"
        
        # Generate dummy IPs
        source_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        destination_ip = f"10.0.{random.randint(1, 5)}.{random.randint(1, 255)}"
        
        data.append((timestamp.strftime('%Y-%m-%d %H:%M:%S'), incident_id, attack_type, severity, status, source_ip, destination_ip, analyst))

    # Insert data, ignoring duplicates (in case it's run multiple times)
    cursor.executemany('''
        INSERT OR IGNORE INTO incidents (timestamp, incident_id, attack_type, severity, status, source_ip, destination_ip, analyst_assigned)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', data)

    conn.commit()
    conn.close()
    print(f"{cursor.rowcount} records inserted into 'incidents' table.")

if __name__ == "__main__":
    # Ensure DB is created before generating data
    import create_db
    create_db.create_database() 
    generate_dummy_data(num_records=100) # Generating 100 sample tickets