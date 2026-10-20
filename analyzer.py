import os
from dotenv import load_dotenv
import re
import hashlib
import mysql.connector
from collections import Counter
from datetime import datetime

LOG_FILE = "server.log"
REPORT_FILE = "incident_report.txt"
load_dotenv()

db_password = os.getenv("DB_PASSWORD")

if not db_password:
    raise ValueError("DB_PASSWORD is missing from the .env file")
# Connect to the local MySQL server
connection = mysql.connector.connect(
    unix_socket="/var/run/mysqld/mysqld.sock",
    user="loguser",
    password=db_password,
    database="log_analyzer"
)

cursor = connection.cursor()

# Add a unique fingerprint column if it does not exist
cursor.execute("SHOW COLUMNS FROM incidents LIKE 'fingerprint'")

if cursor.fetchone() is None:
    cursor.execute(
        "ALTER TABLE incidents ADD COLUMN fingerprint CHAR(64) UNIQUE"
    )
    connection.commit()

counts = Counter()
incidents = []
invalid_lines = 0

# Read and analyze the log file
with open(LOG_FILE, "r", encoding="utf-8") as file:
    for line in file:
        line = line.strip()

        if not line:
            continue

        match = re.match(
            r"^(\d{4}-\d{2}-\d{2}) "
            r"(\d{2}:\d{2}:\d{2}) "
            r"(INFO|WARNING|ERROR) (.+)$",
            line
        )

        if not match:
            invalid_lines += 1
            continue

        log_date, log_time, level, message = match.groups()
        counts[level] += 1

        if level not in ("WARNING", "ERROR"):
            continue

        severity = "HIGH" if level == "ERROR" else "MEDIUM"

        if "database" in message.lower():
            error_type = "Database"
        elif "disk" in message.lower() or "space" in message.lower():
            error_type = "Storage"
        elif "cpu" in message.lower():
            error_type = "CPU"
        elif "memory" in message.lower():
            error_type = "Memory"
        elif "timeout" in message.lower():
            error_type = "Timeout"
        elif "requests" in message.lower():
            error_type = "Traffic"
        else:
            error_type = "General"

        # Fingerprint makes repeated runs idempotent
        fingerprint = hashlib.sha256(
            f"{log_date}|{log_time}|{level}|{message}".encode()
        ).hexdigest()

        incidents.append((
            log_date, log_time, level, severity,
            error_type, message, fingerprint
        ))

# Insert only new incidents
cursor.executemany("""
    INSERT IGNORE INTO incidents
    (log_date, log_time, log_level, severity,
     error_type, message, fingerprint)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
""", incidents)

connection.commit()
new_incidents = cursor.rowcount

# Query all incidents in the database
cursor.execute("""
    SELECT log_date, log_time, log_level, severity,
           error_type, message
    FROM incidents
    ORDER BY log_date, log_time
""")
database_incidents = cursor.fetchall()

# Generate the report
with open(REPORT_FILE, "w", encoding="utf-8") as report:
    report.write("SERVER LOG ANALYSIS REPORT\n")
    report.write("=" * 50 + "\n\n")
    report.write(f"Analysis time: {datetime.now()}\n")
    report.write(f"Total log entries read: {sum(counts.values()) + invalid_lines}\n")
    report.write(f"INFO messages: {counts['INFO']}\n")
    report.write(f"WARNING messages: {counts['WARNING']}\n")
    report.write(f"ERROR messages: {counts['ERROR']}\n")
    report.write(f"Malformed lines: {invalid_lines}\n")
    report.write(f"New incidents inserted: {new_incidents}\n")
    report.write(f"Total incidents in database: {len(database_incidents)}\n\n")

    report.write("INCIDENT DETAILS\n")
    report.write("-" * 50 + "\n")

    for log_date, log_time, level, severity, error_type, message in database_incidents:
        report.write(
            f"{log_date} {log_time} | {level} | "
            f"{severity} | {error_type} | {message}\n"
        )

    report.write("\nINCIDENT SUMMARY BY SEVERITY\n")
    report.write("-" * 50 + "\n")

    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM incidents
        GROUP BY severity
        ORDER BY severity
    """)

    for severity, total in cursor.fetchall():
        report.write(f"{severity}: {total}\n")

    report.write("\nINCIDENT SUMMARY BY ERROR TYPE\n")
    report.write("-" * 50 + "\n")

    cursor.execute("""
        SELECT error_type, COUNT(*)
        FROM incidents
        GROUP BY error_type
        ORDER BY COUNT(*) DESC
    """)

    for error_type, total in cursor.fetchall():
        report.write(f"{error_type}: {total}\n")

cursor.close()
connection.close()

print("Log analysis completed successfully.")
print(f"Log entries: {sum(counts.values()) + invalid_lines}")
print(f"New incidents inserted: {new_incidents}")
print(f"Report generated: {REPORT_FILE}")
