# Python Log Analyzer and Incident Reporting System

## Overview
A Python-based tool that analyzes server log files, identifies errors and warnings, categorizes incidents by severity, and stores incident records in MySQL.

## Technologies Used
- Python
- MySQL and SQL
- Git and GitHub
- Regular expressions
- SHA-256 hashing

## Features
- Parses server logs and identifies INFO, WARNING, and ERROR messages.
- Classifies warnings as MEDIUM severity and errors as HIGH severity.
- Categorizes incidents by error type, including Database, Storage, CPU, Memory, Timeout, and Traffic.
- Stores incident records in a MySQL database.
- Prevents duplicate records when the analyzer is run repeatedly.
- Detects malformed log entries.
- Generates a text report with incident details and SQL-based summaries.

## Project Files
- `analyzer.py` — Main log analysis program.
- `server.log` — Sample server log data.
- `incident_report.txt` — Generated incident report.
- `.gitignore` — Excludes sensitive and unnecessary files.
- `.env` — Stores the database password locally and is excluded from Git.

## How to Run
1. Install Python, MySQL, and the required Python packages.
2. Create the `log_analyzer` database and the `incidents` table in MySQL.
3. Configure the database credentials in `.env`.
4. Activate the virtual environment.
5. Run:

```bash
python analyzer.py
```

The program generates `incident_report.txt` and stores incident records in MySQL.

## Skills Demonstrated
Log parsing, Python scripting, SQL queries, database integration, error classification, duplicate prevention, report generation, and Git version control.
