# Hackerrank-Hackathon-Orchestration-oct26

## Project Description: Ghost Data Still Exists

Ghost Data Still Exists is an AI-powered data deletion auditing project developed for the HackerRank Orchestrate October 2026 challenge.

The main purpose of this project is to check whether a user's personal data has actually been deleted after they request deletion. Sometimes, data remains in databases, backups, logs, search indexes, or other systems even when the deletion process reports success.

The project uses Python to analyze deletion requests, user identity history, system activity logs, and evidence files. It identifies remaining personal data, checks for risks such as active data synchronization or backup restoration, and generates a report with the deletion status and recommended corrective actions.

Technologies used: Python, CSV files, JSON, SQLite, and evidence analysis.

Expected output: An `output.csv` file containing the deletion status and evidence-based findings, remediation steps, and verification checks for each request.
