import csv
import json
import sys
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "code"))
import main

def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

requests = read_csv(ROOT / "dataset" / "sample_deletion_requests.csv")
identities = read_csv(ROOT / "dataset" / "user_identities.csv")
audits = read_csv(ROOT / "dataset" / "user_audit_log.csv")
expected = {r["case_id"]: r for r in read_csv(ROOT / "dataset" / "sample_output.csv")}

actual = {
    r["case_id"]: main.process_request(r, identities, audits)
    for r in requests
}

status_mismatches = [
    case_id for case_id, exp in expected.items()
    if actual[case_id]["deletion_status"] != exp["deletion_status"]
]
step_mismatches = [
    case_id for case_id, exp in expected.items()
    if json.loads(actual[case_id]["steps_json"]) != json.loads(exp["steps_json"])
]

print("Expected statuses:", dict(Counter(r["deletion_status"] for r in expected.values())))
print("Actual statuses:", dict(Counter(r["deletion_status"] for r in actual.values())))
print("Status mismatches:", len(status_mismatches), status_mismatches)
print("Step mismatches:", len(step_mismatches), step_mismatches)
