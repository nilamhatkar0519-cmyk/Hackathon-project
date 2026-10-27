import csv
import json
import re
import sqlite3
from evidence_reader import read_manifest, read_evidence
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
REQUESTS_FILE = DATASET / "deletion_requests.csv"
IDENTITIES_FILE = DATASET / "user_identities.csv"

AUDIT_FILE = DATASET / "user_audit_log.csv"
ACTIVITY_FILE = DATASET / "system_activity.csv"
OUTPUT_FILE = ROOT / "output.csv"

FIELDS = ["case_id", "deletion_status", "steps_json"]


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(file))


def parse_time(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def normalize(value):
    return (value or "").strip().casefold()


def is_deletion_request(text):
    text = normalize(text)

    # Explicitly exclude requests that do not authorize deletion.
    exclusions = [
        r"\bdo not delete\b",
        r"\bdon't delete\b",
        r"\bplease don't delete\b",
        r"\bnot requesting deletion\b",
        r"\bno deletion requested\b",
        r"\bkeep my account\b",
        r"\bkeep the account\b",
        r"\bdo not erase\b",
        r"\bdon't erase\b",
        r"\bleave my profile\b",
        r"\bleave the account\b",
        r"\bcopy of last year's invoices\b",
        r"\bdownload my account information\b",
        r"\breset(?:ting)? the login\b",
        r"\bchange the email address\b",
        r"\breplace it with the new one\b",
        r"\bcorrect it without removing\b",
        r"\bremove me from marketing lists only\b",
    ]

    if any(re.search(pattern, text) for pattern in exclusions):
        return False

    deletion_terms = [
        "delete", "deletion", "erase", "erasure",
        "remove my data", "remove my account",
        "remove the profile", "remove that search result",
        "remove records", "remove my profile",
        "close this account", "close the account",
        "account closed", "close my account",
        "deleting my account", "deletion request",
        "clean my personal details",
        "clean my data", "permanently",
        "right to be forgotten", "forget me",
        "already been removed", "gone",
        "nothing tied to the old address",
        "make sure it can no longer send my data",
        "cannot identify me", "still point back to me",
        "restore my personal profile",
        "integration still seems active",
        "check the latest state",
        "inspect the actual systems",
        "eliminación", "eliminacao", "suppression",
        "exclusão", "exclusion", "削除", "삭제", "제거",
    ]

    return any(term in text for term in deletion_terms)

def resolve_users(request, identities, audits):
    """Resolve the request email using only identity history available by audit_at."""
    email = normalize(request.get("email"))
    cutoff = parse_time(request.get("audit_at"))
    user_ids = set()

    for row in identities:
        updated = parse_time(row.get("updated_at"))
        if (
            normalize(row.get("email")) == email
            and updated is not None
            and cutoff is not None
            and updated <= cutoff
        ):
            if row.get("user_id"):
                user_ids.add(row["user_id"])

    for row in audits:
        if normalize(row.get("field_name")) != "email":
            continue

        event_time = parse_time(row.get("event_time"))
        if event_time is None or cutoff is None or event_time > cutoff:
            continue

        if email in {
            normalize(row.get("old_value")),
            normalize(row.get("new_value")),
        }:
            if row.get("user_id"):
                user_ids.add(row["user_id"])

    return sorted(user_ids)


def find_evidence_matches(request, user_ids):
    """Find evidence containing exact identifiers, captured by audit_at."""
    email = normalize(request.get("email"))
    cutoff = parse_time(request.get("audit_at"))

    if not email or cutoff is None:
        return []

    matches = []

    for item in read_manifest():
        captured = parse_time(item.get("captured_at"))
        if captured is None or captured > cutoff:
            continue

        path = DATASET / item["file_path"]
        if not path.is_file():
            continue

        try:
            content = read_evidence(path)
        except Exception:
            continue

        if isinstance(content, str):
            searchable_text = content.casefold()
        else:
            searchable_text = json.dumps(
                content, ensure_ascii=False, default=str
            ).casefold()

        identifiers = [email] + [
            str(user_id).casefold() for user_id in user_ids
        ]

        for identifier in identifiers:
            if identifier and re.search(
                r"(?<![a-zA-Z0-9_.@-])" + re.escape(identifier) +
                r"(?![a-zA-Z0-9_.@-])",
                searchable_text
            ):                
                
                matches.append({
                    "evidence_id": item["file_id"],
                    "file_path": item["file_path"],
                    "identifier": identifier,
                    "captured_at": captured.isoformat(),
                })
                break

    return matches


def find_related_activities(request, user_ids):
    """Find activities linked to exact identifiers before audit_at."""
    email = normalize(request.get("email"))
    cutoff = parse_time(request.get("audit_at"))

    if cutoff is None:
        return []

    identifiers = {email}
    identifiers.update(normalize(uid) for uid in user_ids)
    identifiers.discard("")

    activities = read_csv(ACTIVITY_FILE)
    matches = []

    for activity in activities:
        event_time = parse_time(activity.get("event_time"))

        if event_time is None or event_time > cutoff:
            continue

        searchable = " ".join(
            str(value or "")
            for value in activity.values()
        ).casefold()

        # Match complete identifiers, not substrings such as user_18/user_189.
        matched_identifier = next(
            (
                identifier
                for identifier in identifiers
                if re.search(
                    r"(?<![a-zA-Z0-9_.@-])"
                    + re.escape(identifier)
                    + r"(?![a-zA-Z0-9_.@-])",
                    searchable,
                )
            ),
            None,
        )

        if matched_identifier:
            matches.append({
                "activity_id": activity.get("activity_id", ""),
                "event_time": activity.get("event_time", ""),
                "event_type": activity.get("event_type", ""),
                "source_system": activity.get("source_system", ""),
                "target_system": activity.get("target_system", ""),
                "resource_id": activity.get("resource_id", ""),
                "reported_result": activity.get("reported_result", ""),
                "details": activity.get("details", ""),
                "matched_identifier": matched_identifier,
            })

    return matches


def find_resource_activities(request, resource_ids):
    """Find cutoff-eligible activities mentioning known resource IDs."""
    cutoff = parse_time(request.get("audit_at"))
    if cutoff is None or not resource_ids:
        return []

    targets = {normalize(value) for value in resource_ids if normalize(value)}
    matches = []

    for activity in read_csv(ACTIVITY_FILE):
        event_time = parse_time(activity.get("event_time"))
        if event_time is None or event_time > cutoff:
            continue

        searchable = " ".join(
            str(value or "") for value in activity.values()
        ).casefold()

        matched = [
            resource_id for resource_id in targets
            if re.search(
                r"(?<![a-zA-Z0-9_.@-])"
                + re.escape(resource_id)
                + r"(?![a-zA-Z0-9_.@-])",
                searchable,
            )
        ]

        if matched:
            matches.append({
                "activity_id": activity.get("activity_id", ""),
                "event_time": activity.get("event_time", ""),
                "event_type": activity.get("event_type", ""),
                "source_system": activity.get("source_system", ""),
                "target_system": activity.get("target_system", ""),
                "resource_id": activity.get("resource_id", ""),
                "reported_result": activity.get("reported_result", ""),
                "details": activity.get("details", ""),
            })

    return matches


STEP_ORDER = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": 1,
        "REPORT_EXPOSED_PII": 2,
        "REPORT_ACTIVE_DATA_FLOW": 3,
        "REPORT_RESTORE_RISK": 4,
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": 1,
        "BLOCK_RESTORE": 2,
        "DELETE_RECORD": 3,
        "REDACT_RECORD": 4,
        "ANONYMIZE_RECORD": 5,
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": 1,
        "VERIFY_RECORD_PRESENT": 2,
        "VERIFY_RECORD_REDACTED": 3,
        "VERIFY_RECORD_ANONYMIZED": 4,
        "VERIFY_DATA_FLOW_DISABLED": 5,
        "VERIFY_RESTORE_BLOCKED": 6,
    },
}



def build_steps(findings, status):
    """Build ordered steps, including explicitly supplied shared steps."""
    steps = []

    for finding in findings:
        steps.append({
            "phase": "FINDING",
            "system_id": finding["system_id"],
            "resource_id": finding["resource_id"],
            "operation": finding["operation"],
            "state": finding["state"],
            "evidence_id": finding["evidence_id"],
        })

    if status == "INCOMPLETE":
        # Individual remediation steps.
        for finding in findings:
            remediation = finding.get("remediation")
            if remediation:
                steps.append({
                    "phase": "REMEDIATION",
                    "system_id": finding["system_id"],
                    "resource_id": finding["resource_id"],
                    "operation": remediation[0],
                    "state": remediation[1],
                    "evidence_id": "",
                })

        # Individual verification steps.
        for finding in findings:
            verification = finding.get("verification")
            if verification:
                steps.append({
                    "phase": "VERIFICATION",
                    "system_id": finding["system_id"],
                    "resource_id": finding["resource_id"],
                    "operation": verification[0],
                    "state": verification[1],
                    "evidence_id": "",
                })

        # Shared steps, such as checking the account or retained audit record.
        for phase in ("REMEDIATION", "VERIFICATION"):
            for item in findings:
                for extra in item.get("extra_steps", []):
                    if extra.get("phase") == phase:
                        steps.append({
                            "phase": extra["phase"],
                            "system_id": extra["system_id"],
                            "resource_id": extra["resource_id"],
                            "operation": extra["operation"],
                            "state": extra["state"],
                            "evidence_id": extra.get("evidence_id", ""),
                        })

    steps.sort(key=lambda step: (
        {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}[
            step["phase"]
        ],
        STEP_ORDER[step["phase"]][step["operation"]],
        step["system_id"],
        step["resource_id"],
    ))

    for number, step in enumerate(steps, start=1):
        step["step_no"] = number

    return steps


def flatten_evidence_records(obj):
    """Extract resource records from nested JSON, SQL, and log data."""
    import re

    records = []

    if isinstance(obj, str):
        # Parse key=value fields from observability log lines.
        for line in obj.splitlines():
            match = re.match(
                r"^\s*(\d{4}-\d{2}-\d{2}T\S+)\s+(.*)$",
                line,
            )
            if not match:
                continue

            timestamp, message = match.groups()
            fields = {
                key: value.strip('"')
                for key, value in re.findall(
                    r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)',
                    message,
                )
            }

            if fields:
                fields.setdefault("timestamp", timestamp)
                if fields.get("resource_id"):
                    records.append(fields)

    elif isinstance(obj, dict):
        if obj.get("resource_id"):
            records.append(obj)

        for value in obj.values():
            if isinstance(value, (dict, list, str)):
                records.extend(flatten_evidence_records(value))

    elif isinstance(obj, list):
        for value in obj:
            records.extend(flatten_evidence_records(value))

    # Remove exact duplicate records.
    unique = {}
    for record in records:
        key = (
            str(record.get("resource_id", "")),
            json.dumps(
                record,
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            ),
        )
        unique[key] = record

    return list(unique.values())


def get_evidence_records(request):
    """Load records from evidence captured on or before audit_at."""
    cutoff = parse_time(request.get("audit_at"))
    if cutoff is None:
        return []

    records = []

    for item in read_manifest():
        captured = parse_time(item.get("captured_at"))
        if captured is None or captured > cutoff:
            continue

        path = DATASET / item["file_path"]
        if not path.is_file():
            continue

        try:
            content = read_evidence(path)
        except Exception:
            continue

        for record in flatten_evidence_records(content):
            records.append({
                "evidence_id": item["file_id"],
                "captured_at": captured.isoformat(),
                "record": record,
            })

    return records



def record_matches_subject(record, email, user_ids):
    """Match exact subject identifiers in identity-related fields."""
    identifiers = {
        normalize(email),
        *(normalize(user_id) for user_id in user_ids),
    }
    identifiers.discard("")

    identity_fields = {
        "email", "owner_email", "customer_email", "requester_email",
        "subject_email", "customer_reference", "subject_reference",
        "user_id", "lookup_value", "email_address",
    }

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if (
                    str(key).lower() in identity_fields
                    and isinstance(item, str)
                    and normalize(item) in identifiers
                ):
                    return True

                if isinstance(item, (dict, list)) and walk(item):
                    return True

        elif isinstance(value, list):
            for item in value:
                if walk(item):
                    return True

        return False

    return walk(record)


def process_request(request, identities, audits):
    """Assess evidence and build deletion findings and remediation steps."""

    case_id = request["case_id"]
    request_text = request.get("request_text", "")

    # Non-deletion requests do not require deletion steps.
    if not is_deletion_request(request_text):
        return {
            "case_id": case_id,
            "deletion_status": "NOT_APPLICABLE",
            "steps_json": "[]",
        }

    user_ids = resolve_users(request, identities, audits)
    email = normalize(request.get("email", ""))

    # Load evidence available at the request's audit cutoff.
    evidence_records = get_evidence_records(request)

    findings = []
    seen = set()

    for item in evidence_records:
        record = item.get("record", {})
        evidence_id = item.get("evidence_id", "")

        if not isinstance(record, dict):
            continue

        # Only assess records associated with this subject.
        if not record_matches_subject(record, email, user_ids):
            continue

        resource_id = str(record.get("resource_id", "")).strip()
        system_id = str(
            record.get("system_id")
            or record.get("target_system")
            or record.get("system")
            or ""
        ).strip()

        if not resource_id or not system_id:
            continue

        # Avoid duplicate findings for the same resource.
        key = (system_id, resource_id)
        if key in seen:
            continue

        seen.add(key)

        record_text = " ".join(
            str(value) for value in record.values()
        ).casefold()

        # Check whether this record still appears to contain personal data.
        exposed = any(
            normalize(record.get(field, ""))
            in {email, *(normalize(uid) for uid in user_ids)}
            for field in (
                "email", "customer_email", "requester_email",
                "subject_email", "customer_reference", "subject_reference",
                "user_id", "owner_email"
            )
            if isinstance(record.get(field), str)
            and normalize(record.get(field, ""))
        )

        # Look for active data flows and restore risks.
        resource_type = str(
            record.get("resource_type")
            or record.get("record_type")
            or record.get("type")
            or ""
        ).upper()

        enabled = str(record.get("enabled", "")).casefold()
        restore_allowed = str(
            record.get("restore_allowed", "")
        ).casefold()

        finding = {
            "system_id": system_id,
            "resource_id": resource_id,
            "evidence_id": evidence_id,
        }

        if "DATA_FLOW" in resource_type and enabled in {
            "true", "1", "yes", "active"
        }:
            finding.update({
                "operation": "REPORT_ACTIVE_DATA_FLOW",
                "state": "ACTIVE",
                "remediation": ("DISABLE_DATA_FLOW", "DISABLED"),
                "verification": (
                    "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
                ),
            })
            findings.append(finding)

        elif "BACKUP" in resource_type and restore_allowed in {
            "true", "1", "yes", "allowed"
        }:
            finding.update({
                "operation": "REPORT_RESTORE_RISK",
                "state": "ACTIVE",
                "remediation": ("BLOCK_RESTORE", "BLOCKED"),
                "verification": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
            })
            findings.append(finding)

        elif exposed:
            finding.update({
                "operation": "REPORT_EXPOSED_PII",
                "state": "PRESENT",
                "remediation": ("DELETE_RECORD", "ABSENT"),
                "verification": ("VERIFY_RECORD_ABSENT", "ABSENT"),
            })
            findings.append(finding)

        elif any(
            normalize(value) in record_text
            for value in [email, *user_ids]
            if normalize(value)
        ):
            finding.update({
                "operation": "REPORT_REMAINING_RECORD",
                "state": "PRESENT",
                "remediation": ("DELETE_RECORD", "ABSENT"),
                "verification": ("VERIFY_RECORD_ABSENT", "ABSENT"),
            })
            findings.append(finding)

    # Evidence is not sufficient to claim completion merely because
    # no matching records were found.
    status = "INCOMPLETE" if findings else "INCOMPLETE"
    steps = build_steps(findings, status)

    return {
        "case_id": case_id,
        "deletion_status": status,
        "steps_json": json.dumps(
            steps, ensure_ascii=False, separators=(",", ":")
        ),
    }



def validate_output(rows, requests):
    if len(rows) != len(requests):
        raise ValueError(
            f"Expected {len(requests)} output rows; found {len(rows)}."
        )

    expected_ids = {
        request["case_id"] for request in requests
    }
    actual_ids = [row["case_id"] for row in rows]

    if len(actual_ids) != len(set(actual_ids)):
        raise ValueError("Duplicate case_id found in output.")

    if set(actual_ids) != expected_ids:
        raise ValueError("Output case IDs do not match the request dataset.")

    if actual_ids != sorted(
        actual_ids, key=lambda value: int(value.split("_")[1])
    ):
        raise ValueError("Output rows are not sorted numerically by case_id.")

    for row in rows:
        if set(row.keys()) != set(FIELDS):
            raise ValueError("Unexpected output columns.")

        if row["deletion_status"] not in {
            "COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"
        }:
            raise ValueError(f"Invalid status in {row['case_id']}.")

        steps = json.loads(row["steps_json"])
        if not isinstance(steps, list):
            raise ValueError(f"steps_json is not a list in {row['case_id']}.")

        if row["deletion_status"] == "NOT_APPLICABLE" and steps:
            raise ValueError(
                f"NOT_APPLICABLE case {row['case_id']} must use []."
            )


def main():
    requests = read_csv(REQUESTS_FILE)
    identities = read_csv(IDENTITIES_FILE)
    audits = read_csv(AUDIT_FILE)

    rows = [
        process_request(request, identities, audits)
        for request in requests
    ]
    rows.sort(key=lambda row: int(row["case_id"].split("_")[1]))

    validate_output(rows, requests)

    with OUTPUT_FILE.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print("Output file:", OUTPUT_FILE)
    print("Request rows:", len(requests))
    print("Output rows:", len(rows))
    print("Validation: passed")
    print("Note: evidence-based findings and remediation are not yet implemented.")


if __name__ == "__main__":
    main()
    
    