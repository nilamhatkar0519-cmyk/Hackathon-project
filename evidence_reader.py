
import csv
import json
import sqlite3
from datetime import datetime
from pathlib import Path

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None


ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
MANIFEST = DATASET / "evidence_files.csv"


def parse_time(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def read_manifest():
    with MANIFEST.open(
        "r", encoding="utf-8-sig", newline=""
    ) as file:
        return list(csv.DictReader(file))


def read_evidence(path):
    """Read supported evidence formats without changing source files."""
    suffix = path.suffix.lower()

    if suffix in {".log", ".txt"}:
        return path.read_text(encoding="utf-8", errors="replace")

    if suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))

    if suffix == ".sql":
        # Parse SQL in an isolated in-memory database.
        connection = sqlite3.connect(":memory:")
        try:
            connection.executescript(
                path.read_text(encoding="utf-8", errors="replace")
            )
            result = {}
            tables = connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' ORDER BY name"
            ).fetchall()

            for (table_name,) in tables:
                cursor = connection.execute(
                    f'SELECT * FROM "{table_name}"'
                )
                columns = [item[0] for item in cursor.description]
                result[table_name] = [
                    dict(zip(columns, row))
                    for row in cursor.fetchall()
                ]

            return result
        finally:
            connection.close()

    if suffix == ".pdf":
        if PdfReader is None:
            return {"error": "pypdf is not installed"}
        reader = PdfReader(str(path))
        return "\n".join(
            page.extract_text() or "" for page in reader.pages
        )

    if suffix == ".png":
        return {
            "note": (
                "Image evidence requires visual inspection or OCR. "
                "It is not treated as empty or as proof of absence."
            )
        }

    return {"error": f"Unsupported evidence format: {suffix}"}


def evidence_before_cutoff(cutoff):
    """Return only manifest entries captured on or before the cutoff."""
    eligible = []

    for item in read_manifest():
        captured = parse_time(item.get("captured_at"))
        if captured is None or captured > cutoff:
            continue

        path = DATASET / item["file_path"]
        if not path.is_file():
            eligible.append({
                **item,
                "path": path,
                "content": None,
                "read_error": "Evidence file is missing",
            })
            continue

        try:
            content = read_evidence(path)
            eligible.append({
                **item,
                "path": path,
                "content": content,
                "read_error": "",
            })
        except Exception as exc:
            eligible.append({
                **item,
                "path": path,
                "content": None,
                "read_error": str(exc),
            })

    return eligible


if __name__ == "__main__":
    from collections import Counter

    files = read_manifest()
    print("Evidence files in manifest:", len(files))
    print("Formats:", dict(Counter(
        Path(item["file_path"]).suffix.lower()
        for item in files
    )))

    cutoff = parse_time("2026-07-19T13:00:00Z")
    eligible = evidence_before_cutoff(cutoff)

    print("Files captured by test cutoff:", len(eligible))
    print("Read errors:", sum(
        bool(item["read_error"]) for item in eligible
    ))
    print("Image files needing separate inspection:", sum(
        item["path"].suffix.lower() == ".png"
        for item in eligible
    ))
