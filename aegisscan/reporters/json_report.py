"""
JSON Report Generator for AegisScan.
Outputs structured JSON suitable for CI/CD pipelines, SIEM ingest, and automation.
"""

import json
from pathlib import Path
from aegisscan.core.models import ScanResult


def generate_json_report(result: ScanResult, output_path: str) -> None:
    """Writes the scan result dictionary to a formatted JSON file."""
    data = result.to_dict()
    Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
