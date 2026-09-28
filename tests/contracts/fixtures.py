"""Deterministic production-exporter inputs, not hand-written report lookalikes."""
import json
import tempfile
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

from vulcanary.dashboard import remediation_receipt
from vulcanary.dataflow import analyze_python_dataflow
from vulcanary.dependencies import Package
from vulcanary.models import Finding, Severity
from vulcanary.reporters import write_json, write_sarif
from vulcanary.sbom import cyclonedx_document, spdx_document
from vulcanary.scanners import ruleset_manifest
from vulcanary.vex import openvex_document


class FixedClock:
    @staticmethod
    def now(tz=None):
        return datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def reports(empty=False):
    findings = [] if empty else [
        Finding("SCA-CONTRACT", "Synthetic advisory", "Contract fixture", severity,
                "dependency", "package-lock.json", index + 1, f"demo-{index}@1.0.0",
                "Upgrade to 1.0.1.", metadata={
                    "package": f"demo-{index}", "current_version": "1.0.0",
                    "ecosystem": "npm", "manager": "npm", "direct": index == 0,
                    "advisory": f"GHSA-contract-{index}",
                })
        for index, severity in enumerate(Severity)
    ]
    packages = [Package(f.metadata["package"], "1.0.0", "npm", "package-lock.json",
                        f.metadata["direct"], "npm") for f in findings]
    serialized = [f.to_dict() for f in findings]
    with ExitStack() as stack, tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for module in ("sbom", "vex", "dashboard"):
            stack.enter_context(patch(f"vulcanary.{module}.datetime", FixedClock))
        for module in ("sbom", "vex"):
            stack.enter_context(patch(f"vulcanary.{module}.uuid4", return_value=UUID(int=1)))
        for module in ("sbom", "vex", "reporters"):
            stack.enter_context(patch(f"vulcanary.{module}.__version__", "0.0.0-contract"))
        write_json(findings, root / "normalized.json", exceptions=[], policy={"fail_on": "high"})
        write_sarif(findings, root / "sarif.json", policy={"fail_on": "high"})
        if not empty:
            (root / "app.py").write_text(
                "def handler():\n    value = request.args.get('q')\n    eval(value)\n",
                encoding="utf-8")
        return {
            "normalized": json.loads((root / "normalized.json").read_text(encoding="utf-8")),
            "sarif": json.loads((root / "sarif.json").read_text(encoding="utf-8")),
            "cyclonedx": cyclonedx_document("contract-demo", packages, serialized),
            "spdx": spdx_document("contract-demo", packages, serialized),
            **({"openvex": openvex_document("contract-demo", serialized)} if serialized else {}),
            "ruleset": ruleset_manifest(),
            "receipt": remediation_receipt({
                "repository": "contract-demo", "branch": "local-fix",
                "files": ["package-lock.json"],
                "verification": {"passed": True, "skipped": False, "results": []},
                "validation": {"passed": True, "remaining": [], "finding_count": 0},
            }, [f.fingerprint for f in findings]),
            "experimental-dataflow": analyze_python_dataflow(root),
        }
