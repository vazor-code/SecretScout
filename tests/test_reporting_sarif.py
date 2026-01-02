import json
from secretscout.models import Finding, Severity
from secretscout.reporting import to_sarif


def test_sarif_is_valid_json():
    f = Finding(
        rule_id="github-token",
        rule_title="GitHub token",
        severity=Severity.high,
        file="a.py",
        line=1,
        col=1,
        match="ghp_…abcd",
        snippet="ghp_…abcd",
        fingerprint="x" * 64,
    )
    sarif = to_sarif([f])
    data = json.loads(sarif)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["ruleId"] == "github-token"
