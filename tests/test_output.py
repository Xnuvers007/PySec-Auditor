import json
from src.output import generate_html_report
def test_generate_html_report_basic():
    data = {"Target": "https://example.com", "Audit_Time": "2025-10-29T00:00:00", "Security_Headers": {"X-Frame-Options": {"value": "DENY","status": "OK"}}}
    html = generate_html_report(data)
    assert "<h1>PySec Auditor Report</h1>" in html or "PySec Auditor Report" in html
    assert "X-Frame-Options" in html
