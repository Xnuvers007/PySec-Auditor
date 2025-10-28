import pytest
from unittest.mock import patch, MagicMock
from src.scanner import check_http_version

@patch("src.scanner.requests.Session.get")
def test_check_http_version(mock_get):
    mock_resp = MagicMock()
    mock_resp.raw.version = 11
    mock_get.return_value = mock_resp
    result = check_http_version("https://example.com")
    assert result["status"] == "OK"
    assert "HTTP/1.1" in result["http_version"]
