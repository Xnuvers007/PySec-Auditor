import pytest
from unittest.mock import patch, MagicMock
from src.requester import create_session, safe_get

def test_create_session_headers():
    s = create_session()
    assert 'User-Agent' in s.headers
    assert s.headers['User-Agent'].startswith('PySec-Auditor')

@patch('src.requester.requests.Session.get')
def test_safe_get_calls(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_get.return_value = mock_resp
    s = create_session()
    r = safe_get(s, 'https://example.com', timeout=2, allow_redirects=False)
    mock_get.assert_called()
    assert r.status_code == 200
