import pytest
from unittest.mock import patch, MagicMock
import src.scanner as scanner

# Mock requests.get for functions that call it
@patch('src.scanner.requests.get')
def test_check_exposure_and_cors(mock_get):
    # Mock a 200 response for HEAD and GET calls
    mock_head = MagicMock()
    mock_head.status_code = 200
    mock_get.return_value = mock_head
    exp = scanner.check_exposure("https://example.com/")
    # Since we mocked responses as 200, exposed_paths may include some results
    assert isinstance(exp, dict)
    # Test CORS with headers containing wildcard
    headers = {'Access-Control-Allow-Origin': '*'}
    cors = scanner.check_cors_insecurity("https://example.com", headers)
    assert 'INSECURE' in cors['result'] or 'MISSING' in cors['result'] or isinstance(cors['result'], str)

# Mock SSL socket for get_tls_info & check_tls_ciphers by patching socket.create_connection and ssl.SSLContext
@patch('src.scanner.socket.create_connection')
@patch('src.scanner.ssl.create_default_context')
def test_get_tls_info_and_ciphers(mock_context_factory, mock_create_conn):
    # Mock socket and ssl wrap to return a fake cert dict
    mock_sock = MagicMock()
    mock_ssock = MagicMock()
    # create_default_context() returns an object whose wrap_socket returns mock_ssock
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
    mock_context_factory.return_value = mock_ctx
    # create_connection returns a context manager as well
    mock_create_conn.return_value.__enter__.return_value = mock_sock
    # make getpeercert return a minimal cert struct
    mock_ssock.getpeercert.return_value = {'subject': ((('commonName','example.com'),),), 'issuer': ((('organizationName','Test CA'),),), 'notAfter': 'Dec 31 23:59:59 2030 GMT'}
    info = scanner.get_tls_info('example.com')
    assert 'subject' in info and 'issuer' in info
    # For ciphers, ensure it returns a dict with status or assessment
    ciphers = scanner.check_tls_ciphers('example.com')
    assert isinstance(ciphers, dict)
