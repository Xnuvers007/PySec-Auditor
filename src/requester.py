import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def create_session():
    session = requests.Session()
    session.headers.update({"User-Agent": "PySec-Auditor/10.0"})
    return session

def safe_get(session, url, **kwargs):
    return session.get(url, timeout=kwargs.get("timeout", 10), verify=False, allow_redirects=kwargs.get("allow_redirects", True), stream=kwargs.get("stream", False))
