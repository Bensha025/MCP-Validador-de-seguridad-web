# utils/security_checks.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# -----------------------------------------
# Seguridad esperada
# -----------------------------------------
SECURITY_HEADERS = [
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy'
]


# -----------------------------------------
# Verificar si la URL usa HTTPS
# -----------------------------------------
def check_https(url: str) -> bool:
    return url.lower().startswith('https://')


# -----------------------------------------
# Verificar headers de seguridad
# -----------------------------------------
def check_security_headers(headers: dict) -> dict:
    result = {}
    for h in SECURITY_HEADERS:
        value = headers.get(h)
        result[h] = {
            "present": value is not None,
            "value": value or "NOT FOUND"
        }
    return result



# -----------------------------------------
# Revisar CORS
# -----------------------------------------
def check_cors(headers: dict) -> dict:
    cors = {}
    allow_origin = headers.get('Access-Control-Allow-Origin')

    if allow_origin:
        cors['allow_origin'] = allow_origin
        cors['weak_cors'] = allow_origin.strip() == '*'
    else:
        cors['allow_origin'] = 'NOT FOUND'
        cors['weak_cors'] = False

    return cors


# -----------------------------------------
# Detectar redirecciones e inseguras
# -----------------------------------------
def detect_redirects(url: str, session: requests.Session) -> dict:
    try:
        r = session.get(url, allow_redirects=True, timeout=10)
        chain = [resp.url for resp in r.history] + [r.url]

        # detectar redirecciones inseguras
        insecure_redirect = any(
            u.lower().startswith('http://') and not u.lower().startswith('https://')
            for u in chain
        )

        return {
            "final_url": r.url,
            "history": chain,
            "insecure_redirect_chain": insecure_redirect
        }

    except Exception as e:
        return {"error": str(e)}


# -----------------------------------------
# Extraer formularios del HTML
# -----------------------------------------
def extract_forms(html: str, base_url: str) -> list:
    soup = BeautifulSoup(html, 'html.parser')
    forms = []

    for f in soup.find_all('form'):
        action = f.get('action') or ''
        method = f.get('method', 'get').lower()
        inputs = []

        for inp in f.find_all(['input', 'textarea', 'select']):
            typ = inp.get('type', inp.name)
            name = inp.get('name')
            inputs.append({"name": name, "type": typ})  # ← CORREGIDO

        forms.append({
            "action": urljoin(base_url, action),
            "method": method,
            "inputs": inputs
        })

    return forms


# -----------------------------------------
# Calcular score de seguridad
# -----------------------------------------
def score_security(details: dict) -> int:
    score = 100

    # penalizar si no usa HTTPS
    if not details.get("https", True):
        score -= 20

    # penalizar por headers faltantes
    headers = details.get("security_headers", {})
    for h, v in headers.items():
        if v == 'NOT FOUND':
            score -= 5

    # penalizar CORS débil
    cors = details.get("cors", {})
    if cors.get("weak_cors", False):
        score -= 10

    # penalizar redirecciones inseguras
    redirects = details.get("redirects", {})
    if redirects.get("insecure_redirect_chain", False):
        score -= 15

    # score mínimo
    return max(score, 0)
