from fastapi import FastAPI
from pydantic import BaseModel
from utils.security_checks import check_security_headers
from utils.form_checks import analyze_forms
from utils.reporter import generate_pdf_report
from utils.cookie_browser import analyze_cookies_with_browser
import requests

#
app = FastAPI()

class ScanRequest(BaseModel):
    url: str
    generate_pdf: bool = False


# Definimos endpoints.
@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
def scan(req: ScanRequest):

    # --- Petición HTML normal para headers y forms ---
    try:
        response = requests.get(
            req.url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            }
        )
    except Exception as e:
        return {"error": f"No se pudo acceder a la URL: {str(e)}"}

    # --- Cookies con navegador real ---
    cookie_analysis = analyze_cookies_with_browser(req.url)

    analysis = {
        "url": req.url,
        "status_code": response.status_code,
        "security_headers": check_security_headers(response.headers),
        "cookies": cookie_analysis,
        "forms": analyze_forms(response.text),
    }

    # -------------------------
    # SCORE
    # -------------------------
    score = 100

    for h, v in analysis["security_headers"].items():
        if not v.get("present", False):
            score -= v.get("penalty", 5)

    for cookie in analysis["cookies"]["cookies"]:
        if cookie["risk"] == "alto":
            score -= 10
        elif cookie["risk"] == "medio":
            score -= 5

    analysis["score"] = max(score, 0)

    # PDF opcional
    if req.generate_pdf:
        pdf_path = generate_pdf_report(analysis)
        analysis["pdf_report"] = pdf_path
    else:
        analysis["pdf_report"] = None

    return analysis
