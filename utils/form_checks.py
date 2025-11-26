import re

# Analiza código HTML directamente.
def analyze_forms(html):
    forms = re.findall(r"<form[^>]*?>", html, re.IGNORECASE)
    methods = re.findall(r"method=[\"'](.*?)[\"']", html, re.IGNORECASE)

    return {
        "forms_detected": len(forms),
        "methods": methods if methods else ["GET (default)"]
    }
