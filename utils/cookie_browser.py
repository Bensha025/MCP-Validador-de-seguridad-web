import asyncio
from playwright.async_api import async_playwright

# Abre el navegador sin interfaz para extraer las cookies.
def analyze_cookies_with_browser(url: str):
    """Función pública que ejecuta la versión async."""
    return asyncio.run(_analyze(url))


async def _analyze(url: str):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        try:
            await page.goto(url, timeout=20000, wait_until="networkidle")
        except Exception as e:
            await browser.close()
            return {"error": f"No se pudo cargar la página: {str(e)}"}

        cookies = await context.cookies()

        parsed = []

        for c in cookies:
            name = c.get("name")
            secure = c.get("secure", False)
            httponly = c.get("httpOnly", False)
            samesite = c.get("sameSite", None)

            # Clasificación de riesgo
            if not secure and not httponly:
                risk = "alto"
            elif not secure or not httponly:
                risk = "medio"
            else:
                risk = "bajo"

            parsed.append({
                "name": name,
                "value": c.get("value"),
                "domain": c.get("domain"),
                "path": c.get("path"),
                "expires": c.get("expires"),
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite,
                "risk": risk
            })

        await browser.close()

        return {
            "count": len(parsed),
            "cookies": parsed
        }
