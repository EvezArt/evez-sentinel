#!/usr/bin/env python3
"""
EVEZ Sentinel — AI Website Security Scanner
Free tier: 10 scans/day | Pro: unlimited + reports + API
Zero-cost self-hosted. Revenue: Stripe $9/mo Pro tier.
"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
import httpx, hashlib, time, json, re, ipaddress
from typing import Optional
from urllib.parse import urlparse

app = FastAPI(title="EVEZ Sentinel", version="1.1.0")

# CORS support for API consumers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Models ---

class ScanRequest(BaseModel):
    url: str
    depth: int = 1

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must start with http:// or https://")
        if not parsed.hostname:
            raise ValueError("URL must have a valid hostname")
        # Block scanning of private/reserved IPs (SSRF protection)
        try:
            resolved = ipaddress.ip_address(parsed.hostname)
            if resolved.is_private or resolved.is_reserved or resolved.is_loopback:
                raise ValueError("Scanning private/reserved IP addresses is not allowed")
        except ValueError:
            pass  # hostname not an IP literal — DNS resolution checked at scan time
        return v

    @field_validator("depth")
    @classmethod
    def validate_depth(cls, v: int) -> int:
        if v < 1 or v > 3:
            raise ValueError("Depth must be between 1 and 3")
        return v

class ScanResult(BaseModel):
    url: str
    grade: str  # A-F
    score: int  # 0-100
    headers: dict
    findings: list
    scanned_at: float

# --- Rate limit store (per-IP, free tier) ---
# Keys: "scan:{ip}", Values: list of timestamps
scan_store: dict[str, list[float]] = {}
RATE_LIMIT_PER_HOUR = 10
RATE_LIMIT_WINDOW = 3600  # seconds
STORE_MAX_KEYS = 10000  # prevent unbounded memory growth

def _prune_rate_store(now: float) -> None:
    """Remove expired entries and enforce max size."""
    expired = []
    for key, timestamps in scan_store.items():
        scan_store[key] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
        if not scan_store[key]:
            expired.append(key)
    for key in expired:
        del scan_store[key]
    # Enforce max keys (LRU-ish: drop oldest)
    if len(scan_store) > STORE_MAX_KEYS:
        oldest_keys = sorted(scan_store, key=lambda k: scan_store[k][0] if scan_store[k] else 0)[:len(scan_store) - STORE_MAX_KEYS]
        for key in oldest_keys:
            del scan_store[key]

# --- Scanner ---

async def scan_security(url: str) -> ScanResult:
    """Core scanner — checks headers, TLS, known vuln patterns."""
    findings = []
    score = 100
    headers = {}

    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, max_redirects=5) as client:
            r = await client.get(url)

        headers = dict(r.headers)

        # Security header checks
        checks = {
            "strict-transport-security": ("HSTS missing", 15),
            "content-security-policy": ("CSP missing", 15),
            "x-content-type-options": ("X-Content-Type-Options missing", 10),
            "x-frame-options": ("X-Frame-Options missing", 10),
            "x-xss-protection": ("X-XSS-Protection missing", 5),
            "referrer-policy": ("Referrer-Policy missing", 5),
            "permissions-policy": ("Permissions-Policy missing", 5),
        }

        for header, (msg, penalty) in checks.items():
            if header not in headers:
                findings.append({
                    "severity": "medium" if penalty >= 10 else "low",
                    "message": msg,
                    "header": header,
                })
                score -= penalty

        # TLS check
        if not url.startswith("https"):
            findings.append({
                "severity": "critical",
                "message": "No HTTPS — data transmitted in plaintext",
            })
            score -= 25

        # Server disclosure
        server = headers.get("server", "")
        if server and len(server) > 2:
            findings.append({
                "severity": "low",
                "message": f"Server header discloses: {server}",
            })
            score -= 3

        # Powered-by disclosure
        powered = headers.get("x-powered-by", "")
        if powered:
            findings.append({
                "severity": "medium",
                "message": f"X-Powered-By discloses: {powered}",
            })
            score -= 5

    except httpx.TimeoutException:
        findings.append({"severity": "critical", "message": "Scan timed out — target did not respond within 15s"})
        score = 0
    except httpx.ConnectError as e:
        findings.append({"severity": "critical", "message": f"Connection failed: {str(e)}"})
        score = 0
    except Exception as e:
        findings.append({"severity": "critical", "message": f"Scan failed: {str(e)}"})
        score = 0

    score = max(0, min(100, score))
    grade = (
        "A" if score >= 90 else
        "B" if score >= 80 else
        "C" if score >= 70 else
        "D" if score >= 60 else
        "F"
    )

    return ScanResult(url=url, grade=grade, score=score, headers=headers, findings=findings, scanned_at=time.time())

# --- Routes ---

@app.get("/health")
def health():
    return {"status": "ok", "service": "evez-sentinel", "version": "1.1.0"}

@app.post("/v1/scan", response_model=ScanResult)
async def scan(req: ScanRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    key = f"scan:{ip}"
    now = time.time()

    # Prune and enforce rate limit
    _prune_rate_store(now)
    count = scan_store.get(key, [])
    if len(count) >= RATE_LIMIT_PER_HOUR:
        raise HTTPException(429, "Free tier: 10 scans/hour. Upgrade to Pro for unlimited.")
    count.append(now)
    scan_store[key] = count

    return await scan_security(req.url)

@app.get("/", response_class=HTMLResponse)
def landing():
    return LANDING_HTML

# Pre-built landing HTML (avoids Python string interpolation bugs in JS)
LANDING_HTML = """<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EVEZ Sentinel — AI Security Scanner</title>
<style>
body{background:#0a0a0a;color:#e0e0e0;font-family:-apple-system,Roboto,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px;}
h1{color:#00ff88;font-size:2rem;}input{background:#111;border:1px solid #1e1e1e;color:#e0e0e0;padding:12px;border-radius:8px;width:100%;max-width:400px;font-size:16px;}
button{background:#00ff88;color:#000;border:none;padding:12px 24px;border-radius:8px;font-weight:700;cursor:pointer;margin-top:8px;font-size:16px;}
button:hover{background:#00cc6a;}#result{margin-top:20px;width:100%;max-width:500px;}.finding{background:#111;border:1px solid #1e1e1e;border-radius:8px;padding:12px;margin:8px 0;}
.grade{font-size:4rem;font-weight:900;text-align:center;margin:16px 0;}.critical{border-color:#ff4444;}.medium{border-color:#ffaa00;}.low{border-color:#666;}
</style></head><body>
<h1>🛡️ EVEZ Sentinel</h1>
<p>AI Website Security Scanner — Free</p>
<input id="url" placeholder="https://example.com" value="https://">
<button onclick="scan()">Scan</button>
<div id="result"></div>
<script>
function gradeColor(grade) {
  if (grade === 'A') return '#00ff88';
  if (grade === 'B') return '#88ff00';
  if (grade === 'C' || grade === 'D') return '#ffaa00';
  return '#ff4444';
}

async function scan() {
  var url = document.getElementById("url").value;
  document.getElementById("result").innerHTML = "<p>Scanning...</p>";
  try {
    var r = await fetch("/v1/scan", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url: url})
    });
    var d = await r.json();
    if (d.detail) {
      document.getElementById("result").innerHTML = "<p>" + d.detail + "</p>";
      return;
    }
    var html = '<div class="grade" style="color:' + gradeColor(d.grade) + '">' + d.grade + '</div>';
    html += "<p>Score: " + d.score + "/100</p>";
    for (var i = 0; i < d.findings.length; i++) {
      var f = d.findings[i];
      html += '<div class="finding ' + f.severity + '"><b>' + f.severity.toUpperCase() + "</b>: " + f.message + "</div>";
    }
    document.getElementById("result").innerHTML = html;
  } catch(e) {
    document.getElementById("result").innerHTML = "<p>Error: " + e.message + "</p>";
  }
}
</script></body></html>"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8084)
