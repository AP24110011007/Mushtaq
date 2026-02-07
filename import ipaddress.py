import ipaddress
from urllib.parse import urlparse

# -----------------------------
# CONFIG
# -----------------------------
TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "github.com",
    "microsoft.com", "amazon.com", "wikipedia.org"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update", "secure"
]

# -----------------------------
# HELPERS
# -----------------------------
def is_ip_address(netloc):
    try:
        ipaddress.ip_address(netloc)
        return True
    except ValueError:
        return False

def is_trusted_domain(domain):
    return any(domain.endswith(td) for td in TRUSTED_DOMAINS)

def classify_risk(score):
    if score >= 6:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"

# -----------------------------
# STATIC URL ANALYSIS
# -----------------------------
def analyze_url(url):
    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    if is_ip_address(domain):
        score += 2
        reasons.append("IP address used instead of domain")

    if len(url) > 100:
        score += 2
        reasons.append("Unusually long URL")
    elif len(url) > 70:
        score += 1
        reasons.append("Long URL")

    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path]
    if found_keywords:
        score += 1
        reasons.append(f"Suspicious keywords found: {found_keywords}")

    if any(domain.endswith(s) for s in SHORTENERS):
        score += 1
        reasons.append("URL shortener detected")

    if is_trusted_domain(domain):
        score -= 1
        reasons.append("Trusted domain detected")

    return max(score, 0), reasons

# -----------------------------
# SANDBOX IMITATION
# -----------------------------
def sandbox_imitation(events):
    score = 0
    log = []

    if events["redirects"] > 1:
        score += 2
        log.append("Multiple redirects observed")

    if events["external_domains"] > 2:
        score += 2
        log.append("Contacted multiple external domains")

    if events["js_obfuscation"]:
        score += 2
        log.append("Obfuscated JavaScript detected")

    if events["file_download"]:
        score += 3
        log.append("File download attempt detected")

    if events["permission_request"]:
        score += 1
        log.append("Browser permission requested")

    return score, log

# -----------------------------
# V2 ADDITIONS
# -----------------------------
def calculate_confidence(static_score, sandbox_score):
    if sandbox_score > 0:
        return "HIGH"
    if static_score == 0:
        return "MEDIUM"
    return "LOW"

def risk_range(base_score):
    return {
        "best_case": classify_risk(base_score),
        "worst_case": classify_risk(base_score + 5)
    }

def analyst_verdict(risk, confidence):
    if risk == "HIGH":
        return "Strong indicators of malicious intent detected."
    if risk == "MEDIUM":
        return "Suspicious patterns observed. Caution advised."
    if confidence == "LOW":
        return "No immediate threats detected, but visibility is limited."
    return "No significant threats detected."

# -----------------------------
# MAIN ANALYSIS PIPELINE
# -----------------------------
def analyze(url, sandbox_events):
    static_score, static_reasons = analyze_url(url)
    sandbox_score, sandbox_log = sandbox_imitation(sandbox_events)

    final_score = static_score + sandbox_score
    risk = classify_risk(final_score)
    confidence = calculate_confidence(static_score, sandbox_score)
    range_info = risk_range(static_score)
    verdict = analyst_verdict(risk, confidence)

    return {
        "url": url,
        "risk": risk,
        "confidence": confidence,
        "score": final_score,
        "risk_range": range_info,
        "verdict": verdict,
        "static_reasons": static_reasons,
        "sandbox_log": sandbox_log
    }

# -----------------------------
# USER INPUT MODE
# -----------------------------
if __name__ == "__main__":
    print("=== URL Risk Analyzer (V2) ===")

    url = input("Enter URL to analyze: ").strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    print("\nSimulating sandbox behavior (safe imitation)...\n")

    sandbox_events = {
        "redirects": 1,
        "external_domains": 2,
        "js_obfuscation": False,
        "file_download": False,
        "permission_request": False
    }

    result = analyze(url, sandbox_events)

    print("URL:", result["url"])
    print("Risk Level:", result["risk"])
    print("Confidence:", result["confidence"])
    print("Final Score:", result["score"])
    print("Risk Range:", result["risk_range"]["best_case"],
          "→", result["risk_range"]["worst_case"])
    print("Verdict:", result["verdict"])

    if result["static_reasons"]:
        print("\nStatic Analysis:")
        for r in result["static_reasons"]:
            print(" -", r)

    if result["sandbox_log"]:
        print("\nSandbox Imitation:")
        for s in result["sandbox_log"]:
            print(" -", s)
