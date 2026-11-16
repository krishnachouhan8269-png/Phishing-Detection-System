
from flask import Flask, send_file, request, jsonify
from urllib.parse import urlparse
import ipaddress

app = Flask(__name__)


@app.route("/")
def home():
    return send_file("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL"})

    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    score = 0
    reasons = []

    if parsed.scheme != "https":
        score += 20
        reasons.append("HTTPS is missing")

    is_ip = False

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
        score += 30
        reasons.append("IP address used as domain")
    except ValueError:
        pass

    if not is_ip and hostname.count(".") >= 3:
        score += 10
        reasons.append("Too many subdomains")

    if "-" in hostname:
        score += 5
        reasons.append("Hyphen in domain")

    if "@" in url:
        score += 20
        reasons.append("@ symbol found in URL")

    if len(url) > 75:
        score += 10
        reasons.append("URL is too long")

    score = min(score, 100)

    if score >= 50:
        risk = "POTENTIALLY PHISHING"
    elif score >= 25:
        risk = "SUSPICIOUS"
    else:
        risk = "LOW RISK"

    return jsonify({
        "score": score,
        "risk": risk,
        "reasons": reasons
    })


if __name__ == "__main__":
    app.run(debug=True)
