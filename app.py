from flask import Flask, render_template, request, redirect, url_for
import pickle
import re
import requests
import base64
import os

app = Flask(__name__)

# ---------------- BASE DIRECTORY ----------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------- LOAD MODEL ----------------

VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")
MODEL_PATH = os.path.join(BASE_DIR, "phishing.pkl")

with open(VECTORIZER_PATH, "rb") as f:
    vector = pickle.load(f)

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# ---------------- VIRUSTOTAL API ----------------

# Vercel Environment Variable
# Name: VT_API_KEY
VT_API_KEY = os.environ.get(
    "VT_API_KEY",
    "b91d175a771c3f5820804894c6bc7f6d70a3584e2260e44b1d03abba081192ee"
)


def check_virustotal(url):

    if not VT_API_KEY:
        return {
            "status": "VirusTotal API Key Missing",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
        }

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )

        # URL not scanned before
        if response.status_code == 404:

            requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )

            return {
                "status": "Submitted for scanning",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
            }

        if response.status_code != 200:

            return {
                "status": "VirusTotal Error",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
            }

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "status": "Success",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

    except Exception as e:

        return {
            "status": str(e),
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
        }


# ---------------- LOGIN PAGE ----------------

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        return redirect(url_for("scan"))

    return render_template("index.html")


# ---------------- SCAN PAGE ----------------

@app.route("/scan", methods=["GET", "POST"])
def scan():

    predict = None
    url = ""

    vt_result = None
    malicious = 0
    suspicious = 0
    harmless = 0

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        # Remove http:// https:// www.
        cleaned_url = re.sub(r"^https?://(www\.)?", "", url)

        # ML Prediction

        prediction = model.predict(
            vector.transform([cleaned_url])
        )[0]

        if prediction == "bad":
            predict = "⚠️ Phishing Website"

        elif prediction == "good":
            predict = "✅ Safe Website"

        else:
            predict = "Unknown"

        # VirusTotal

        vt = check_virustotal(url)

        malicious = vt["malicious"]
        suspicious = vt["suspicious"]
        harmless = vt["harmless"]

        if vt["status"] == "Submitted for scanning":
            vt_result = "URL submitted to VirusTotal. Try again in a few seconds."

        elif vt["status"] == "VirusTotal API Key Missing":
            vt_result = "VirusTotal API key is not configured."

        elif malicious > 0:
            vt_result = "⚠️ Malicious"

        elif suspicious > 0:
            vt_result = "⚠️ Suspicious"

        else:
            vt_result = "✅ Safe"

    return render_template(
        "scan.html",
        predict=predict,
        url=url,
        vt_result=vt_result,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)