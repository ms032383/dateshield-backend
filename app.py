from flask import Flask, request, jsonify
from flask_cors import CORS
import io
import re

from PIL import Image
import pytesseract

# app.py mein ye line update karein
import pytesseract
import os

# Docker environment mein tesseract yahan hota hai
pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'


# ================== APP SETUP ==================
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})


# --- YE LOGIC YAHAN PASTE KAREIN ---
if os.environ.get('RENDER') or os.environ.get('RAILWAY_ENVIRONMENT') or os.path.exists('/usr/bin/tesseract'):
    # Linux (Render/Railway/Docker) ka path
    pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'
else:
    # Aapka local Windows path
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
# ----------------------------------

# # ================== TESSERACT PATH ==================
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# ================== WEIGHTED RULE ENGINE ==================
SCAM_WEIGHTS = {
    # Payment (high)
    "upi": 35,
    "gpay": 30,
    "phonepe": 30,
    "pay now": 35,
    "pay first": 35,
    "advance": 30,
    "deposit": 30,

    # Cafe scam (medium)
    "cafe": 18,
    "café": 18,
    "entry": 18,
    "cover": 18,
    "table booked": 16,
    "menu link": 16,
    "club": 16,

    # Urgency / manipulation
    "jaldi": 14,
    "abhi": 12,
    "today only": 14,
    "5 min": 12,
    "urgent": 14,
    "quick": 10,
}

NORMALIZE_MAP = {
    # pay / send
    "bhej do": "send",
    "bhejdo": "send",
    "bhej": "send",
    "send kr": "send",
    "send karo": "send",
    "bhejna": "send",

    "pay kr": "pay",
    "pay karo": "pay",
    "pay krdo": "pay",
    "payment kr": "pay",
    "payment karo": "pay",

    # urgency
    "jaldi karo": "jaldi",
    "abhi karo": "abhi",
    "abhi aa jao": "abhi",

    # video call
    "vc": "video call",
    "video call nahi": "no video call",
    "vc nahi": "no video call",
}

REPLY_TEMPLATES = {
    "payment": {
        "sigma": "No advance payments. Don’t contact me again.",
        "classy": "I’m not comfortable with advance payments.",
        "ghost": "..."
    },
    "cafe": {
        "sigma": "I don’t do paid meetups.",
        "classy": "I prefer meeting without entry or cover charges.",
        "ghost": "..."
    },
    "off_app": {
        "sigma": "Let’s keep the conversation here.",
        "classy": "I prefer chatting on this app for now.",
        "ghost": "..."
    },
    "generic_high": {
        "sigma": "Not interested. Bye.",
        "classy": "I don’t think we are a match.",
        "ghost": "..."
    }
}






AMOUNT_RE = re.compile(r"(₹|rs\.?|inr)\s*\d{2,6}", re.IGNORECASE)
UPI_ID_RE = re.compile(r"[\w\.\-]{2,}@[\w]{2,}", re.IGNORECASE)
MAP_LINK_RE = re.compile(r"(maps\.app\.goo\.gl|goo\.gl/maps|google\.com/maps)", re.IGNORECASE)
PHONE_RE = re.compile(r"(\+91[\s\-]?)?\b[6-9]\d{9}\b")
IG_RE = re.compile(r"\b(@[a-z0-9._]{3,30}|instagram\.com\/[a-z0-9._]{3,30}|ig[:\s])", re.IGNORECASE)


# ================== OCR ==================
def extract_text_from_image(file_storage) -> str:
    img = Image.open(io.BytesIO(file_storage.read())).convert("RGB")
    return (pytesseract.image_to_string(img) or "").strip()

# ================== RULE ANALYSIS ==================
def analyze_text(text: str):
    raw = text or ""
    t = normalize_hinglish(raw)

    score = 0
    red_flags = []
    reasons = []
    hits = []

    # 1) weighted keywords
    for k, w in SCAM_WEIGHTS.items():
        if k in t:
            score += w
            hits.append((k, w))
            reasons.append(f"Keyword '{k}' (+{w})")
            # keep red_flags clean (not too spammy)
            if k in ["upi", "pay now", "pay first", "advance", "deposit"]:
                red_flags.append("Payment push / advance asked")
            if k in ["cafe", "café", "entry", "cover", "menu link", "table booked", "club"]:
                red_flags.append("Pushes specific cafe/club")
            if k in ["jaldi", "abhi", "urgent", "today only", "5 min", "quick"]:
                red_flags.append("Urgency to meet / decide fast")

    # 2) patterns
    if AMOUNT_RE.search(raw):
        score += 20
        reasons.append("Money amount detected (+20)")
        red_flags.append("Mentions money amount")

    if UPI_ID_RE.search(raw):
        score += 25
        reasons.append("UPI/payment handle detected (+25)")
        red_flags.append("Shares UPI/payment handle")

    if MAP_LINK_RE.search(raw):
        score += 10
        reasons.append("Map link detected (+10)")
        red_flags.append("Unknown location map link")

    if PHONE_RE.search(raw):
        score += 10
        reasons.append("Phone number shared (+10)")
        red_flags.append("Asks to move off-app / shares phone number")

    if IG_RE.search(raw):
        score += 8
        reasons.append("Instagram handle/link mentioned (+8)")
        red_flags.append("Moves conversation to Instagram")

    # 3) explicit behavior phrases (normalized)
    if "no video call" in t:
        score += 10
        reasons.append("Avoids video call (+10)")
        red_flags.append("Avoids video call")

    # clamp
    score = max(0, min(100, score))

    # risk buckets
    if score >= 70:
        risk = "HIGH"
    elif score >= 35:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    # confidence (simple)
    # high confidence if score high AND at least 2 strong signals
    strong_signals = 0
    if any(k in t for k in ["upi", "pay now", "pay first", "advance", "deposit"]):
        strong_signals += 1
    if any(k in t for k in ["cafe", "entry", "cover", "menu link", "table booked", "club"]):
        strong_signals += 1
    if AMOUNT_RE.search(raw) or UPI_ID_RE.search(raw):
        strong_signals += 1

    if risk == "HIGH":
        confidence = 0.75 + (0.08 * min(3, strong_signals))  # 0.75–0.99
    elif risk == "MEDIUM":
        confidence = 0.55 + (0.06 * min(3, strong_signals))  # 0.55–0.73
    else:
        confidence = 0.40 + (0.04 * min(3, strong_signals))  # 0.40–0.52

    confidence = round(min(0.99, confidence), 2)

    # dedupe red flags
    red_flags = list(dict.fromkeys(red_flags))
    if not red_flags:
        red_flags = ["Low signal red flags"]

    # keep reasons short (top 6)
    reasons = reasons[:6]

    return score, risk, red_flags, confidence, reasons, hits

# ================== VERDICT ==================
def make_verdict_and_roast(risk: str, text: str):
    t = text.lower()

    if risk == "HIGH":
        verdict = "RUN BRO"
        roast = "UPI + cafe + urgency? Ye date nahi, scam speedrun hai."
    elif risk == "MEDIUM":
        verdict = "SUS BUT OK"
        roast = "Thoda shady lag raha. Proof maango, pyaar nahi."
    else:
        verdict = "SAFE-ish"
        roast = "Green vibes, par dimaag ON rakho."

    if "cafe" in t and ("upi" in t or "advance" in t):
        roast = "Classic Cafe Scam combo detected 🚨"

    return verdict, roast


def normalize_hinglish(text: str) -> str:
    t = (text or "").lower()
    for src, dst in NORMALIZE_MAP.items():
        t = t.replace(src, dst)
    return t
def pick_reply_triggers(text: str):
    t = (text or "").lower()
    triggers = set()

    if any(k in t for k in ["upi", "pay", "advance", "deposit"]):
        triggers.add("payment")

    if any(k in t for k in ["cafe", "entry", "cover", "menu link", "table booked"]):
        triggers.add("cafe")

    if any(k in t for k in ["instagram", "ig", "phone", "call me"]):
        triggers.add("off_app")

    return triggers


def build_suggested_replies(text: str, risk: str):
    triggers = pick_reply_triggers(text)

    # Priority: payment > cafe > off_app
    if "payment" in triggers:
        return REPLY_TEMPLATES["payment"]

    if "cafe" in triggers:
        return REPLY_TEMPLATES["cafe"]

    if "off_app" in triggers:
        return REPLY_TEMPLATES["off_app"]

    # fallback
    if risk == "HIGH":
        return REPLY_TEMPLATES["generic_high"]

    return {
        "sigma": "Let’s take it slow.",
        "classy": "I’d like to know you better first.",
        "ghost": "..."
    }







# ================== ROUTES ==================
@app.route('/')
def health_check():
    return jsonify({"status": "online", "message": "DateShield Backend is Live on Railway!"}), 200

@app.post("/scan")
def scan():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    extracted_text = extract_text_from_image(file)
    hint = request.form.get("hint", "")
    final_text = f"{extracted_text}\n{hint}"

    toxicity_score, scam_risk, red_flags, confidence, reasons, hits = analyze_text(final_text)
    verdict, roast = make_verdict_and_roast(scam_risk, final_text)
    suggested_replies = build_suggested_replies(final_text, scam_risk)

    return jsonify({
        "toxicity_score": toxicity_score,
        "scam_risk": scam_risk,
        "verdict": verdict,
        "roast": roast,
        "red_flags": red_flags,
        "confidence": confidence,
        "reasons": reasons,
        "extracted_text": extracted_text,
        "suggested_replies": suggested_replies,
    }), 200


@app.post("/scan_text")
def scan_text():
    data = request.get_json(silent=True) or {}

    you_text = (data.get("you_text") or "").strip()
    other_text = (data.get("other_text") or "").strip()

    # Priority: analyze OTHER person text (scammer usually)
    final_text = other_text if other_text else (you_text + "\n" + other_text).strip()

    if not final_text:
        return jsonify({"error": "Empty text provided"}), 400

    toxicity_score, scam_risk, red_flags, confidence, reasons, hits = analyze_text(final_text)
    verdict, roast = make_verdict_and_roast(scam_risk, final_text)
    suggested_replies = build_suggested_replies(final_text, scam_risk)  # if you added this earlier

    return jsonify({
        "toxicity_score": int(toxicity_score),
        "scam_risk": scam_risk,
        "verdict": verdict,
        "roast": roast,
        "red_flags": red_flags,
        "confidence": confidence,
        "reasons": reasons,
        "extracted_text": final_text,  # now this is "refined text"
        "suggested_replies": suggested_replies,
        "sender_split": {
            "you_len": len(you_text),
            "other_len": len(other_text)
        }
    }), 200




# ================== RUN ==================
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
