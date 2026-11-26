import os
import re
import joblib
RULES = {
    "blackmail": {
        "weight": 45,
        "why": "Threatens to expose private photos/videos or demands money (sextortion pattern)",
        "patterns": [
            r"(leak|post|share|send).{0,25}(photos?|pics?|videos?|nudes?)",
            r"(photos?|pics?|videos?).{0,25}(viral|leak)",
            r"(send|pay|give).{0,20}(money|rs\.?|rupees).{0,30}(or|otherwise|else)",
            r"वायरल कर",
            r"ವೈರಲ್ ಮಾಡ",
            r"ಫೋಟೋ.{0,15}(ಲೀಕ್|ವೈರಲ್)",
        ],
    },
    "threat": {
        "weight": 40,
        "why": "Threatens violence or says they know where you live",
        "patterns": [
            r"(i will|i'll|will) (kill|hurt|beat|destroy)",
            r"i know where you (live|stay|work)",
            r"(jaan se )?maar (dunga|dalunga)",
            r"जान से मार",
            r"मार दूंगा",
            r"ಕೊಂದು",
            r"ಹೊಡೆದು",
        ],
    },
    "stalking": {
        "weight": 25,
        "why": "Signs of stalking or obsessive contact",
        "patterns": [
            r"i('m| am) (following|watching) you",
            r"why are you (ignoring|blocking) me",
            r"पीछा कर",
            r"peecha kar",
        ],
    },
    "sexual_harassment": {
        "weight": 30,
        "why": "Unwanted sexual demands or comments",
        "patterns": [
            r"send (me )?(nudes?|pics?)",
            r"(sleep|sex) with me",
        ],
    },
    "abuse": {
        "weight": 15,
        "why": "Abusive or demeaning language",
        "patterns": [
            r"\b(slut|whore|bitch|useless|stupid)\b",
        ],
    },
}


def analyze(text: str) -> dict:
    score = 0
    found = []
    for name, rule in RULES.items():
        for p in rule["patterns"]:
            if re.search(p, text, re.IGNORECASE | re.DOTALL):
                score += rule["weight"]
                found.append({"category": name, "reason": rule["why"]})
                break
    score = min(score, 100)
    if score == 0:
        level = "none"
    elif score < 40:
        level = "low"
    elif score < 70:
        level = "medium"
    else:
        level = "high"
    return {"score": score, "severity": level, "findings": found}
    import os
import joblib

_path = os.path.join(os.path.dirname(__file__), "toxicity_model.joblib")
_MODEL = joblib.load(_path) if os.path.exists(_path) else None

_rule_analyze = analyze


def analyze(text: str) -> dict:
    result = _rule_analyze(text)
    if _MODEL is not None:
        p = float(_MODEL.predict_proba([text])[0][1])
        result["ml_probability"] = round(p, 2)
        score = max(result["score"], int(p * 100))
        result["score"] = score
        if score == 0:
            result["severity"] = "none"
        elif score < 40:
            result["severity"] = "low"
        elif score < 70:
            result["severity"] = "medium"
        else:
            result["severity"] = "high"
    return result