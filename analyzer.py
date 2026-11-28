"""SheShield analyzer: rules + context + (supporting) ML classifier, with explainable output.

Output is a risk indicator about the MESSAGE. It never states that a person committed an offence.
"""
import os
import re
import joblib

CATEGORY_LABELS = {
    "sextortion": "Sextortion (intimate-media threat)",
    "blackmail_extortion": "Blackmail / extortion",
    "threat": "Threat of violence",
    "harassment_abuse": "Harassment / abusive or sexual remarks",
    "cyberstalking_contact": "Cyberstalking / repeated unwanted contact",
    "impersonation": "Impersonation",
    "romance_scam": "Romance scam pattern",
    "financial_scam": "Financial scam pattern",
    "phishing": "Phishing pattern",
    "coercive_manipulation": "Coercive control / manipulation",
    "benign": "No threat pattern found",
}

# (indicator label, regex). Weight and 'why' are per category.
RULES = {
    "sextortion": dict(weight=50, why="Threatens to share or leak intimate photos/videos, usually to force payment or more images", ind=[
        ("Threat to post/leak intimate media", r"(leak|post|share|send|viral|upload|daal|dal dunga|haakth|hakth|haaki).{0,40}(nudes?|nude|private (pics?|photos?|videos?)|intimate|naked)|(nudes?|private (pics?|photos?|videos?)).{0,50}(leak|post|viral|everyone|sabko|ellarigu|daal|haak)"),
        ("Says they hold your intimate media", r"(i have|i recorded|mere paas|mujhe|ide|hatra ide|हैं|ಇದೆ).{0,40}(nudes?|nude|private|video call|नंगे|बेतल|ಬೆತ್ತಲೆ|ಖಾಸಗಿ)|(video call|वीडियो कॉल).{0,25}(record|रिकॉर्ड)"),
        ("Threat to make media viral", r"(viral|वायरल|ವೈರಲ್)"),
        ("Demands more intimate images", r"(send|bhej|kalsu|भेज|ಕಳಿಸು).{0,15}(more|aur|innu|और|ಇನ್ನೂ).{0,20}(photos?|pics?|videos?|nudes?|फोटो|वीडियो|ಫೋಟೋ)"),
    ]),
    "blackmail_extortion": dict(weight=45, why="Demands money or action under threat of exposing a secret, chats or reputation", ind=[
        ("Demand for money with a condition", r"(pay|send|transfer|give|de |dena|bhej|kodu|kalsu|दे |भेज|ಕೊಡು|ಕಳಿಸು).{0,40}(or|otherwise|warna|varna|illandre|illaandre|नहीं तो|वरना|ಇಲ್ಲಾಂದ್ರೆ|else|and they stay)"),
        ("Threat to reveal a secret / chats", r"(tell|expose|bata|bataunga|helthini|हे|बता|ಹೇಳ್ತೀನಿ).{0,40}(secret|raaz|राज़|gutthu|ಗುಟ್ಟು|chats?|screenshots?|family|parents|boss|office)|(screenshots?|चैट|chat).{0,40}(mere paas|i have|hatra ide|मेरे पास|ಹತ್ರ ಇದೆ)"),
        ("Threat to ruin reputation", r"(ruin|destroy|mitti|मिट्टी|maryade|ಮರ್ಯಾದೆ|izzat|इज़्ज़त).{0,30}(reputation|izzat|इज़्ज़त|tegith|ಮರ್ಯಾದೆ|mila)"),
        ("Threat to go to police/office", r"(police|पुलिस|ಪೊಲೀಸ).{0,30}(office|bata|helth|ಹೇಳ್ತೀನಿ|and your)"),
    ]),
    "threat": dict(weight=45, why="Threatens physical harm or says they know where you live", ind=[
        ("Threat to kill or hurt", r"(i will|i'll|will|i'm going to|im going to) (kill|hurt|beat|break|destroy)(?! it\b)(?! the\b)|(jaan se )?maar (dunga|dalunga)|जान से मार|मार दूँगा|मार दूंगा|ಕೊಂದು|ಕೊಂದು ಬಿಡ್ತೀನಿ|konde bid|kolthini|ಕೊಲ್ತೀನಿ"),
        ("Says they know where you live/stay", r"i know where you (live|stay|work)|pata hai tu kahan|पता है तू कहाँ|elli irthiya|ಎಲ್ಲಿ ಇರ್ತೀಯ"),
        ("Threat to break limbs", r"break your legs|haath.?pair tod|हाथ.?पैर तोड़|kai kaalu mur|ಕೈ ಕಾಲು ಮುರ"),
        ("Warning of retaliation", r"you will regret|watch your back|tujhe nahi chhodunga|नहीं छोड़ूँगा|bidalla|ಬಿಡಲ್ಲ"),
    ]),
    "harassment_abuse": dict(weight=30, why="Abusive, demeaning or unwanted sexual language directed at you", ind=[
        ("Demand for nude images", r"send (me )?(nudes?|nude pics?)|nude (bhej|kalsu)|नंगी फोटो भेज|ಬೆತ್ತಲೆ ಫೋಟೋ ಕಳಿಸು"),
        ("Sexual demand", r"(sleep|sex) with me"),
        ("Abusive slur", r"\b(slut|whore|bitch|bastard|randi)\b|बदचलन|ghatiya|घटिया|ketta|keta hudugi|ಕೆಟ್ಟ ಹುಡುಗಿ"),
        ("Demeaning remark", r"worthless|useless|nobody (will|likes)|bekaar ladki|बेकार लड़की|waste hudugi|ವ್ಯರ್ಥ"),
    ]),
    "cyberstalking_contact": dict(weight=30, why="Signs of monitoring you or repeated contact after you tried to stop it", ind=[
        ("Says they are watching/following you", r"(i('m| am)|main) (following|watching|dekh raha)|watching you|har jagah dekh|हर जगह देख|ಎಲ್ಲಾ ಕಡೆ ನೋಡ್ತಿದ್ದೀನಿ|ellaa kade nodthid"),
        ("Contact after blocking / new account", r"(blocked|block).{0,40}(new account|naya account|naye account)|new account since you blocked|नया अकाउंट|ಹೊಸ ಅಕೌಂಟ್|hosa account"),
        ("Demands an immediate reply", r"why are you (ignoring|blocking)|reply (kyun|right now)|रिप्लाई क्यों|ಯಾಕೆ ರಿಪ್ಲೈ|yaake reply|pick up the phone"),
        ("Knows your routine / location", r"your (schedule|route)|(time aur raasta|roz ka time)|ದಿನದ time|daari nanage"),
    ]),
    "impersonation": dict(weight=40, why="Claims to be a bank, police, employer or relative to pressure you", ind=[
        ("Claims to be bank/police/officer", r"(i am|this is|main|naanu|मैं).{0,25}(bank manager|police|cyber (cell|police)|बैंक|पुलिस|ಬ್ಯಾಂಕ್ ಮ್ಯಾನೇಜರ್)|bank ka manager|cyber police se"),
        ("Claims to be boss/relative on a new number", r"(new number|naya number|nayi number|hosa number|नया नंबर|ಹೊಸ ನಂಬರ್).{0,50}|your boss here|boss bol raha"),
        ("Asks for gift-card codes or urgent money", r"gift card.{0,25}code|send .{0,20}urgently|turant bhej|तुरंत भेज|takshana kalsu"),
    ]),
    "romance_scam": dict(weight=45, why="Affection or a hardship story used to ask for money or investment", ind=[
        ("Stranded/hardship story with a money ask", r"(stuck|phans|sikkihaak|फँस).{0,40}(airport|एयरपोर्ट|ticket|टिकट)|customs fee|कस्टम फीस|mother is in hospital"),
        ("Claims to be overseas (military) and wants to marry", r"(soldier|army|sena|सेना|videsh|विदेश|videshad).{0,50}(marry|shaadi|शादी|maduve)"),
        ("Asks you to invest (crypto) with them", r"(invest|invest karo|hoodi).{0,25}(crypto|bitcoin)|crypto.{0,30}(invest|future)"),
        ("Gift parcel / customs fee", r"gift.{0,30}(parcel|customs)|gift (bheja|kalsidini)|गिफ्ट भेजा"),
    ]),
    "financial_scam": dict(weight=45, why="Promises prizes, guaranteed returns or jobs in exchange for an upfront fee", ind=[
        ("Lottery / prize with a fee", r"(lottery|लॉटरी|ಲಾಟರಿ).{0,60}(fee|ಫೀ|शुल्क|फीस|processing)|processing fee"),
        ("Guaranteed or doubled returns", r"(double|दोगुना|dugna|ಡಬಲ್).{0,30}(return|paisa|money|duddu|पैसा|ಹಣ)|guarantee|गारंटी|ಗ್ಯಾರಂಟಿ"),
        ("Registration/insurance fee for a job or loan", r"(registration|insurance|बीमा|नोंदणಿ|ನೋಂದಣಿ).{0,25}(fee|फीस|ಶುಲ್ಕ|bharo|kattiri|kodi)|pay .{0,12}insurance first|insurance (bharo|kattiri)|पहले .{0,10}बीमा"),
        ("Asks you to scan a QR to 'return' money", r"scan (this )?qr|qr (scan|code).{0,20}return"),
    ]),
    "phishing": dict(weight=45, why="Pressure to share OTP/KYC/bank details or click a suspicious link", ind=[
        ("Asks for OTP", r"\botp\b|ओटीपी|ಒಟಿಪಿ"),
        ("KYC/account-block pressure", r"(kyc|केवाईसी|ಕೆವೈಸಿ).{0,40}(update|अपडेट|ಅಪ್‌ಡೇಟ್)|account (will be|ho jayega|band ho).{0,20}(suspend|block|band)|खाता|ಸ್ಥಗಿತ|account.{0,15}(suspend|block)"),
        ("Link to pay challan/fee/refund", r"(challan|चालान|refund|delivery|parcel).{0,60}(link|http)|http\S+"),
        ("Asks for bank/card details", r"(bank|card) details|card ki detail|कार्ड की डिटेल|card vivara|ಕಾರ್ಡ್ ವಿವರ"),
    ]),
    "coercive_manipulation": dict(weight=35, why="Language that isolates you, controls contact, or makes you doubt yourself", ind=[
        ("Controls who you can talk to", r"(not allowed|ijazat nahi|इजाज़त नहीं|bidalla).{0,30}(friends|dosto|दोस्त|snehit)|i decide who you|main tay karta|naanu nirdharisthini"),
        ("Demands password / deleting friends", r"(password|पासवर्ड|ಪಾಸ್‌ವರ್ಡ್).{0,25}(give|deta|देती|kodthidde|ಕೊಡ್ತಿದ್ದೆ)|delete your (male )?friends|doston ko delete|ಸ್ನೇಹಿತರನ್ನ ಡಿಲೀಟ್"),
        ("Isolation: only I care / don't tell anyone", r"don'?t tell anyone|only i care|kisi ko .{0,20}mat batana|किसी को .{0,25}मत बताना|yarigu helbeda|ಯಾರಿಗೂ ಹೇಳಬೇಡ"),
        ("Undermines your perception", r"you are (crazy|imagining)|nobody will believe you|tu pagal|तू पागल|koi tera yakeen|nobody else will ever put up"),
    ]),
}

FINANCIAL_CATS = {"romance_scam", "financial_scam", "phishing", "impersonation", "blackmail_extortion", "sextortion"}

MONEY_RE = re.compile(r"(rs\.?|₹|rupees?|rupay|rupaye|रुपये|ರೂಪಾಯಿ|\b\d{3,6}\s?(k|hazaar|हज़ार|saavira|ಸಾವಿರ)?\b|\blakh\b|लाख|ಲಕ್ಷ|\bpaise\b|पैसे|duddu|ದುಡ್ಡು|\bpay\b|transfer)", re.I)
DEADLINE_RE = re.compile(r"(tonight|in one hour|by \d|tomorrow|today|right now|immediately|urgent|aaj raat|kal subah|ghante|आज रात|कल सुबह|एक घंटे|ivattu raathri|naale|ಇವತ್ತು ರಾತ್ರಿ|ನಾಳೆ|ಒಂದು ಗಂಟೆ)", re.I)
INTIMATE_RE = re.compile(r"(nudes?|naked|private (pics?|photos?|videos?)|video call|intimate|नंगे|नंगी|प्राइवेट|बेतल|ಬೆತ್ತಲೆ|ಖಾಸಗಿ)", re.I)
# Benign idioms / reporting contexts that must not trigger violence rules
IDIOMS = re.compile(r"(kill (it|the)|killer|killing it|dhamaal|dhool ebbs|could scream|to death (with|by) (laughter|boredom))", re.I)
REPORTING_RE = re.compile(r"\b(he|she|they|someone|unknown)\b.{0,30}\b(said|told|sent|messaged|texted|wrote)\b|\bi received\b|\bi got (a )?(message|text)\b|\bwhat should i do\b", re.I)

LATIN_HINGLISH = set("hai nahi nahin kyun kya mera meri tera teri tujhe mujhe tu tum aap bhej dena warna varna paise paisa kal aaj raat kar karo karunga dunga denge sabko ghar wale bata bol raha rahi ladki jaan mat abhi bahut bhi toh to se ko ka ki ke hain tha thi main".split())
LATIN_KANGLISH = set("illa illandre ninna nanna nange ninage naanu neenu madi madthini kalsu kodu ide idini aagide ivattu naale beligge raathri duddu thumba yaake yaaru illa gottu maathadu mattu hudugi mane appa amma".split())


def detect_language(text: str) -> str:
    dev = len(re.findall(r"[ऀ-ॿ]", text))
    kan = len(re.findall(r"[ಀ-೿]", text))
    if kan >= 3 and kan >= dev:
        return "kn"
    if dev >= 3:
        return "hi"
    words = re.findall(r"[a-z']+", text.lower())
    if not words:
        return "en"
    h = sum(w in LATIN_HINGLISH for w in words)
    k = sum(w in LATIN_KANGLISH for w in words)
    if k >= 2 and k >= h:
        return "kanglish"
    if h >= 2:
        return "hinglish"
    return "en"


_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threat_model.joblib")
_BUNDLE = joblib.load(_path) if os.path.exists(_path) else None

NEXT = {
    "default": ["Do not reply, pay or share more. Keep the original messages.", "Save this as evidence in your vault.",
                "See Legal Action & Reporting for channels you can use."],
    "financial": ["Do not pay, share OTPs, card details or click links.", "If money was lost, call 1930 immediately and report on cybercrime.gov.in.",
                  "Save this as evidence in your vault."],
    "sextortion": ["You are not at fault. Do not pay and do not send more images.", "Do not delete the chat; save evidence first.",
                   "Open Emergency Support for step-by-step help."],
}


def _severity(score):
    return "none" if score == 0 else "low" if score < 40 else "medium" if score < 70 else "high"


def analyze(text: str, context: dict | None = None) -> dict:
    """context (optional): {"prior_categories": [...]} from earlier records in the same conversation."""
    text = text or ""
    lang = detect_language(text)
    hits = {}  # category -> list of (indicator, snippet)
    for cat, rule in RULES.items():
        for label, pat in rule["ind"]:
            try:
                m = re.search(pat, text, re.I | re.S)
            except re.error:
                m = None
            if m:
                snippet = m.group(0).strip()
                if len(snippet) > 80:
                    snippet = snippet[:77] + "…"
                hits.setdefault(cat, []).append((label, snippet))
    ctx = []
    idiom = bool(IDIOMS.search(text))
    if idiom and "threat" in hits:
        hits["threat"] = [h for h in hits["threat"] if not IDIOMS.search(h[1])]
        if not hits["threat"]:
            del hits["threat"]
        ctx.append("Idiom detected (e.g. 'kill it'); violence rule suppressed")

    money = bool(MONEY_RE.search(text))
    deadline = bool(DEADLINE_RE.search(text))
    intimate = bool(INTIMATE_RE.search(text))
    reporting = bool(REPORTING_RE.search(text))

    # context boosts / reclassification
    if intimate and "blackmail_extortion" in hits and "sextortion" not in hits:
        hits["sextortion"] = [("Intimate-media reference combined with a demand", "context")]
        ctx.append("Intimate media + extortion demand → treated as sextortion")
    if "sextortion" in hits and money:
        ctx.append("Payment demand present alongside media threat")
    if "sextortion" in hits and deadline:
        ctx.append("Deadline pressure present")
    if (context or {}).get("prior_categories"):
        pc = set(context["prior_categories"])
        if pc & set(hits):
            ctx.append("Same pattern already seen earlier in this conversation (escalation)")

    cat_scores = {}
    for cat, hs in hits.items():
        w = RULES[cat]["weight"]
        s = w + 12 * (len(hs) - 1)
        if cat in FINANCIAL_CATS and money:
            s += 8
        if deadline and cat in ("sextortion", "blackmail_extortion", "threat", "phishing", "financial_scam"):
            s += 8
        if cat == "sextortion" and intimate:
            s += 10
        if "same pattern" in " ".join(ctx):
            s += 8
        cat_scores[cat] = min(100, s)

    ml_probs, ml_top, ml_p = {}, None, 0.0
    if _BUNDLE and text.strip():
        m = _BUNDLE["model"]
        probs = m.predict_proba([text])[0]
        ml_probs = {c: float(p) for c, p in zip(m.classes_, probs)}
        ml_top = max(ml_probs, key=ml_probs.get)
        ml_p = ml_probs[ml_top]

    # primary category: rules first; the ML model only supports (or adds a low-confidence flag when no rule fired)
    if cat_scores:
        primary = max(cat_scores, key=cat_scores.get)
        score = cat_scores[primary]
        agree = ml_top == primary
        if agree:
            score = min(100, score + 5)
        n_ind = len(hits[primary])
        conf = "high" if (n_ind >= 2 and agree) or n_ind >= 3 else "medium" if (n_ind >= 2 or agree) else "low"
        # a second category lifts the score slightly (e.g. threat + extortion)
        if len(cat_scores) > 1:
            score = min(100, score + 6)
    elif ml_top and ml_top != "benign" and ml_p >= 0.55:
        primary = ml_top
        score = int(min(39, 20 + ml_p * 25))  # model-only: capped low/medium-low; never alarming alone
        conf = "low"
        hits[primary] = [("Wording similar to examples of this category (statistical match only)", f"model {ml_p:.2f}")]
        ctx.append("No explicit rule matched; this is a statistical match only")
    else:
        primary, score, conf = "benign", 0, "high" if (ml_top == "benign" and ml_p >= 0.5) else "medium"

    if reporting and primary != "benign":
        ctx.append("Message looks like a description of a message you received; analyse the original text instead")
        conf = "low" if conf == "high" else conf

    severity = _severity(score)
    findings = [{"category": c, "reason": RULES[c]["why"]} for c in sorted(cat_scores, key=cat_scores.get, reverse=True)]
    indicators = [{"label": l, "matched": s} for l, s in hits.get(primary, [])] if primary != "benign" else []
    if primary == "benign":
        explanation = "No threat, extortion, stalking or scam pattern was found in this text. This does not guarantee the sender is safe."
    else:
        explanation = (f"This text shows {len(indicators)} indicator(s) associated with {CATEGORY_LABELS[primary].lower()}. "
                       f"{RULES[primary]['why']}. This describes the wording only; it is not a finding about the sender.")
    nxt = NEXT["sextortion"] if primary == "sextortion" else NEXT["financial"] if primary in ("romance_scam", "financial_scam", "phishing", "impersonation") else NEXT["default"]
    high_sx = primary == "sextortion" and severity == "high" and conf in ("high", "medium") and (money or intimate or deadline)
    return {
        "score": score, "severity": severity, "findings": findings,
        "category": primary, "category_label": CATEGORY_LABELS[primary],
        "secondary_categories": [c for c in cat_scores if c != primary],
        "language": lang, "confidence": conf, "indicators": indicators, "context": ctx,
        "explanation": explanation, "next_steps": nxt,
        "emergency": {"sextortion": bool(high_sx)},
        "ml": {"top": ml_top, "probability": round(ml_p, 2)} if ml_top else None,
        "ml_probability": round(ml_p, 2) if ml_top else None,
    }
