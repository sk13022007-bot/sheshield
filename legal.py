"""Legal Action & Reporting: maps a detected incident category to POTENTIALLY relevant Indian
provisions and official reporting channels.

This is informational assistance, not legal advice. Nothing here says anyone committed an
offence. Only a court can establish that. Provisions are listed by their current names
(Bharatiya Nyaya Sanhita, 2023 and the Information Technology Act, 2000). Old IPC numbers
are intentionally not used.

Verification record: section numbers and headings were checked on 2026-11-28 against
bare-act text and legal references that quote the Act (BNS 74-79, 308, 318, 319, 351;
IT Act 66C, 66D, 66E, 67, 67A). Helplines were checked against the National Commission for
Women, PIB and Ministry of Women and Child Development pages. Penalties are deliberately
NOT stated, because they change with amendments. Confirm against India Code
(https://www.indiacode.nic.in) or the Gazette before relying on any provision.
"""

CHECKED_ON = "2026-11-28"

DISCLAIMER = ("This is general information to help you understand possible options. It is not legal advice, "
              "and it does not say that any person has committed an offence. Whether a provision applies "
              "depends on facts that police and courts decide. A lawyer or legal services authority can advise on your case.")

STATUS_EXPLAINER = {
    "observed": "Observed: patterns SheShield found in the text you provided. These are automated and can be wrong.",
    "alleged": "Alleged: who sent the message, and what they intended, are claims you may make in a complaint. SheShield cannot confirm them.",
    "established": "Established: only a court can decide that an offence was committed.",
}

P = {
    "BNS-75": dict(act="Bharatiya Nyaya Sanhita, 2023", section="75", title="Sexual harassment",
                   covers="Unwelcome physical contact and advances, a demand or request for sexual favours, showing pornography against a woman's will, or sexually coloured remarks. The section is written for acts by a man against a woman.",
                   url="https://www.indiacode.nic.in/bitstream/123456789/20062/1/a202345.pdf"),
    "BNS-77": dict(act="Bharatiya Nyaya Sanhita, 2023", section="77", title="Voyeurism",
                   covers="Watching or capturing images of a woman in a private act, and sharing such images. Includes spreading images that were taken with consent but shared beyond what she agreed to.",
                   url="https://www.indiacode.nic.in/bitstream/123456789/20062/1/a202345.pdf"),
    "BNS-78": dict(act="Bharatiya Nyaya Sanhita, 2023", section="78", title="Stalking",
                   covers="Following a woman or repeatedly contacting her to foster personal interaction despite clear disinterest, and monitoring her use of the internet, email or other electronic communication.",
                   url="https://www.indiacode.nic.in/bitstream/123456789/20062/1/a202345.pdf"),
    "BNS-79": dict(act="Bharatiya Nyaya Sanhita, 2023", section="79", title="Word, gesture or act intended to insult the modesty of a woman",
                   covers="Words, sounds, gestures or objects intended to insult a woman's modesty and meant to be heard or seen by her, or intruding on her privacy.",
                   url="https://www.indiacode.nic.in/bitstream/123456789/20062/1/a202345.pdf"),
    "BNS-308": dict(act="Bharatiya Nyaya Sanhita, 2023", section="308", title="Extortion",
                    covers="Intentionally putting a person in fear of injury (including fear of an accusation) to dishonestly make them hand over property or something of value. Sub-sections cover putting or attempting to put a person in fear.",
                    url="https://www.indiacode.nic.in/bitstream/123456789/20062/1/a202345.pdf"),
    "BNS-318": dict(act="Bharatiya Nyaya Sanhita, 2023", section="318", title="Cheating",
                    covers="Deceiving someone to dishonestly induce them to hand over property or do something they would not otherwise do. Replaces several former cheating provisions.",
                    url="https://www.indiacode.nic.in/bitstream/123456789/20062/1/a202345.pdf"),
    "BNS-319": dict(act="Bharatiya Nyaya Sanhita, 2023", section="319", title="Cheating by personation",
                    covers="Cheating by pretending to be another person, or knowingly substituting one person for another. Applies whether the person pretended to be is real or imaginary.",
                    url="https://www.indiacode.nic.in/bitstream/123456789/20062/1/a202345.pdf"),
    "BNS-351": dict(act="Bharatiya Nyaya Sanhita, 2023", section="351", title="Criminal intimidation",
                    covers="Threatening a person with injury to their person, reputation or property, or to someone they care about, to cause alarm or to make them do or avoid something. Aggravated forms include anonymous threats and threats of death or grievous hurt.",
                    url="https://www.indiacode.nic.in/bitstream/123456789/20062/1/a202345.pdf"),
    "IT-66C": dict(act="Information Technology Act, 2000", section="66C", title="Identity theft",
                   covers="Fraudulently or dishonestly using another person's electronic signature, password or other unique identification feature.",
                   url="https://www.indiacode.nic.in"),
    "IT-66D": dict(act="Information Technology Act, 2000", section="66D", title="Cheating by personation using a computer resource",
                   covers="Cheating by personation by means of a communication device or computer resource, for example a fake profile or a spoofed identity used to deceive.",
                   url="https://www.indiacode.nic.in"),
    "IT-66E": dict(act="Information Technology Act, 2000", section="66E", title="Violation of privacy",
                   covers="Intentionally or knowingly capturing, publishing or transmitting an image of a person's private area without consent, in circumstances violating privacy.",
                   url="https://www.indiacode.nic.in"),
    "IT-67": dict(act="Information Technology Act, 2000", section="67", title="Publishing or transmitting obscene material in electronic form",
                  covers="Publishing or transmitting material that is lascivious or appeals to the prurient interest in electronic form.",
                  url="https://www.indiacode.nic.in"),
    "IT-67A": dict(act="Information Technology Act, 2000", section="67A", title="Publishing or transmitting material containing a sexually explicit act",
                   covers="Publishing or transmitting material containing a sexually explicit act or conduct in electronic form.",
                   url="https://www.indiacode.nic.in"),
}

# per category: list of (provision id, why it may be relevant, condition that must hold)
MAP = {
    "sextortion": [
        ("BNS-308", "The message appears to demand money or something of value while threatening to expose private images. That pattern is what the extortion provision describes.", "A demand for property or value, made by putting you in fear of harm or exposure."),
        ("BNS-351", "A threat to expose or harm your reputation can amount to criminal intimidation.", "The threat was meant to alarm you or to make you do something you would not otherwise do."),
        ("IT-66E", "May be relevant if an image of a private area was captured, published or sent without consent.", "Only if such an image was actually captured, published or transmitted. A threat alone does not meet this."),
        ("IT-67A", "May be relevant if sexually explicit material has actually been published or sent onward.", "Only if the material was actually published or transmitted. A threat alone does not meet this."),
        ("IT-67", "May be relevant if obscene material has actually been published or sent onward.", "Only if such material was actually published or transmitted."),
        ("BNS-77", "May be relevant if private images were taken or shared without the depicted woman's consent.", "Applies to images of a woman in a private act and to sharing them beyond her consent."),
        ("BNS-75", "May be relevant if the messages include demands for sexual favours or sexually coloured remarks.", "A demand or request for sexual favours, or sexual remarks, made by a man to a woman."),
    ],
    "blackmail_extortion": [
        ("BNS-308", "The text appears to demand money or something of value under a threat. That is the core of the extortion provision.", "A demand for property or value, obtained by putting you in fear of harm, exposure or an accusation."),
        ("BNS-351", "Threats of harm to person, reputation or property can amount to criminal intimidation.", "The threat was meant to alarm you or compel an action."),
    ],
    "threat": [
        ("BNS-351", "The text contains language that may threaten injury to you, your reputation, your property or people close to you.", "A threat meant to cause alarm or to compel you to act or not act. Anonymous or death threats are treated more seriously."),
        ("BNS-308", "If the threat is paired with a demand for money or something of value, the extortion provision may also be relevant.", "Only if a demand for property or value accompanies the threat."),
    ],
    "cyberstalking_contact": [
        ("BNS-78", "The text suggests repeated contact or monitoring after you showed no interest, which is what the stalking provision describes.", "Repeated contact despite clear disinterest, or monitoring of your online activity. The provision is written for acts by a man against a woman."),
        ("BNS-351", "If any of the messages threaten you, criminal intimidation may also be relevant.", "A threat meant to alarm you or compel an action."),
        ("BNS-79", "If the contact includes sexual remarks meant to insult your modesty, this provision may be relevant.", "Words or gestures intended to insult the modesty of a woman."),
    ],
    "harassment_abuse": [
        ("BNS-75", "If the messages include sexual remarks, unwelcome advances or demands for sexual favours, the sexual harassment provision may be relevant.", "Sexual content or demands made by a man to a woman."),
        ("BNS-79", "If words were meant to insult your modesty and reach you, this provision may be relevant.", "Words, sounds or gestures intended to insult the modesty of a woman."),
        ("BNS-351", "If there are also threats, criminal intimidation may be relevant.", "A threat meant to alarm you or compel an action."),
    ],
    "impersonation": [
        ("IT-66D", "The text suggests someone may be pretending to be another person to deceive you, using a phone or online account.", "Cheating by personation using a communication device or computer resource."),
        ("BNS-319", "Pretending to be another person to cheat is covered by the personation provision.", "Cheating by pretending to be someone else."),
        ("IT-66C", "If someone used your login, password or other identity credential without permission, this may be relevant.", "Only if another person's password or unique identification feature was actually used."),
    ],
    "romance_scam": [
        ("BNS-318", "The pattern of building a relationship to obtain money is the kind of deception the cheating provision describes.", "Deception that dishonestly induces you to hand over money or property."),
        ("IT-66D", "If a fake or borrowed identity was used online, the personation provision may be relevant.", "Cheating by personation using a computer resource."),
        ("BNS-319", "If the person pretended to be someone they are not, this may be relevant.", "Cheating by pretending to be another person."),
    ],
    "financial_scam": [
        ("BNS-318", "A request for money based on a false story or offer is what the cheating provision describes.", "Deception that dishonestly induces you to hand over money or property."),
        ("IT-66D", "If it was done through a fake identity, website or app, this may be relevant.", "Cheating by personation using a computer resource."),
    ],
    "phishing": [
        ("IT-66D", "A message that pretends to be a bank, company or official to get your details may involve personation using a computer resource.", "Cheating by personation by means of a computer resource."),
        ("BNS-318", "If it was used to obtain money or property by deception, the cheating provision may be relevant.", "Deception that dishonestly induces a handover of money or property."),
        ("IT-66C", "If your credentials were actually used by someone else, identity theft may be relevant.", "Only if your password, signature or other identification feature was actually used."),
    ],
    "coercive_manipulation": [
        ("BNS-351", "If control or pressure is backed by threats to you, your reputation or people you care about, criminal intimidation may be relevant.", "A threat meant to alarm you or compel an action."),
        ("BNS-78", "If the pattern includes repeated contact or monitoring after you asked for distance, the stalking provision may be relevant.", "Repeated contact despite disinterest, or monitoring of electronic communication."),
    ],
}

FINANCIAL = {"romance_scam", "financial_scam", "phishing", "impersonation"}
INTIMATE = {"sextortion"}

HEADLINE = {
    "sextortion": "Threats to expose private images, often with a demand for money or more images",
    "blackmail_extortion": "A demand backed by a threat",
    "threat": "Threatening language",
    "cyberstalking_contact": "Repeated or unwanted contact",
    "harassment_abuse": "Harassing or abusive messages",
    "impersonation": "Possible impersonation",
    "romance_scam": "Possible romance scam",
    "financial_scam": "Possible financial scam",
    "phishing": "Possible phishing",
    "coercive_manipulation": "Pressure, control or manipulation",
}

CHANNELS = {
    "emergency": dict(id="emergency", name="Emergency (police)", contact="112", tel="112", url=None,
                      use_for="Immediate danger or if you feel unsafe right now.", official=True),
    "ncrp": dict(id="ncrp", name="National Cyber Crime Reporting Portal", contact="cybercrime.gov.in",
                 tel=None, url="https://cybercrime.gov.in/",
                 use_for="Reporting cyber crime online. The portal has separate options for crimes related to women and children (which can be reported anonymously), financial fraud, and other cyber crime.", official=True),
    "fraud_1930": dict(id="fraud_1930", name="Cyber financial fraud helpline", contact="1930", tel="1930",
                       url="https://cybercrime.gov.in/",
                       use_for="Primarily for reporting financial cyber fraud, such as money taken through UPI, cards or online scams, ideally soon after it happens. It is not a general harassment helpline.", official=True),
    "women_181": dict(id="women_181", name="Women Helpline (Ministry of Women and Child Development)", contact="181", tel="181", url=None,
                      use_for="24x7 support for women facing violence or distress, linking you to police, One Stop Centres and counselling. Availability can vary by state.", official=True),
    "ncw_14490": dict(id="ncw_14490", name="NCW Women Helpline (National Commission for Women)", contact="14490", tel="14490",
                      url="https://ncw.gov.in/",
                      use_for="24x7 helpline for women affected by violence, with a digital complaint registration system. Complaints to NCW can also be made online.", official=True),
    "ncw_online": dict(id="ncw_online", name="NCW online complaint", contact="ncwapps.nic.in", tel=None,
                       url="https://ncwapps.nic.in/onlinecomplaintsv2/frmPubRegistration.aspx",
                       use_for="Filing a written complaint with the National Commission for Women.", official=True),
    "police": dict(id="police", name="Nearest police station or cyber crime police station", contact="In person", tel=None, url=None,
                   use_for="Filing a written complaint or FIR. Take the PDF report from SheShield and your original devices.", official=True),
    "sanchar": dict(id="sanchar", name="Sanchar Saathi (Department of Telecommunications)", contact="sancharsaathi.gov.in", tel=None,
                    url="https://sancharsaathi.gov.in/", use_for="Reporting suspected misuse of a phone number or suspicious calls and messages.", official=True),
    "stopncii": dict(id="stopncii", name="StopNCII.org (non-government service)", contact="stopncii.org", tel=None, url="https://stopncii.org/",
                     use_for="Creating a hash of intimate images on your own device so participating platforms can try to block them. It works only with participating platforms and cannot remove content from the whole internet. It is not an Indian government service.", official=False),
}

STEPS = {
    "default": [
        "Keep the original messages, screenshots and phone numbers. Do not delete them.",
        "Save the evidence in the vault and generate the PDF report.",
        "Report through an official channel below, or take the report to your nearest police station.",
        "Tell a person you trust, if it is safe to do so.",
    ],
    "sextortion": [
        "Do not pay. Payment usually leads to more demands.",
        "Do not send more images or information.",
        "Keep the original messages and the sender's profile or number. Do not delete chats or accounts yet.",
        "Do not confront the sender.",
        "Report on cybercrime.gov.in (use the women/children option if you wish to report anonymously) or call 112 if you are in danger.",
        "If any person shown is under 18, tell the police right away. Special child-protection laws apply.",
        "Consider StopNCII.org to ask participating platforms to block the images.",
        "Contact someone you trust, if it is safe to do so.",
    ],
}


def pathway(category, indicators=None, observed_summary=None):
    cat = category if category in MAP else None
    prov = []
    if cat:
        for pid, why, cond in MAP[cat]:
            p = P[pid]
            prov.append(dict(ref=f"{p['act']}, Section {p['section']}", id=pid, title=p["title"],
                             covers=p["covers"], why_relevant=why, applies_if=cond, url=p["url"],
                             status="Potentially applicable. Not a conclusion."))
    ch = [CHANNELS["emergency"], CHANNELS["ncrp"]]
    if cat in FINANCIAL:
        ch.append(CHANNELS["fraud_1930"])
    if cat in {"sextortion", "cyberstalking_contact", "harassment_abuse", "threat", "blackmail_extortion", "coercive_manipulation"}:
        ch += [CHANNELS["women_181"], CHANNELS["ncw_14490"], CHANNELS["ncw_online"]]
    if cat in INTIMATE:
        ch.append(CHANNELS["stopncii"])
    ch += [CHANNELS["police"], CHANNELS["sanchar"]]
    seen, channels = set(), []
    for c in ch:
        if c["id"] not in seen:
            seen.add(c["id"]); channels.append(c)
    return {
        "category": cat or "none",
        "headline": HEADLINE.get(cat, "No specific category detected"),
        "applicable": bool(cat),
        "observed": list(indicators or []),
        "observed_summary": observed_summary,
        "status_explainer": STATUS_EXPLAINER,
        "provisions": prov,
        "channels": channels,
        "next_steps": STEPS["sextortion"] if cat == "sextortion" else STEPS["default"],
        "note_1930": "1930 is mainly for financial cyber fraud. For harassment or threats use cybercrime.gov.in, 112 in an emergency, or the women's helplines.",
        "disclaimer": DISCLAIMER,
        "checked_on": CHECKED_ON,
        "verify_at": "https://www.indiacode.nic.in",
    }
