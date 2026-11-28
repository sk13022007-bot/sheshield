"""Sextortion emergency guide. Static, reviewed text. Nothing here is generated per user."""

HEADLINE = "You're not alone. You can take steps to protect yourself."
SUBLINE = ("Sextortion is a crime committed against you. Being threatened is not your fault, "
           "and paying or complying rarely makes it stop.")

ACTIONS = [
    {"id": "stop_pay", "title": "Don't pay and don't send anything more",
     "body": "Payment usually leads to more demands. Sending more images gives the person more to use."},
    {"id": "dont_delete", "title": "Don't delete the conversation",
     "body": "Messages, usernames, profile links, payment details and dates are evidence."},
    {"id": "save", "title": "Save evidence first",
     "body": "Take screenshots showing the username, profile link, messages and times. Save them in your vault so each one gets a tamper-evident record."},
    {"id": "platform", "title": "Report the account to the platform, then block",
     "body": "Use the app's report tool for sextortion or non-consensual intimate images, then block the account."},
    {"id": "secure", "title": "Secure your accounts",
     "body": "Change passwords, turn on two-step verification, and review who can see your friends and followers."},
    {"id": "report", "title": "Report to the police",
     "body": "File at cybercrime.gov.in. In immediate danger call 112. If you already sent money, call 1930 quickly."},
    {"id": "support", "title": "Tell someone you trust",
     "body": "Support is available: Women Helpline 181, or the National Commission for Women. You do not have to handle this alone."},
]

STOPNCII_EXPLAINER = (
    "StopNCII.org (run by SWGfL / Revenge Porn Helpline) lets you create a digital fingerprint (hash) of an intimate "
    "image on your own device. Only the hash is shared with participating platforms, which can then block matching "
    "images. The image itself is never uploaded to them."
)

PROTOTYPE_NOTE = (
    "The tool on this page is a local prototype. It computes fingerprints in your browser and keeps them on this device. "
    "It does not contact StopNCII or any platform and cannot block images anywhere on the internet. "
    "To actually request blocking, use StopNCII.org yourself."
)

HASH_TYPES = [
    {"name": "SHA-256 (cryptographic)", "what": "Changes completely if even one pixel or byte changes. Proves a file is exactly the same file. Does not match edited or re-compressed copies."},
    {"name": "dHash (perceptual)", "what": "Describes how an image looks. Resized or re-compressed copies of the same picture give similar hashes, so it can spot near-copies. It can also give false matches and misses heavily edited images."},
]


def guide():
    return {"headline": HEADLINE, "subline": SUBLINE, "actions": ACTIONS, "stopncii": STOPNCII_EXPLAINER,
            "prototype_note": PROTOTYPE_NOTE, "hash_types": HASH_TYPES}
