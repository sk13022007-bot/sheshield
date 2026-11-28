"""Identifier normalisation and linking inside ONE user's vault.

Matching never leaves the account: it runs on that account's own decrypted records, in memory.
Cross-user matching is deliberately NOT implemented (see README, "Not implemented").

A repeated identifier is a signal, not proof. Phone numbers get recycled and spoofed, devices
are shared and OCR misreads digits, so every group carries cautions and a confidence tier.
"""
from datetime import datetime
from urllib.parse import urlparse

import phonenumbers

KINDS = ("phone", "email", "upi", "handle", "url")

# Platforms where the account path identifies a person; for other URLs only the host is kept.
SOCIAL_HOSTS = {"instagram.com", "facebook.com", "t.me", "telegram.me", "twitter.com", "x.com",
                "snapchat.com", "linkedin.com", "youtube.com", "wa.me", "tiktok.com"}
# bare hosts that say nothing about an individual
GENERIC_HOSTS = {"google.com", "gmail.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
                 "wa.me", "t.me", "twitter.com", "x.com", "bit.ly", "tinyurl.com", "goo.gl", "linkedin.com"}

CAUTION = {
    "phone": ["Phone numbers can be recycled, spoofed, or used by several people on a shared device.",
              "Digits read from screenshots can be misread. Check against the original image."],
    "email": ["Email addresses can be created freely and used by different people at different times."],
    "upi": ["A UPI ID identifies a payment account, not necessarily the person who sent the messages."],
    "handle": ["Handles are easy to copy, change or fake, so identical handles may belong to different people."],
    "url": ["The same link can be shared by many unrelated senders."],
}
CONFIDENCE = {"upi": "higher", "email": "higher", "phone": "medium", "handle": "lower", "url": "lower"}


def normalise(kind, value):
    v = (value or "").strip()
    if not v:
        return None
    if kind == "phone":
        try:
            n = phonenumbers.parse(v, "IN")
            if phonenumbers.is_possible_number(n):
                return phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)
        except phonenumbers.NumberParseException:
            pass
        digits = "".join(ch for ch in v if ch.isdigit())
        return digits[-10:] if len(digits) >= 10 else None
    if kind == "email":
        v = v.strip(".,;:()<>[]\"'").lower()
        return v if "@" in v and "." in v.split("@")[-1] else None
    if kind == "upi":
        v = v.strip(".,;:()<>[]\"'").lower()
        return v if v.count("@") == 1 and "." not in v.split("@")[-1] else None
    if kind == "handle":
        v = v.strip(".,;:()<>[]\"'").lstrip("@").lower()
        return v if len(v) >= 3 else None
    if kind == "url":
        raw = v if "://" in v else "http://" + v
        try:
            u = urlparse(raw)
        except ValueError:
            return None
        host = (u.hostname or "").lower()
        host = host[4:] if host.startswith("www.") else host
        if not host or "." not in host:
            return None
        if host in SOCIAL_HOSTS:
            seg = [s for s in u.path.split("/") if s]
            if not seg:
                return None          # bare platform host: not an identifier
            return f"{host}/{seg[0].lower()}"
        return host
    return None


def from_extracted(extracted, source):
    """Turn ocr_utils.extract_identifiers output into normalised identifier dicts."""
    out, seen = [], set()

    def add(kind, raw):
        n = normalise(kind, raw)
        if n and (kind, n) not in seen:
            seen.add((kind, n))
            out.append({"kind": kind, "value": n, "raw": raw if isinstance(raw, str) else str(raw), "source": source})

    for p in extracted.get("phones", []) or []:
        add("phone", p.get("number") or p.get("display") if isinstance(p, dict) else p)
    for k, key in (("email", "emails"), ("upi", "upi_ids"), ("url", "urls"), ("handle", "handles")):
        for v in extracted.get(key, []) or []:
            add(k, v)
    return out


def _parse(ts):
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def link_records(records):
    """records: list of vault list_all() dicts. Returns groups, clusters and timeline."""
    by_key = {}
    for r in records:
        for ident in (r.get("meta") or {}).get("identifiers", []) or []:
            kind, val = ident.get("kind"), ident.get("value")
            if not kind or not val:
                continue
            if kind == "url" and val in GENERIC_HOSTS:
                continue
            by_key.setdefault((kind, val), {})[r["id"]] = (r, ident.get("source", "unknown"))

    groups = []
    for (kind, val), recs in by_key.items():
        if len(recs) < 2:
            continue
        items = sorted((r for r, _ in recs.values()), key=lambda r: r["created_at"])
        sources = {s for _, s in recs.values()}
        first, last = _parse(items[0]["created_at"]), _parse(items[-1]["created_at"])
        span_days = (last - first).total_seconds() / 86400 if first and last else None
        cautions = list(CAUTION[kind])
        if "ocr" in sources:
            cautions.append("At least one match was read automatically from a screenshot and may contain a reading error.")
        pattern = None
        if len(items) >= 3 and span_days is not None and span_days <= 7:
            pattern = f"{len(items)} records within {max(1, round(span_days))} day(s): a repeated contact pattern."
        elif len(items) >= 2 and span_days is not None and span_days > 7:
            pattern = f"Seen again after {round(span_days)} days."
        label = {"phone": "phone number", "email": "email address", "upi": "UPI ID", "handle": "handle", "url": "link"}[kind]
        groups.append({
            "kind": kind, "value": val, "count": len(items), "confidence": CONFIDENCE[kind],
            "headline": "Repeated identifier detected",
            "message": f"This {label} appears in {len(items)} evidence records in this vault.",
            "record_ids": [r["id"] for r in items],
            "first_seen": items[0]["created_at"], "last_seen": items[-1]["created_at"],
            "pattern": pattern,
            "why_linked": f"These records were linked because the same normalised {label} was found in each of them. "
                          "This shows repetition inside your vault. It does not show who owns the identifier.",
            "cautions": cautions,
        })
    groups.sort(key=lambda g: (-g["count"], g["kind"]))

    # clusters of potentially related incidents (records connected through any shared identifier)
    parent = {r["id"]: r["id"] for r in records}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for g in groups:
        ids = g["record_ids"]
        for other in ids[1:]:
            parent[find(other)] = find(ids[0])
    comp = {}
    for r in records:
        comp.setdefault(find(r["id"]), []).append(r["id"])
    clusters = []
    for ids in comp.values():
        if len(ids) < 2:
            continue
        idset = set(ids)
        shared = [{"kind": g["kind"], "value": g["value"], "count": g["count"]} for g in groups if idset & set(g["record_ids"])]
        clusters.append({
            "headline": "Potentially related incidents",
            "record_ids": sorted(ids),
            "shared_identifiers": shared,
            "why_linked": "Linked through shared identifiers shown above. Records may be unrelated if an identifier was recycled, spoofed or misread.",
        })
    clusters.sort(key=lambda c: -len(c["record_ids"]))

    linked_ids = {i for g in groups for i in g["record_ids"]}
    timeline = [{"id": r["id"], "created_at": r["created_at"], "severity": r["severity"],
                 "linked": r["id"] in linked_ids,
                 "identifiers": [{"kind": i["kind"], "value": i["value"]} for i in (r.get("meta") or {}).get("identifiers", []) or []]}
                for r in sorted(records, key=lambda r: r["created_at"])]
    return {
        "groups": groups, "clusters": clusters, "timeline": timeline,
        "records_with_identifiers": sum(1 for r in records if (r.get("meta") or {}).get("identifiers")),
        "total_records": len(records),
        "scope": "Matching covers only records in your own vault.",
        "disclaimer": "A repeated identifier is a signal, not proof of who is behind it. SheShield never labels anyone as an offender.",
    }
