"""Safety insights computed from this user's own vault and analysis log only. Not population statistics."""
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import db
import identifiers
import vault


def compute(ctx):
    c = db.connect()
    try:
        log = [dict(r) for r in c.execute("SELECT created_at, category, severity, score, language, source FROM analysis_log WHERE user_id=? ORDER BY id", (ctx.user_id,))]
    finally:
        c.close()
    records = vault.list_all(ctx)
    integ = vault.verify_all(ctx)
    total_rec = len(records)
    if integ.get("ok"):
        verified, pct = total_rec, 100.0 if total_rec else None
    else:
        bad = integ["tampered_at_id"]
        verified = sum(1 for r in records if r["id"] < bad)
        pct = round(100 * verified / total_rec, 1) if total_rec else None
    cats = Counter(l["category"] or "unknown" for l in log)
    langs = Counter(l["language"] or "unknown" for l in log)
    sev = Counter(l["severity"] for l in log)
    today = datetime.now(timezone.utc).date()
    days = [today - timedelta(days=i) for i in range(29, -1, -1)]
    per = defaultdict(int)
    for l in log:
        try:
            per[datetime.fromisoformat(l["created_at"]).date()] += 1
        except ValueError:
            pass
    trend = [{"date": d.isoformat(), "count": per.get(d, 0)} for d in days]
    links = identifiers.link_records(records)
    return {
        "scope": "Statistics from your own vault only. They are not crime statistics or a measure of how common anything is.",
        "total_analysed": len(log), "total_saved": total_rec,
        "by_category": dict(cats), "by_language": dict(langs), "by_severity": dict(sev),
        "trend_30d": trend,
        "integrity": {"ok": bool(integ.get("ok")), "percent_verified": pct, "records_verified": verified, "records_total": total_rec},
        "related": {"repeated_identifiers": len(links["groups"]), "related_incident_groups": len(links["clusters"])},
    }
