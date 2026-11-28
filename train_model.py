"""Train the SheShield multi-class classifier and write honest evaluation artefacts.

    python train_model.py

Outputs: threat_model.joblib, ml/metrics.json, MODEL_CARD.md
Splitting is by TEMPLATE (see ml/dataset.py) so no template appears in more than one split.
A near-duplicate check (normalised text overlap) is also run and reported.
"""
import json
import os
import re
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import make_pipeline, make_union

from ml.dataset import CLASSES, LANGS, build, split_groups

HERE = os.path.dirname(os.path.abspath(__file__))
MIN_SUPPORT = 8  # do not report per-cell metrics under this many test examples


def norm(t):
    return re.sub(r"[^\wऀ-ॿಀ-೿]+", " ", t.lower()).strip()


def make_pipe():
    feats = make_union(
        TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True, min_df=1, lowercase=True),
        TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True, token_pattern=r"(?u)\b\w+\b"),
    )
    return make_pipeline(feats, LogisticRegression(max_iter=2000, C=8, class_weight="balanced"))


def prf(y, p, labels):
    pr, rc, f1, sup = precision_recall_fscore_support(y, p, labels=labels, zero_division=0)
    return {l: dict(precision=round(float(a), 3), recall=round(float(b), 3), f1=round(float(c), 3), support=int(d))
            for l, a, b, c, d in zip(labels, pr, rc, f1, sup)}


def main():
    rows = build()
    assign = split_groups(rows)
    for r in rows:
        r["split"] = assign[r["group"]]
    by = {s: [r for r in rows if r["split"] == s] for s in ("train", "val", "test")}

    # near-duplicate audit across splits
    seen = {}
    leaks = 0
    for s in ("train", "val", "test"):
        for r in by[s]:
            k = norm(r["text"])
            if k in seen and seen[k] != s:
                leaks += 1
            seen.setdefault(k, s)

    pipe = make_pipe()
    pipe.fit([r["text"] for r in by["train"]], [r["label"] for r in by["train"]])

    def evaluate(split):
        X = [r["text"] for r in by[split]]
        y = [r["label"] for r in by[split]]
        p = list(pipe.predict(X))
        acc = float(np.mean([a == b for a, b in zip(y, p)]))
        labs = [c for c in CLASSES if c in set(y) | set(p)]
        out = dict(n=len(y), accuracy=round(acc, 3), by_category=prf(y, p, labs),
                   confusion_matrix=dict(labels=labs, matrix=confusion_matrix(y, p, labels=labs).tolist()))
        langs = {}
        for lg in LANGS:
            idx = [i for i, r in enumerate(by[split]) if r["lang"] == lg]
            if len(idx) >= MIN_SUPPORT:
                yl = [y[i] for i in idx]
                pl = [p[i] for i in idx]
                _, _, f1, _ = precision_recall_fscore_support(yl, pl, average="macro", zero_division=0)
                langs[lg] = dict(n=len(idx), accuracy=round(float(np.mean([a == b for a, b in zip(yl, pl)])), 3),
                                 macro_f1=round(float(f1), 3))
            else:
                langs[lg] = dict(n=len(idx), note="support too low to report")
        out["by_language"] = langs
        _, _, f1, _ = precision_recall_fscore_support(y, p, average="macro", zero_division=0)
        out["macro_f1"] = round(float(f1), 3)
        return out

    metrics = dict(
        dataset=dict(total=len(rows), splits={s: len(v) for s, v in by.items()},
                     by_class={c: sum(r["label"] == c for r in rows) for c in CLASSES},
                     by_language={l: sum(r["lang"] == l for r in rows) for l in LANGS},
                     templates=len({r["group"] for r in rows}), cross_split_exact_duplicates=leaks),
        validation=evaluate("val"), test=evaluate("test"))
    os.makedirs(os.path.join(HERE, "ml"), exist_ok=True)
    with open(os.path.join(HERE, "ml", "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)

    # Final model: refit on train+val (test stays untouched for reporting)
    final = make_pipe()
    tv = by["train"] + by["val"]
    final.fit([r["text"] for r in tv], [r["label"] for r in tv])
    joblib.dump(dict(model=final, classes=list(final.classes_), version="2"), os.path.join(HERE, "threat_model.joblib"))
    write_card(metrics)
    t = metrics["test"]
    print(f"rows={len(rows)} templates={metrics['dataset']['templates']} leaks={leaks}")
    print(f"TEST accuracy={t['accuracy']} macro_f1={t['macro_f1']}")
    for lg, v in t["by_language"].items():
        print(" ", lg, v)


def write_card(m):
    d, t = m["dataset"], m["test"]
    lines = ["# SheShield threat classifier — model card", "",
             "**What it is:** a TF-IDF (character + word n-grams) + logistic-regression classifier over 11 classes.",
             "It supports a rule engine; it does not replace human judgement and is not a legal determination.", "",
             "## Data (read this first)",
             f"- {d['total']} short messages generated from {d['templates']} hand-written templates with slot fillers.",
             "- **This is a synthetic, template-based dataset written for this project. It is not real victim data.**",
             "- Languages: English, Hinglish, Hindi, Kannada, Kanglish (romanised Kannada). Hindi/Kannada text needs native-speaker review.",
             "- Several requested categories are merged because of data size: cyberstalking + repeated contact; coercive control + isolation + emotional manipulation.",
             f"- Split by **template** (train/val/test = {d['splits']['train']}/{d['splits']['val']}/{d['splits']['test']}); exact-duplicate texts across splits: {d['cross_split_exact_duplicates']}.",
             "", "## Test-set results (held-out templates)",
             f"- accuracy {t['accuracy']}, macro-F1 {t['macro_f1']} on {t['n']} examples.",
             "- Because test sentences are paraphrase-like variants of few templates, **these numbers are optimistic** and will be lower on real messages.", "",
             "| category | precision | recall | F1 | support |", "|---|---|---|---|---|"]
    for k, v in t["by_category"].items():
        lines.append(f"| {k} | {v['precision']} | {v['recall']} | {v['f1']} | {v['support']} |")
    lines += ["", "| language | n | accuracy | macro-F1 |", "|---|---|---|---|"]
    for k, v in t["by_language"].items():
        lines.append(f"| {k} | {v['n']} | {v.get('accuracy', '–')} | {v.get('macro_f1', v.get('note', ''))} |")
    try:
        from analyzer import analyze
        te = [r for r in build() if split_groups(build())[r["group"]] == "test"]
        ok = sum(analyze(r["text"])["category"] == r["label"] for r in te)
        lines += ["", "## Full system (rules + context + model) on the same test split",
                  f"- category accuracy {ok / len(te):.3f} on {len(te)} examples.",
                  "- **Not independent evidence.** The rules were written by the same author who wrote the templates, so this number is optimistic. "
                  "It shows the system is consistent with its own examples, not how it performs on real messages. Real-world accuracy is unmeasured."]
    except Exception:
        pass
    lines += ["", "Confusion matrix and validation metrics: `ml/metrics.json`.", "",
              "## Limits", "- Small, synthetic data; slang, code-mixing and sarcasm outside the templates will be missed.",
              "- Benign examples include some tricky ones (idioms like \"I will kill it\"), but coverage is limited.",
              "- Output is a risk indicator for the user, never proof that anyone committed an offence."]
    with open(os.path.join(HERE, "MODEL_CARD.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
