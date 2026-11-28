# SheShield threat classifier — model card

**What it is:** a TF-IDF (character + word n-grams) + logistic-regression classifier over 11 classes.
It supports a rule engine; it does not replace human judgement and is not a legal determination.

## Data (read this first)
- 666 short messages generated from 242 hand-written templates with slot fillers.
- **This is a synthetic, template-based dataset written for this project. It is not real victim data.**
- Languages: English, Hinglish, Hindi, Kannada, Kanglish (romanised Kannada). Hindi/Kannada text needs native-speaker review.
- Several requested categories are merged because of data size: cyberstalking + repeated contact; coercive control + isolation + emotional manipulation.
- Split by **template** (train/val/test = 380/122/164); exact-duplicate texts across splits: 0.

## Test-set results (held-out templates)
- accuracy 0.463, macro-F1 0.439 on 164 examples.
- Because test sentences are paraphrase-like variants of few templates, **these numbers are optimistic** and will be lower on real messages.

| category | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.263 | 0.833 | 0.4 | 12 |
| harassment_abuse | 0.333 | 0.125 | 0.182 | 8 |
| cyberstalking_contact | 0.4 | 0.571 | 0.471 | 7 |
| sextortion | 0.833 | 0.357 | 0.5 | 28 |
| blackmail_extortion | 0.386 | 0.654 | 0.486 | 26 |
| threat | 0.444 | 0.25 | 0.32 | 16 |
| impersonation | 0.5 | 0.2 | 0.286 | 10 |
| romance_scam | 0.545 | 0.261 | 0.353 | 23 |
| financial_scam | 1.0 | 0.737 | 0.848 | 19 |
| phishing | 1.0 | 0.375 | 0.545 | 8 |
| coercive_manipulation | 0.312 | 0.714 | 0.435 | 7 |

| language | n | accuracy | macro-F1 |
|---|---|---|---|
| en | 37 | 0.297 | 0.259 |
| hinglish | 33 | 0.788 | 0.767 |
| hi | 25 | 0.64 | 0.475 |
| kn | 37 | 0.27 | 0.135 |
| kanglish | 32 | 0.406 | 0.561 |

## Full system (rules + context + model) on the same test split
- category accuracy 0.878 on 164 examples.
- **Not independent evidence.** The rules were written by the same author who wrote the templates, so this number is optimistic. It shows the system is consistent with its own examples, not how it performs on real messages. Real-world accuracy is unmeasured.

Confusion matrix and validation metrics: `ml/metrics.json`.

## Limits
- Small, synthetic data; slang, code-mixing and sarcasm outside the templates will be missed.
- Benign examples include some tricky ones (idioms like "I will kill it"), but coverage is limited.
- Output is a risk indicator for the user, never proof that anyone committed an offence.
