import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

PATH = os.path.join("data", "train.csv")
if not os.path.exists(PATH):
    raise SystemExit("data\\train.csv not found. Put the downloaded CSV in the data folder.")

df = pd.read_csv(PATH)
print("Columns found:", list(df.columns))

text_col = next((c for c in ["comment_text", "text", "comment", "content"] if c in df.columns), None)
label_col = next((c for c in ["toxic", "label", "target", "toxicity"] if c in df.columns), None)
if not text_col or not label_col:
    raise SystemExit("Could not find the text/label columns. Send me the column names above.")

df = df[[text_col, label_col]].dropna()
if df[label_col].dtype == object:
    df[label_col] = df[label_col].astype(str).str.lower().isin(["1", "true", "tox", "toxic", "yes"]).astype(int)
elif df[label_col].max() <= 1 and df[label_col].nunique() > 2:
    df[label_col] = (df[label_col] >= 0.5).astype(int)
else:
    df[label_col] = (df[label_col] > 0).astype(int)

df = df.sample(min(len(df), 40000), random_state=42)
print("Rows used:", len(df), "| harassing share:", round(df[label_col].mean(), 3))

X_train, X_test, y_train, y_test = train_test_split(
    df[text_col].astype(str), df[label_col], test_size=0.2, random_state=42, stratify=df[label_col])

extra = [
    ("Paise de warna tere photos leak kar dunga", 1),
    ("Tujhe photos leak kar dunga", 1),
    ("Mujhe pata hai tu kahan rehti hai, bach ke rehna", 1),
    ("Chup reh warna tera video viral kar dunga", 1),
    ("Tere ghar aake dekh lunga", 1),
    ("Nin yelli iddiya gottu, ninna photo leak madtini", 1),
    ("Nanage hana kodu illandre photo hakteeni", 1),
    ("Ninna video viral madtini, nodu", 1),
    ("Yaarigu helbeda, illandre pashchattapa padtiya", 1),
    ("Send money or I will leak your photos", 1),
    ("I know where you live, you will regret this", 1),
    ("Send nudes or I will tell everyone", 1),
    ("Kal college aa rahi ho kya?", 0),
    ("Notes bhej do please", 0),
    ("Aaj lab ka time kya hai?", 0),
    ("Dhanyavaad, assignment mein help karne ke liye", 0),
    ("Naale college ge baruttiya?", 0),
    ("Notes kalsu, dayavittu", 0),
    ("Hackathon yaavaga shuru aagutte?", 0),
    ("Thumba dhanyavadagalu", 0),
    ("Are you coming to the hackathon meeting?", 0),
    ("Happy birthday, have a great day", 0),
]
extra_df = pd.DataFrame(extra * 30, columns=["t", "l"])
X_fit = pd.concat([X_train, extra_df["t"]], ignore_index=True)
y_fit = pd.concat([y_train, extra_df["l"]], ignore_index=True)

print("Training... this should take about 1 to 2 minutes. Please wait, do not close.")
model = make_pipeline(
    TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 4), lowercase=True,
                    max_features=150000, sublinear_tf=True),
    LogisticRegression(solver="liblinear", class_weight="balanced"),
)
model.fit(X_fit, y_fit)

pred = model.predict(X_test)
print("\n===== RESULTS ON UNSEEN TEST DATA =====")
print("Accuracy:", round(accuracy_score(y_test, pred), 3))
print(classification_report(y_test, pred, target_names=["normal", "harassing/toxic"]))

if os.path.exists("toxicity_model.joblib"):
    os.replace("toxicity_model.joblib", "toxicity_model_old.joblib")
joblib.dump(model, "toxicity_model.joblib")
print("Model saved: toxicity_model.joblib (old one kept as toxicity_model_old.joblib)")

for t in [
    "give me money or i will leak your photos",
    "are you coming to the hackathon",
    "tujhe photos leak kar dunga",
    "ninna photo leak madtini",
]:
    print(f"{model.predict_proba([t])[0][1]:.2f}  {t}")