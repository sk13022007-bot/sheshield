import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

# label 1 = harassment (threat, blackmail, abuse), label 0 = safe
data = [
    ("send money or i will leak your photos", 1),
    ("i know where you live, you will regret this", 1),
    ("i will kill you", 1),
    ("you are a worthless slut", 1),
    ("send nudes or i will tell everyone", 1),
    ("i will post your pictures online if you block me", 1),
    ("i am watching you everywhere you go", 1),
    ("i will ruin your life and your family", 1),
    ("pay me or your video goes viral", 1),
    ("you ugly whore nobody will marry you", 1),
    ("tujhe jaan se maar dunga", 1),
    ("paise de warna photos leak kar dunga", 1),
    ("tera video viral kar dunga", 1),
    ("main tujhe dhundh lunga, bach nahi payegi", 1),
    ("ninna photo leak madtini", 1),
    ("duddu kodu illa andre video hakthini", 1),
    ("ninna jeevana nashana madtini", 1),
    ("see you at college tomorrow", 0),
    ("did you submit the assignment", 0),
    ("happy birthday, have a great day", 0),
    ("can you send me the notes for class", 0),
    ("great job on the presentation", 0),
    ("let's meet for lunch at the canteen", 0),
    ("thanks for helping me with the project", 0),
    ("the exam is on monday, all the best", 0),
    ("what time does the hackathon start", 0),
    ("kal college mein milte hain", 0),
    ("assignment submit kar diya kya", 0),
    ("tumhara presentation bahut accha tha", 0),
    ("naale college ge baro", 0),
    ("oota aytha, nanu mane ge hogtini", 0),
    ("ninna presentation tumba chennagittu", 0),
]

texts = [t for t, _ in data]
labels = [l for _, l in data]

# character n-grams help with spelling variations and mixed languages
model = make_pipeline(
    TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), lowercase=True),
    LogisticRegression(max_iter=1000),
)
model.fit(texts, labels)
joblib.dump(model, "toxicity_model.joblib")
print("Model saved: toxicity_model.joblib")

tests = [
    "give me money or i will leak your photos",
    "are you coming to the hackathon",
    "tujhe photos leak kar dunga",
]
for t in tests:
    p = model.predict_proba([t])[0][1]
    print(f"{p:.2f}  {t}")