from fastapi import FastAPI
from pydantic import BaseModel
from analyzer import analyze

app = FastAPI(title="SheShield")


class Msg(BaseModel):
    text: str


@app.get("/")
def home():
    return {"app": "SheShield", "status": "running"}


@app.post("/analyze")
def check(m: Msg):
    return analyze(m.text)