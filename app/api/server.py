import json
import os
from fastapi.responses import FileResponse
from fastapi import FastAPI

app = FastAPI()


@app.get("/alerts")
def get_alerts():

    if not os.path.exists("alerts.json"):

        return []

    with open(
        "alerts.json",
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)
    
@app.get("/")
def dashboard():
    return FileResponse("dashboard/index.html")