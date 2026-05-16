import json
from pathlib import Path


ALERT_FILE = Path("alerts.json")


def export_alert(alert_data):

    alerts = []

    if ALERT_FILE.exists():

        with open(ALERT_FILE, "r") as file:

            try:
                alerts = json.load(file)

            except json.JSONDecodeError:
                alerts = []

    alerts.append(alert_data)

    with open(ALERT_FILE, "w") as file:

        json.dump(
            alerts,
            file,
            indent=4
        )