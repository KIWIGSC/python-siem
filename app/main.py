from rich import print

from app.exporters.json_exporter import export_alert

from app.alerts.detectors.brute_force import detect_brute_force
from app.alerts.detectors.sql_injection import detect_sql_injection
from app.alerts.detectors.admin_access import detect_admin_access
from app.alerts.detectors.suspicious_hours import detect_suspicious_hours
from app.alerts.detectors.geo_detection import detect_external_ip

from app.scoring.threat_scorer import (
    add_threat_score,
    get_threat_level
)

from app.ingestion.live_reader import follow
from app.parsing.regex_parser import parse_log
from app.storage.memory_store import MemoryStore


store = MemoryStore()

already_alerted = set()

print("[bold cyan]Monitoring started...[/bold cyan]\n")


# =====================================
# Helpers
# =====================================

def get_level_color(level):

    if level == "CRITICAL":
        return "bold white on red"

    elif level == "HIGH":
        return "bold red"

    elif level == "MEDIUM":
        return "bold yellow"

    return "bold green"


def handle_detection(
    parsed,
    rule_name,
    alert_message
):

    result = add_threat_score(
        parsed,
        rule_name
    )

    if not result:
        return

    ip, score = result

    level = get_threat_level(score)

    color = get_level_color(level)

    alert_key = (
        rule_name,
        ip
    )

    # =========================
    # Déduplication alertes
    # =========================

    if alert_key not in already_alerted:

        already_alerted.add(alert_key)

        print(
            f"\n[bold white on red]"
            f"{alert_message}"
            f"[/bold white on red]"
        )

    # =========================
    # Threat score
    # =========================

    print(
        f"[{color}]"
        f"THREAT SCORE [{ip}] = "
        f"{score} ({level})"
        f"[/{color}]"
    )

    # =========================
    # Export JSON
    # =========================

    export_alert({

        "timestamp": str(parsed.timestamp),

        "rule": rule_name,

        "ip": ip,

        "score": score,

        "level": level,

        "message": alert_message
    })


# =====================================
# Main monitoring loop
# =====================================

for line in follow("logs/app.log"):

    parsed = parse_log(line)

    if not parsed:
        continue

    store.add(parsed)

    # =========================
    # Affichage logs
    # =========================

    if parsed.level == "ERROR":

        print(
            f"[bold red]{parsed}[/bold red]"
        )

    elif parsed.level == "WARN":

        print(
            f"[bold yellow]{parsed}[/bold yellow]"
        )

    else:

        print(
            f"[bold green]{parsed}[/bold green]"
        )

    # =========================
    # Stats live
    # =========================

    stats = store.count_by_level()

    print(
        "\n[bold cyan]"
        "=== LIVE STATS ==="
        "[/bold cyan]"
    )

    for level, count in stats.items():

        if level == "ERROR":

            print(
                f"[red]{level}: {count}[/red]"
            )

        elif level == "WARN":

            print(
                f"[yellow]{level}: {count}[/yellow]"
            )

        else:

            print(
                f"[green]{level}: {count}[/green]"
            )

    # =========================
    # External IP
    # =========================

    geo_alert = detect_external_ip(parsed)

    if geo_alert:

        handle_detection(
            parsed,
            "external_ip",
            geo_alert
        )

    # =========================
    # Suspicious hours
    # =========================

    hour_alert = detect_suspicious_hours(parsed)

    if hour_alert:

        handle_detection(
            parsed,
            "suspicious_hour",
            hour_alert
        )

    # =========================
    # Admin access
    # =========================

    admin_alert = detect_admin_access(parsed)

    if admin_alert:

        handle_detection(
            parsed,
            "admin_access",
            admin_alert
        )

    # =========================
    # SQL Injection
    # =========================

    sql_alert = detect_sql_injection(parsed)

    if sql_alert:

        handle_detection(
            parsed,
            "sql_injection",
            sql_alert
        )

    # =========================
    # Brute force
    # =========================

    brute_force_alert = detect_brute_force(parsed)

    if brute_force_alert:

        handle_detection(
            parsed,
            "brute_force",
            brute_force_alert
        )

    # =========================
    # Alertes globales
    # =========================

    if stats.get("ERROR", 0) >= 3:

        print(
            "\n[bold white on red]"
            "ALERTE: trop d'erreurs détectées !"
            "[/bold white on red]"
        )

    print()