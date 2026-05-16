from collections import defaultdict
import re

IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

threat_scores = defaultdict(int)

RULE_SCORES = {
    "brute_force": 40,
    "sql_injection": 90,
    "admin_access": 40,
    "suspicious_hour": 30,
    "external_ip": 20
}

def add_threat_score(log, rule_name):

    ip_match = re.search(IP_REGEX, log.message)

    if not ip_match:
        return None

    ip = ip_match.group()

    threat_scores[ip] += RULE_SCORES[rule_name]

    return ip, threat_scores[ip]

def get_threat_level(score):

    if score >= 200:
        return "CRITICAL"

    elif score >= 100:
        return "HIGH"

    elif score >= 50:
        return "MEDIUM"

    return "LOW"