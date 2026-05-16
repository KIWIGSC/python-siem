from collections import defaultdict
from datetime import timedelta
import re

IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

failed_attempts = defaultdict(list)
already_detected = set()
MAX_WINDOW_SECONDS = 30
MAX_FAILED_ATTEMPTS = 5


def detect_brute_force(log):

    if "Failed login attempt" not in log.message:
        return None

    ip_match = re.search(IP_REGEX, log.message)

    if not ip_match:
        return None

    ip = ip_match.group()

    current_time = log.timestamp

    failed_attempts[ip].append(current_time)

    # garder seulement les événements récents
    failed_attempts[ip] = [

        timestamp

        for timestamp in failed_attempts[ip]

        if current_time - timestamp
        <= timedelta(seconds=MAX_WINDOW_SECONDS)
    ]

    attempt_count = len(failed_attempts[ip])

    if attempt_count >= MAX_FAILED_ATTEMPTS:

        if ip in already_detected:
            return None

        already_detected.add(ip)

        return (
        f"BRUTE FORCE DETECTED "
        f"FROM {ip} "
        f"({attempt_count} attempts "
        f"in {MAX_WINDOW_SECONDS}s)"
        )

    return None