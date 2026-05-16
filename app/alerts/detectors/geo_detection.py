import re

IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

TRUSTED_PREFIXES = (
    "192.168.",
    "10.",
    "172.16."
)

def detect_external_ip(log):

    message = log.message

    ip_match = re.search(IP_REGEX, message)

    if not ip_match:
        return None

    ip = ip_match.group()

    is_trusted = any(
        ip.startswith(prefix)
        for prefix in TRUSTED_PREFIXES
    )

    if not is_trusted:

        return (
            f"SUSPICIOUS EXTERNAL IP : {ip}"
        )

    return None