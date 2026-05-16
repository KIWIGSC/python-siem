def detect_suspicious_hours(log):

    hour = log.timestamp.hour

    sensitive_users = [
        "admin",
        "root"
    ]

    message = log.message.lower()

    if (
        0 <= hour <= 5
        and any(user in message for user in sensitive_users)
        and "logged in" in message
    ):

        return (
            f"SUSPICIOUS LOGIN HOUR "
            f"({hour}:00)"
        )

    return None