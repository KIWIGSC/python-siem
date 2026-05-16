ADMIN_PATTERNS = [
    "/admin",
    "/wp-admin",
    "/admin-panel"
]

def detect_admin_access(log):

    message = log.message.lower()

    for pattern in ADMIN_PATTERNS:

        if pattern in message:

            return (
                "SUSPICIOUS ADMIN ACCESS : "
                f"{pattern}"
            )

    return None