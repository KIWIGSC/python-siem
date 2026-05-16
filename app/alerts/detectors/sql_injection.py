SQL_PATTERNS = [
    "' OR '1'='1",
    "UNION SELECT",
    "--",
    "DROP TABLE"
]

def detect_sql_injection(log):

    message = log.message.upper()

    for pattern in SQL_PATTERNS:

        if pattern.upper() in message:

            return (
                "SQL INJECTION DETECTED : "
                f"{pattern}"
            )

    return None