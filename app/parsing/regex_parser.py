import re
from datetime import datetime

from app.models.log_event import LogEvent


LOG_PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2}) "
    r"(\d{2}:\d{2}:\d{2}) "
    r"(INFO|WARN|ERROR) "
    r"(.+)"
)


def parse_log(line):

    line = line.strip()

    if not line:
        return None

    match = LOG_PATTERN.match(line)

    if not match:

        print(
            f"[bold red]"
            f"INVALID LOG FORMAT: {line}"
            f"[/bold red]"
        )

        return None

    try:

        date_str, time_str, level, message = match.groups()

        timestamp = datetime.strptime(
            f"{date_str} {time_str}",
            "%Y-%m-%d %H:%M:%S"
        )

        return LogEvent(
            timestamp=timestamp,
            level=level,
            message=message,
            source="app.log"
        )

    except Exception as error:

        print(
            f"[bold red]"
            f"PARSING ERROR: {error}"
            f"[/bold red]"
        )

        return None