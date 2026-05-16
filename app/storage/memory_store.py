class MemoryStore:

    def __init__(self):
        self.logs = []

    def add(self, log_event):
        self.logs.append(log_event)

    def count_by_level(self):

        stats = {}

        for log in self.logs:
            stats[log.level] = (
                stats.get(log.level, 0) + 1
            )

        return stats

    def search(self, keyword):

        return [
            log for log in self.logs
            if keyword.lower() in log.message.lower()
        ]