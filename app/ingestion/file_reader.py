def read_logs(path):
    with open(path, "r") as file:
        for line in file:
            yield line.strip()