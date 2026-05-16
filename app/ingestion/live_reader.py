import time

def follow(path):

    position = 0

    while True:

        with open(path, "r", encoding="utf-8") as file:

            file.seek(position)

            new_lines = file.readlines()

            position = file.tell()

        for line in new_lines:

            yield line.strip()

        time.sleep(0.2)