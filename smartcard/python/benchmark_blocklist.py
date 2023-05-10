from secrets import token_bytes
import subprocess

from prototype import APDU, GPCommand


def main():
    for num_log in range(2, 11):
        num_elements = 2 ** num_log
        num_blocks = num_elements // 4

        print()
        print()
        print(f"{num_elements} ({num_blocks} blocks of 128 B):")
        for _repetition in range(5):
            blocklist = [token_bytes(128) for _ in range(num_blocks)]
            gp: GPCommand
            if num_blocks > 1:
                gp = GPCommand(
                    APDU(0x21, p1=1, payload=blocklist[0]),
                    *tuple(
                        APDU(0x21, p1=2, payload=block) for block in blocklist[1:-1]
                    ),
                    APDU(0x21, p1=3, payload=blocklist[-1]),
                )
            else:
                gp = GPCommand(APDU(0x21, p1=3, payload=blocklist[0]))

            command = f"{str(gp)} | tail -n 1"

            completed = subprocess.run(command, shell=True, capture_output=True, text=True)
            print(completed.stdout)


if __name__ == "__main__":
    main()
