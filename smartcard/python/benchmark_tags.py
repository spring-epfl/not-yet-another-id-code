from random import Random
import subprocess
import time

from prototype import APDU, GPCommand


def main():
    rng = Random()

    print("Initialize household secret")
    print("===========================")

    household_secret = rng.randbytes(32)
    gp = GPCommand(
        APDU(0x15, payload=household_secret),
    )
    completed = subprocess.run(str(gp), shell=True)

    period = 1000 * int(time.time())

    print("Start benchmark")
    print("===========================")

    for n in range(10):
        period += rng.randint(1, 100)
        gp = GPCommand(
            APDU(0x22, payload=period.to_bytes(8, "big"))
        )

        completed = subprocess.run(str(gp), shell=True, capture_output=True, text=True)
        print(completed.stdout)


if __name__ == "__main__":
    main()
