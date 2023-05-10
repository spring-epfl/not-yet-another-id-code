from random import Random
import subprocess

from prototype import APDU, GPCommand


class GPBenchmarkCommand(GPCommand):
    base = "${GP} -d -a 00A404000B03F1FF55DE16074A09012500"


def main():
    rng = Random()


    for payload_log2_size in range(7, 11):
        payload_size = 2** payload_log2_size
        print()
        print(f"upload payload size: {payload_size}")
        print("=============================")
        print()
        for n in range(2):
            gp = GPBenchmarkCommand(
                APDU(0x32, payload=rng.randbytes(payload_size)),
                APDU(0x32, payload=rng.randbytes(payload_size)),
                APDU(0x32, payload=rng.randbytes(payload_size)),
                APDU(0x32, payload=rng.randbytes(payload_size)),
            )
            completed = subprocess.run(str(gp), shell=True)

            completed = subprocess.run(str(gp), shell=True, capture_output=True, text=True)
            print(completed.stdout)


    for payload_log2_size in range(6, 9):
        payload_size: int = 2 ** payload_log2_size
        length_bytes = payload_size.to_bytes(2, "big")
        print()
        print(f"download payload size: {payload_size}")
        print("=============================")
        print()
        for n in range(2):
            gp = GPBenchmarkCommand(
                APDU(0x40, p1=length_bytes[0], p2=length_bytes[1]),
            )
            completed = subprocess.run(str(gp), shell=True)

            completed = subprocess.run(str(gp), shell=True, capture_output=True, text=True)
            print(completed.stdout)
if __name__ == "__main__":
    main()
