from __future__ import annotations
from hashlib import sha256
from secrets import token_bytes
import sys
import time
from typing import List, Optional

from Cryptodome.Cipher import AES

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec as ec_cryptography
from petlib import bn, ec


class APDU:
    apdu_cls = 0x80

    def __init__(self, ins: int, p1: int = 0, p2: int = 0, payload: Optional[bytes] = None) -> None:
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.payload = payload


    def __str__(self) -> str:
        cls_hex = self.__class__.apdu_cls.to_bytes(1, "big").hex()
        ins_hex = self.ins.to_bytes(1, "big").hex()
        p1_hex = self.p1.to_bytes(1, "big").hex()
        p2_hex = self.p2.to_bytes(1, "big").hex()
        length_hex = ""
        payload_hex = ""

        if self.payload:
            length = len(self.payload)
            payload_hex = self.payload.hex()
            if length > 255:
                length_hex = length.to_bytes(3, "big").hex()
            else:
                length_hex = length.to_bytes(1, "big").hex()

        return f"-a {cls_hex}{ins_hex}{p1_hex}{p2_hex}{length_hex}{payload_hex}"


class GPCommand:
    base = "${GP} -d -a 00A404000B03F1FF55DE16074A09012600"

    def __init__(self, *apdus: APDU) -> None:
        self.apdus: List[APDU] = list(apdus)

    def add(self, apdu: APDU) -> GPCommand:
        self.apdus.append(apdu)
        return self

    def __str__(self) -> str:
        apdus = " ".join(str(apdu) for apdu in self.apdus)
        return f"{self.__class__.base} {apdus}"


class ScriptCommand:
    def __init__(self, subcommand: str, *args: bytes, ending_args: str = "") -> None:
        self.subcommand = subcommand
        self.arguments = args
        self.ending_args = ending_args

    def __str__(self) -> str:
        args = " ".join(arg.hex() for arg in self.arguments)
        return f"python {sys.argv[0]} {self.subcommand} {args} {self.ending_args}"


def serialize_public_key(public_key: ec_cryptography.EllipticCurvePublicKey) -> bytes:
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return public_bytes


def verify_commitment(ph: str, zh: str, mh: str, rcom: str) -> None:
    ec_group = ec.EcGroup(nid=415)
    point = ec.EcPt.from_binary(bytes.fromhex(ph), ec_group)
    z = bn.Bn.from_hex(zh)
    m = bn.Bn.from_hex(mh)
    r = bn.Bn.from_hex(rcom[:64])
    a = ((z * m + r) * point).export().hex()[2:].upper()
    b = rcom[64:]

    if a == b:
        print("valid commitment")
    else:
        print("Invalid commitment")


def verify_signature(public_key_hex: str, tag: str, period: str, blocklist_hash: str, rcom: str, signature_hex: str) -> None:
    message_hex = tag + period + rcom[64:] + blocklist_hash
    message = bytes.fromhex(message_hex)
    signature = bytes.fromhex(signature_hex)
    public_key = ec_cryptography.EllipticCurvePublicKey.from_encoded_point(ec_cryptography.SECP256R1(), bytes.fromhex(public_key_hex))

    try:
        public_key.verify(signature, message, ec_cryptography.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("Verification failed!")
        return

    print("Verification successful!")


def apdus() -> None:
    private_key = ec_cryptography.generate_private_key(ec_cryptography.SECP256R1(), default_backend())
    public_bytes = serialize_public_key(private_key.public_key())
    shared_secret = private_key.private_numbers().private_value.to_bytes(32, "big")
    household_revocation_value = token_bytes(32)
    household_secret = token_bytes(32)

    ec_group = ec.EcGroup(nid=415)
    point: ec.EcPt = ec_group.order().random() * ec_group.generator()
    commitment_g: bytes = point.export(ec.POINT_CONVERSION_UNCOMPRESSED)

    commitment_z = token_bytes(32)
    household_entitlement = token_bytes(32)

    blocklist = [token_bytes(128) for _ in range(3)]
    blocklist_hash = sha256(b"".join(blocklist)).digest()

    period = int(time.time()).to_bytes(8, "big")

    tag = (
        AES.new(household_secret[:16], AES.MODE_ECB).encrypt(period + b"\x00" * 8) +
        AES.new(household_secret[16:], AES.MODE_ECB).encrypt(period + b"\x00" * 8)
    )

    commands = (
        "Initialization phase at distribution station.",
        GPCommand(
            APDU(0x11, payload=shared_secret),
            APDU(0x12, payload=household_revocation_value),
            APDU(0x13, payload=commitment_g),
            APDU(0x14, payload=commitment_z),
            APDU(0x15, payload=household_secret),
        ),
        "Set entitlement.",
        GPCommand(
            APDU(0x16, payload=household_entitlement)
        ),
        "",
        "Hash blocklist",
        GPCommand(
            APDU(0x21, p1=1, payload=blocklist[0]),
            *tuple(
                APDU(0x21, p1=2, payload=block) for block in blocklist[1:-1]
            ),
            APDU(0x21, p1=3, payload=blocklist[-1]),
        ),
        "Expected result",
        blocklist_hash.hex(),
        "",
        "Set period",
        GPCommand(
            APDU(0x22, payload=period)
        ),
        "Expected result",
        tag.hex(),
        "",
        "Compute showing off proof",
        GPCommand(
            APDU(0x23)
        ),
        "Verification",
        ScriptCommand("verify-commitment", commitment_g, commitment_z, household_entitlement, ending_args="R+COMMITMENT"),
        "",
        "Sending proof",
        GPCommand(
            APDU(0x21, p1=1, payload=blocklist[0]),
            *tuple(
                APDU(0x21, p1=2, payload=block) for block in blocklist[1:-1]
            ),
            APDU(0x21, p1=3, payload=blocklist[-1]),
            APDU(0x23),
            APDU(0x24)
        ),
        "Verification (use result of previous command)",
        ScriptCommand("verify-signature", public_bytes, tag, period, blocklist_hash, ending_args="R+COMMITMENT SIGNATURE"),
    )

    for command in commands:
        print(command)


def main():
    if len(sys.argv) == 1:
        apdus()
    elif sys.argv[1] == "verify-commitment":
        verify_commitment(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        verify_signature(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])


if __name__ == "__main__":
    main()
