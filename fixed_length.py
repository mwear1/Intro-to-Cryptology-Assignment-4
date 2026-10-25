# Matthew Wear
# Intro to Crypto
# Fixed-Length Restriction
# 10/22/2026

from forge import MacOracle, forge, TARGET
from cbc_mac import verify

REQUIRED_LENGTH = 48  # 3 AES blocks


class FixedLengthOracle(MacOracle):

    def query(self, msg: bytes) -> bytes:
        # Reject messages that are not exactly 3 blocks
        if len(msg) != REQUIRED_LENGTH:
            raise ValueError("Only 3-block messages are accepted")

        return super().query(msg)

    def verify(self, msg: bytes, tag: bytes) -> bool:
        # Reject messages that are not exactly 3 blocks
        if len(msg) != REQUIRED_LENGTH:
            return False

        return verify(self.key, msg, tag)


def main():
    oracle = FixedLengthOracle()

    try:
        forged_tag = forge(oracle.query, TARGET)
        print("Forged tag:", forged_tag.hex())

    except ValueError as error:
        print("Forgery failed:", error)

    print("Accepted queries:", len(oracle.queries))
    print("One-block message accepted:",
          oracle.verify(TARGET[:16], bytes(16)))
    print("Two-block message accepted:",
          oracle.verify(TARGET[:32], bytes(16)))


if __name__ == "__main__":
    main()
