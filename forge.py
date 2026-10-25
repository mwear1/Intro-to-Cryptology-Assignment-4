# Matthew Wear
# Intro to Crypto
# CBC-MAC forgery
# 10/22/2026

import secrets
from cbc_mac import mac, verify

BLOCK_SIZE = 16
TARGET = b"from=alice&to=mallory&amount=1000000&note=rent!!"


class MacOracle:
    def __init__(self):
        self.key = secrets.token_bytes(16)
        self.queries = []

    def query(self, msg: bytes) -> bytes:
        tag = mac(self.key, msg)
        self.queries.append((msg, tag))
        return tag


def forge(query, target: bytes) -> bytes:
    if len(target) < 2 * BLOCK_SIZE or len(target) % BLOCK_SIZE != 0:
        raise ValueError("Target must have at least two complete blocks")

    # First query: the target's first block.
    first_tag = query(target[:BLOCK_SIZE])

    # Second query: M_2 XOR first_tag, followed by remaining blocks.
    changed_block = bytes(
        a ^ b for a, b in zip(target[BLOCK_SIZE:2 * BLOCK_SIZE], first_tag)
    )
    second_message = changed_block + target[2 * BLOCK_SIZE:]

    forged_tag = query(second_message)
    return forged_tag


def main():
    successes = 0

    for trial in range(100):
        oracle = MacOracle()  # Fresh key for each trial.
        forged_tag = forge(oracle.query, TARGET)

        target_was_queried = any(
            msg == TARGET for msg, _ in oracle.queries
        )
        valid = verify(oracle.key, TARGET, forged_tag)

        if trial == 0:
            print(f"Target length: {len(TARGET)} bytes")

            for i, (msg, tag) in enumerate(oracle.queries, start=1):
                print(f"Query {i} (hex): {msg.hex()}")
                print(f"Tag {i} (hex):   {tag.hex()}")

            print(f"Forged tag (hex): {forged_tag.hex()}")
            print(f"Target queried: {target_was_queried}")
            print(f"Verification: {valid}")

        if len(oracle.queries) == 2 and not target_was_queried and valid:
            successes += 1

    print(f"Successful forgeries: {successes}/100")


if __name__ == "__main__":
    main()
