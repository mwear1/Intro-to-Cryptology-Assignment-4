# Matthew Wear
# Intro to Crypto
# CBC-MAC
# 10/22/2026

import hmac
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def mac(key: bytes, msg: bytes) -> bytes:
    # Basic CBC-MAC accepts only complete, nonempty blocks.
    if not msg or len(msg) % BLOCK_SIZE != 0:
        raise ValueError("Message must contain complete 16-byte blocks")

    cipher = AES.new(key, AES.MODE_ECB)
    x = bytes(BLOCK_SIZE)  # x_0 = 0^128

    for i in range(0, len(msg), BLOCK_SIZE):
        block = msg[i:i + BLOCK_SIZE]
        mixed = bytes(a ^ b for a, b in zip(block, x))
        x = cipher.encrypt(mixed)  # x_i = F_k(m_i XOR x_(i-1))

    return x  # Final chaining value is the tag.


def verify(key: bytes, msg: bytes, tag: bytes) -> bool:
    if not msg or len(msg) % BLOCK_SIZE != 0 or len(tag) != BLOCK_SIZE:
        return False

    return hmac.compare_digest(mac(key, msg), tag)
