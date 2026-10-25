# Matthew Wear
# Intro to Crypto
# Test CBC-MAC
# 10/22/2026

import unittest
from cbc_mac import mac, verify


class TestCBCMAC(unittest.TestCase):

    def setUp(self):
        # Key and messages from Table 1
        self.key = bytes.fromhex(
            "2b7e151628aed2a6abf7158809cf4f3c"
        )

        self.message = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )

        # Expected tags for 1 through 4 blocks
        self.tags = [
            "3ad77bb40d7a3660a89ecaf32466ef97",
            "b148c17f309ee692287ae57cf12add49",
            "c93d11bfaf08c5dc4d90b37b4dee002b",
            "a7356e1207bb406639e5e5ceb9a9ed93"
        ]

    def test_known_answers(self):
        # Check all four tags and verification
        for i in range(1, 5):
            msg = self.message[:i * 16]
            expected = bytes.fromhex(self.tags[i - 1])

            self.assertEqual(mac(self.key, msg), expected)
            self.assertTrue(verify(self.key, msg, expected))

    def test_invalid_messages(self):
        # Empty and 17-byte messages must be rejected
        for msg in [b"", bytes(17)]:
            with self.assertRaises(ValueError):
                mac(self.key, msg)

            self.assertFalse(
                verify(self.key, msg, bytes(16))
            )

    def test_invalid_tags(self):
        # Tags must be exactly 16 bytes
        msg = self.message[:16]

        for size in [0, 15, 17]:
            self.assertFalse(
                verify(self.key, msg, bytes(size))
            )

    def test_modified_messages_and_tags(self):
        # Check that modifying one bit causes rejection
        for i in range(1, 5):
            msg = self.message[:i * 16]
            tag = bytes.fromhex(self.tags[i - 1])

            # Flip one bit in the message
            modified_msg = bytearray(msg)
            modified_msg[0] ^= 0x01

            self.assertFalse(
                verify(self.key, bytes(modified_msg), tag)
            )

            # Flip one bit in the tag
            modified_tag = bytearray(tag)
            modified_tag[0] ^= 0x01

            self.assertFalse(
                verify(self.key, msg, bytes(modified_tag))
            )


if __name__ == "__main__":
    unittest.main()
