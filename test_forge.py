# Matthew Wear
# Intro to Crypto
# Forgery tests
# 10/22/2026

import unittest
from forge import MacOracle, forge, TARGET
from cbc_mac import verify


class TestForgery(unittest.TestCase):

    def setUp(self):
        # Create an oracle with a fresh random key
        self.oracle = MacOracle()

    def test_forged_tag(self):
        # Check that the forged tag is valid for the target
        tag = forge(self.oracle.query, TARGET)

        self.assertTrue(
            verify(self.oracle.key, TARGET, tag)
        )

    def test_two_queries(self):
        # The attack must make exactly two oracle queries
        forge(self.oracle.query, TARGET)

        self.assertEqual(len(self.oracle.queries), 2)

    def test_target_not_queried(self):
        # The complete target must never be queried
        forge(self.oracle.query, TARGET)

        queried_messages = [
            msg for msg, tag in self.oracle.queries
        ]

        self.assertNotIn(TARGET, queried_messages)

    def test_invalid_target(self):
        # The target must contain at least two complete blocks
        with self.assertRaises(ValueError):
            forge(self.oracle.query, bytes(16))

        # Reject messages that are not multiples of 16 bytes
        with self.assertRaises(ValueError):
            forge(self.oracle.query, bytes(33))

        # Invalid inputs must not cause any oracle queries
        self.assertEqual(len(self.oracle.queries), 0)

    def test_100_forgeries(self):
        # Repeat the attack using 100 fresh random keys
        successes = 0

        for _ in range(100):
            oracle = MacOracle()
            tag = forge(oracle.query, TARGET)

            queried_messages = [
                msg for msg, _ in oracle.queries
            ]

            if (
                verify(oracle.key, TARGET, tag)
                and TARGET not in queried_messages
                and len(oracle.queries) == 2
            ):
                successes += 1

        self.assertEqual(successes, 100)


if __name__ == "__main__":
    unittest.main()
