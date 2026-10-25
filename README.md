# Assignment 4: Forging Basic CBC-MAC

**Name:** Matthew Wear  
**Course:** Introduction to Cryptography  
**Language:** Python 3.14.8  
**AES Library:** PyCryptodome

## Overview

This assignment implements basic CBC-MAC using AES-128 and demonstrates a forgery attack when messages of different lengths are accepted under the same key.

The assignment also demonstrates how restricting messages to a fixed length prevents the attack.

## Files

- `analysis.md` - Written answers to Problems 1 and 2, and implementation results.
- `cbc_mac.py` - CBC-MAC generation and verification.
- `test_cbc_mac.py` - Automated tests for CBC-MAC.
- `forge.py` - MAC oracle and two-query forgery demonstration.
- `test_forge.py` - Automated tests for the forgery.
- `fixed_length.py` - Demonstrates the fixed-length restriction.

## Requirements

Python 3 and the PyCryptodome library are required.

Install PyCryptodome using:

```powershell
py -m pip install pycryptodome
```

The `unittest` module is included with Python and does not require installation.

## Running the Tests

### Problem 3(a): CBC-MAC Tests

```powershell
py -m unittest -v test_cbc_mac.py
```

Expected result: 4 passing tests.

### Problem 3(b): Forgery Tests

```powershell
py -m unittest -v test_forge.py
```

Expected result: 5 passing tests.

### Run All Tests

```powershell
py -m unittest discover -v
```

Expected result: 9 passing tests.

## Running the Demonstrations

### Problem 3(b): CBC-MAC Forgery

```powershell
py forge.py
```

The program prints both oracle queries and their tags in hexadecimal, the forged tag, and the verification result.

It also repeats the attack 100 times using fresh random AES keys.

Expected results:

- Target queried: False
- Verification: True
- Successful forgeries: 100/100

### Problem 3(c): Fixed-Length Restriction

```powershell
py fixed_length.py
```

The program attempts the same forgery against an oracle that only accepts 3-block messages.

The first query is rejected because it contains only one block.

Expected results:

- Forgery rejected
- Accepted queries: 0
- One-block message accepted: False
- Two-block message accepted: False

## Implementation Notes

AES-128 is used to encrypt individual 16-byte blocks. The CBC-MAC chaining loop is implemented manually without using a library's CBC mode or CBC-MAC implementation.

The oracle generates a random 128-bit key using Python's `secrets` module.

The fixed-length demonstration shows why basic CBC-MAC should only be used with messages of an agreed fixed length.
