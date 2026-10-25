# Assignment 4: Forging Basic CBC-MAC

**Name:** Matthew Wear

## Problem 1: Basic CBC-MAC

### (a) Gen, Mac, and Vrfy

**Gen:** Generate a random 128-bit secret key `k` for AES-128.

**Mac:** Given a message consisting of $\ell$ blocks, each 128 bits:

1. Initialize the chaining value to $x_0 = 0^{128}$.
2. For each message block $m_i$, calculate:

   $$
   x_i = F_k(m_i \oplus x_{i-1})
   $$

3. After processing all blocks, output the final chaining value as the tag:

   $$
   t = x_\ell
   $$

**Vrfy:** Given a message $m$ and tag $t$, recompute the MAC using the same secret key. Return 1 if the computed tag matches $t$, otherwise return 0.

The algorithm uses a fixed zero initialization value and processes each block sequentially. Each chaining value depends on the previous block's result, and the final value becomes the message authentication tag.

### (b) Differences Between CBC-MAC and CBC-Mode Encryption

1. **Initialization:** CBC-MAC is deterministic and uses a fixed initial chaining value of $x_0 = 0^{128}$. CBC-mode encryption uses a fresh random IV to provide CPA security.

2. **Output:** CBC-MAC outputs only the final chaining value $x_\ell$ as the authentication tag. CBC-mode encryption outputs the IV and all ciphertext blocks to provide confidentiality.

### (c) Security of Basic CBC-MAC

Basic CBC-MAC is secure when all messages have the same fixed length of $\ell$ blocks, where $\ell$ is agreed upon in advance.

If $F$ is a secure pseudorandom function (PRF), then basic CBC-MAC is a secure MAC for messages of length $\ell \cdot n$ bits.

If messages of different lengths are allowed under the same key, basic CBC-MAC is no longer secure because an attacker can construct valid message-tag pairs without knowing the secret key.

## Problem 2: A Forgery on Messages of Different Lengths

### (a) Forging a Valid CBC-MAC Tag

The attacker queries the MAC oracle on two messages:

$$
m = m_1 \| \cdots \| m_\ell
$$

$$
m' = m'_1 \| \cdots \| m'_{\ell'}
$$

The oracle returns tags $t = \mathsf{Mac}_k(m)$ and $t' = \mathsf{Mac}_k(m')$.

The attacker constructs the forged message:

$$
m^* = m_1 \| \cdots \| m_\ell \| (m'_1 \oplus t) \| m'_2 \| \cdots \| m'_{\ell'}
$$

**Computing the chaining values:**

For the first $\ell$ blocks, CBC-MAC processes $m$ normally:

$$
x_0 = 0^{128}
$$

$$
x_i = F_k(m_i \oplus x_{i-1})
$$

After processing these blocks:

$$
x_\ell = t
$$

The next block is $(m'_1 \oplus t)$. Its chaining value becomes:

$$
x_{\ell+1} = F_k((m'_1 \oplus t) \oplus x_\ell)
$$

Since $x_\ell = t$:

$$
x_{\ell+1} = F_k(m'_1 \oplus t \oplus t)
$$

Using $t \oplus t = 0^{128}$:

$$
x_{\ell+1} = F_k(m'_1)
$$

This is exactly the first chaining value when computing $\mathsf{Mac}_k(m')$.

The remaining blocks $m'_2, \ldots, m'_{\ell'}$ follow the same chaining process as $m'$. Therefore:

$$
x_{\ell+\ell'} = t'
$$

Thus:

$$
\boxed{\mathsf{Mac}_k(m^*) = t'}
$$

**Why the forgery is valid:**

The forged message contains $\ell + \ell'$ blocks, while the original queried messages contain $\ell$ and $\ell'$ blocks. Since both lengths are at least one block, $m^*$ differs from both queried messages.

The attacker can therefore produce the valid message-tag pair $(m^*, t')$ without querying $m^*$ or knowing the secret key.

The forgery succeeds with probability 1 because the chaining values are guaranteed to match.

### (b) Forging a Tag for a Fixed Target Message

Let the target message be:

$$
M = M_1 \| M_2 \| \cdots \| M_L
$$

where $L \geq 2$.

**First query:**

Query the MAC oracle on the first block:

$$
m = M_1
$$

The oracle returns:

$$
t = \mathsf{Mac}_k(M_1) = F_k(M_1)
$$

**Second query:**

Construct a new message using the first tag:

$$
m' = (M_2 \oplus t) \| M_3 \| \cdots \| M_L
$$

Query the MAC oracle on $m'$ and receive:

$$
t' = \mathsf{Mac}_k(m')
$$

**Showing the forgery works:**

When computing CBC-MAC on the target $M$, the first chaining value is:

$$
x_1 = F_k(M_1) = t
$$

The second chaining value is:

$$
x_2 = F_k(M_2 \oplus t)
$$

This is exactly the first chaining value when computing the MAC of $m'$, since CBC-MAC starts with $x_0 = 0^{128}$.

All remaining blocks $M_3, \ldots, M_L$ are identical, so the chaining values continue to match.

Therefore:

$$
\boxed{\mathsf{Mac}_k(M) = t'}
$$

**Why this is a valid forgery:**

Neither query equals the target message $M$:

- The first query contains only one block, while $M$ contains $L \geq 2$ blocks.
- The second query contains $L-1$ blocks, so it also differs from $M$.

The attacker has made exactly two queries and obtained a valid tag for the target without ever querying it directly.

The attack succeeds with probability 1 because the chaining values match for every secret key.

### (c) Fixed-Length Restriction

Basic CBC-MAC is secure when all messages have a fixed length of $\ell$ blocks, assuming $F$ is a secure PRF.

**Attack (a):**

The forged message $m^*$ has $\ell_1 + \ell_2$ blocks, where $\ell_1$ and $\ell_2$ are the lengths of the two queried messages.

If both queries must contain exactly $\ell$ blocks, the forged message will contain $2\ell$ blocks.

Since $2\ell \neq \ell$, the verifier rejects the forged message.

**Attack (b):**

The attacker queries the first block $M_1$ and then queries the remaining $L-1$ blocks with the modified first block.

If the target has the required length $L = \ell \geq 2$, neither query has exactly $\ell$ blocks, so both are rejected by the oracle.

**Conclusion:**

Both attacks rely on authenticating messages of different lengths under the same key. Restricting CBC-MAC to a fixed message length prevents these attacks because messages with invalid lengths are rejected.


## Problem 3: Implementation

### (a) CBC-MAC Implementation

Basic CBC-MAC was implemented in Python using PyCryptodome for AES-128 encryption.

The implementation initializes the chaining value to $x_0 = 0^{128}$ and processes each 16-byte message block using:

$$
x_i = F_k(m_i \oplus x_{i-1})
$$

The final chaining value $x_\ell$ is returned as the authentication tag.

The `verify` function recomputes the MAC and compares the result with the provided tag using `hmac.compare_digest` for constant-time comparison.

**Testing:**

Automated tests were implemented using Python's `unittest` framework to verify:

1. All four known-answer tags from Table 1.
2. Rejection of empty and invalid-length messages.
3. Rejection of tags with invalid lengths.
4. Rejection of modified messages and tags.

**Test Results:**

```text
Ran 4 tests in 0.038s

OK
```

All four tests passed, confirming that the implementation produces the expected tags and correctly handles invalid inputs.

### (b) CBC-MAC Forgery

The attack was implemented using a MAC oracle with a randomly generated 128-bit AES key. The oracle returns tags for queried messages without revealing the secret key.

The target message contains 3 blocks (48 bytes):

`from=alice&to=mallory&amount=1000000&note=rent!!`

The attack makes two queries:

$$
m = M_1
$$

The first query returns:

$$
t = \mathsf{Mac}_k(M_1)
$$

The second query is constructed as:

$$
m' = (M_2 \oplus t) \| M_3
$$

The returned tag $t'$ is then used as the forged tag for the original target.

**Output:**

```text
Target length: 48 bytes
Query 1 (hex): 66726f6d3d616c69636526746f3d6d61
Tag 1 (hex):   45739438827bf851e6e1e2a01840c62d
Query 2 (hex): 291ffb4afb5d993c89948cd42571f61d30303030266e6f74653d72656e742121
Tag 2 (hex):   a9094f75cca3e194f712199874332ea7
Forged tag (hex): a9094f75cca3e194f712199874332ea7
Target queried: False
Verification: True
Successful forgeries: 100/100
```

**Explanation:**

The forged tag was accepted because the second oracle query produces the same final chaining value as the target message.

The target was never queried directly, and the attack succeeded in all 100 trials using fresh random keys.

This demonstrates that basic CBC-MAC is insecure when messages of different lengths are accepted under the same key.

### (c) Fixed-Length Check

The oracle and verifier were modified to accept only messages containing exactly 3 blocks (48 bytes).

**Output:**

```text
Forgery failed: Only 3-block messages are accepted
Accepted queries: 0
One-block message accepted: False
Two-block message accepted: False
```

**Explanation:**

The attack fails on the first query because $M_1$ contains only one block, while the oracle requires exactly 3 blocks.

Since the first query is rejected, the attacker cannot obtain the tag needed to construct the second query.

This demonstrates that restricting basic CBC-MAC to a fixed message length prevents the variable-length forgery.
