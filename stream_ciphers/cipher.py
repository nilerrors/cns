"""
Encryption module.

This module implements a custom stream cipher.
"""

# LCG parameters
A = 1103515245
C = 12345
M = 2**31


def next_state(state):
    """Generate the next PRNG state."""
    return (A * state + C) % M


def generate_keystream(seed, length):
    """Generate a pseudorandom keystream."""
    state = seed
    keystream = bytearray()

    for _ in range(length):
        state = next_state(state)
        keystream.append((state >> 16) & 0xff)

    return bytes(keystream)


def encrypt(plaintext, seed):
    """Encrypt plaintext using XOR."""
    keystream = generate_keystream(seed, len(plaintext))
    return bytes(
        p ^ k for p, k in zip(plaintext, keystream)
    )


def decrypt(ciphertext, seed):
    """Decrypt ciphertext using XOR."""
    return encrypt(ciphertext, seed)

if __name__ == "__main__":
    def to_ascii(lst: list[int]) -> str:
        return ''.join(chr(v) for v in lst)

    def xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(a[i] ^ b[i] for i in range(min(len(a), len(b))))

    pt = b"STATUS: SERVER ONLINE"
    ct = bytes.fromhex("22135cc0b9daa9e717f98a998e6ee5e92655e1a88f")
    ks = xor_bytes(pt, ct)
    st = bytes.fromhex("12296eef9eece6b42dd2bf90aa63b6d21a7cc98b95c78b4b01d833d628a941b82fb65176b4ed3c3f64")
    print(pt)
    print(ct)
    print(ks)
    print(to_ascii(xor_bytes(ks, st)))

    for Hn in range(2**7):
        for Ln in range(2**16):
            state = Hn * 2**24 + ks[0] * 2**16 + Ln
            origin_state = state
            ok = True
            for k in ks:
                if k != (state >> 16) & 0xff:
                    ok = False
                    break
                state = next_state(state)
            if not ok:
                continue
            seed = (pow(A, -1, M) * (origin_state - C)) % M
            print(seed)
            print(to_ascii(decrypt(st, seed)))
