#!/usr/bin/env python3
"""
Verify the toolkit: (A) reproduce the flags of the already-solved exercises, and
(B) exercise the 'related' attacks on fresh random instances.

    ../venv/bin/python test_toolkit.py

Exit code 0 = all good.
"""
import sys, os, json, hashlib, random
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cnscrypto as C
from Crypto.Util.number import getPrime

EX = os.path.normpath(os.path.join(HERE, "..", "asymmetric_encryption"))  # sessions/asymmetric_encryption/
ok = fail = 0


def check(name, cond):
    global ok, fail
    print(f"[{'OK ' if cond else 'XXX'}] {name}")
    ok += cond; fail += (not cond)


# ============================ A. real exercises ============================
def read_kv(path):
    d, ctx = {}, None
    for line in open(path):
        line = line.rstrip("\n")
        if line.startswith("--- "):
            ctx = line.strip("- ")
        elif not line:
            ctx = None
        elif " = " in line:
            k, v = line.split(" = ", 1)
            (d.setdefault(ctx, {}) if ctx else d)[k] = int(v)
    return d


def test_exercises():
    try:
        ch = json.load(open(f"{EX}/rsa/sifting_sand/challenge.json"))
        n, e = ch["n"], ch["e"]; p = C.pollard_rho(n); q = n // p; d = C.rsa_d(e, p, q)
        pt = b"".join(C.rsa_decrypt(c, d, n).to_bytes(ch["block_size"], "big")
                      for c in ch["ciphertext"])[:ch["original_length"]]
        check("rsa/sifting_sand", b"cns{" in pt)

        ch = json.load(open(f"{EX}/rsa/free_keys/challenge.json"))
        m = C.common_modulus(ch["n"], ch["e1"], ch["c1"], ch["e2"], ch["c2"])
        check("rsa/free_keys", C.find_flag(m) is not None)

        for name in ("group_chat", "better_group_chat"):
            ks = read_kv(f"{EX}/rsa/{name}/public_keys.txt")
            cs = read_kv(f"{EX}/rsa/{name}/ciphertexts.txt")
            keys = sorted(ks)
            pairs = [(list(cs.values())[i], ks[k]["n"]) for i, k in enumerate(keys)]
            m = C.hastad_broadcast(pairs, ks[keys[0]]["e"])
            check(f"rsa/{name}", C.find_flag(m) is not None)

        ch = json.load(open(f"{EX}/rsa/sports_car_desire/challenge.json"))
        d, p, q = C.wiener(ch["e"], ch["n"])
        check("rsa/sports_car_desire", C.find_flag(C.long_to_bytes(C.rsa_decrypt(ch["c"], d, ch["n"]))) is not None)

        ch = json.load(open(f"{EX}/elgamal/asymmetric_nonsense/challenge.json"))
        p = ch["p"]; mk = C.bytes_to_long(ch["known_plaintext"].encode())
        mf = C.elgamal_key_reuse(ch["cipher_known"][1], mk, ch["cipher_flag"][1], p)
        check("elgamal/asymmetric_nonsense", b"cns{" in C.long_to_bytes(mf))

        ch = json.load(open(f"{EX}/elgamal/fresh_every_time/ElGamal_challenge.json"))
        p, g, y = ch["p"], ch["g"], ch["y"]; mk = C.bytes_to_long(ch["known_plaintext"].encode())
        mf = C.elgamal_scale_mask(ch["cipher_known"][1], mk, ch["cipher_flag"][1], y, p, 1)
        check("elgamal/fresh_every_time", b"cns{" in C.long_to_bytes(mf))

        ch = json.load(open(f"{EX}/digital_signatures/dsa1_challenge.json"))
        p, q, g, y = ch["p"], ch["q"], ch["g"], ch["y"]; s = ch["signatures"]
        H = lambda msg: C.H_int_mod(msg.encode(), q)
        x = C.dsa_x_from_nonce_reuse(q, s[0]["r"], s[0]["s"], H(s[0]["message"]),
                                     s[1]["s"], H(s[1]["message"]))
        check("digital_signatures/dsa1", pow(g, x, p) == y)
    except FileNotFoundError as e:
        print(f"[--] skipped exercise tests (files not found: {e})")


# ============================ B. related attacks ============================
def smooth_prime():
    while True:
        m = 1
        while m < 10**12:
            m *= random.choice([2, 3, 5, 7, 11, 13])
        if C.is_prime(m + 1):
            return m + 1


def test_related():
    p = 7919; g = C.primitive_root(p); x = 1234
    check("bsgs", C.bsgs(g, pow(g, x, p), p) == x)

    p = smooth_prime(); g = C.primitive_root(p); x = random.randrange(2, p - 1)
    check("pohlig_hellman", C.pohlig_hellman(g, pow(g, x, p), p) == x)

    a = getPrime(200); b = a + 2
    while not C.is_prime(b):
        b += 2
    check("fermat_factor (close primes)", set(C.fermat_factor(a * b) or []) == {a, b})

    sp = smooth_prime(); N = sp * getPrime(80)
    d = C.pollard_pm1(N, bound=200000)
    check("pollard_pm1", bool(d) and N % d == 0 and 1 < d < N)

    s = getPrime(100); A = s * getPrime(100); B = s * getPrime(100)
    check("common_factor", C.common_factor([A, B])[0][2] == s)

    P, Q = getPrime(128), getPrime(128); Nn = P * Q; e = 65537; d = C.rsa_d(e, P, Q)
    check("factor_from_d", set(C.factor_from_d(Nn, e, d)) == {P, Q})

    m = C.bytes_to_long(b"cns{x}"); e = 3; N = getPrime(512) * getPrime(512)
    check("low_exponent_root", C.low_exponent_root(pow(m, e, N), e, N) == C.long_to_bytes(m))

    P, Q = getPrime(128), getPrime(128); N = P * Q; e = 65537; d = C.rsa_d(e, P, Q)
    secret = C.bytes_to_long(b"cns{lsb}") % N; c = pow(secret, e, N)
    rec = C.bytes_to_long(C.lsb_oracle(N, e, c, lambda cc: pow(cc, d, N) & 1, verbose=False))
    check("lsb_oracle", rec == secret)

    q = getPrime(160); x = random.randrange(2, q); k1 = random.randrange(2, q)
    a, b = 1, 5; k2 = (a * k1 + b) % q; g = 2; P = getPrime(300)
    r1 = pow(g, k1, P) % q; r2 = pow(g, k2, P) % q
    H1 = random.randrange(1, q); H2 = random.randrange(1, q)
    s1 = C.inverse(k1, q) * (H1 + x * r1) % q; s2 = C.inverse(k2, q) * (H2 + x * r2) % q
    check("dsa_x_from_linear_nonce", C.dsa_x_from_linear_nonce(q, r1, s1, H1, r2, s2, H2, a, b) == x)

    P, Q = getPrime(256), getPrime(256); N = P * Q; e = 65537; d = C.rsa_d(e, P, Q)
    s1, s2 = C.rsa_sign_raw(42, d, N), C.rsa_sign_raw(1337, d, N)
    mf, sf = C.rsa_forge_product(42, s1, 1337, s2, N)
    check("rsa_forge_product", C.rsa_verify_raw(mf, sf, e, N) and mf == 42 * 1337 % N)


if __name__ == "__main__":
    print("A. solved exercises"); test_exercises()
    print("\nB. related attacks (random instances)"); test_related()
    print(f"\n==== {ok} ok, {fail} fail ====")
    sys.exit(1 if fail else 0)
