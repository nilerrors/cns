#!/usr/bin/env python3
"""
solve_elgamal.py -- ElGamal challenge solver.

Usage:
    ./solve_elgamal.py challenge.json
    ./solve_elgamal.py challenge.json --x 12345     # private key known

Handles the common patterns:
  * private key x given (or p small enough to dlog) -> straight decrypt
  * known-plaintext + SAME nonce (equal c1)         -> mask reuse
  * known-plaintext + related nonce (c1' = c1*g^d)  -> scale the mask by y^d
Fields are read loosely: p/q/modulus, g/alpha/generator, y/Y/pub,
known_plaintext, cipher_known/cipher_flag as [c1, c2] pairs (or c1_*/c2_*).
"""
import sys, os, json, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cnscrypto as C


def get(o, *names, default=None):
    for nm in names:
        if nm in o:
            return o[nm]
    return default


def pair(o, base):
    """Pull a [c1,c2] pair whether it's a list or split fields."""
    v = get(o, base, f"{base}_pair")
    if isinstance(v, (list, tuple)):
        return C.to_int(v[0]), C.to_int(v[1])
    c1 = get(o, f"{base}_c1", f"c1_{base}", f"{base}1")
    c2 = get(o, f"{base}_c2", f"c2_{base}", f"{base}2")
    if c1 is not None and c2 is not None:
        return C.to_int(c1), C.to_int(c2)
    return None


def as_bytes_or_int(v):
    """known_plaintext may be text or an int."""
    if isinstance(v, int):
        return v
    try:
        return C.to_int(v)
    except (ValueError, TypeError):
        return C.bytes_to_long(v.encode())


def show(m):
    b = C.long_to_bytes(m) if isinstance(m, int) else m
    flag = C.find_flag(b)
    if flag:
        print(f"[+] FLAG: {flag}")
    try:
        print(f"[+] plaintext: {b.decode()}")
    except UnicodeDecodeError:
        print(f"[+] plaintext (raw): {b!r}\n[+] hex: {b.hex()}")
    return flag is not None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--x", type=str, help="private key, if known")
    ap.add_argument("--max-delta", type=int, default=5000)
    args = ap.parse_args()

    o = json.load(open(args.file))
    p = C.to_int(get(o, "p", "q", "modulus", "prime"))
    g = C.to_int(get(o, "g", "alpha", "generator"))
    y = get(o, "y", "Y", "Y_A", "pub", "public_key")
    y = C.to_int(y) if y is not None else None

    flag_pair = pair(o, "cipher_flag") or pair(o, "flag") or pair(o, "cipher")
    known_pair = pair(o, "cipher_known") or pair(o, "known")
    known_pt = get(o, "known_plaintext", "known_message", "plaintext")

    if flag_pair is None:
        print("[-] could not find the flag ciphertext pair"); return 1
    c1f, c2f = flag_pair
    print(f"[*] p has {p.bit_length()} bits")

    # 1. private key available (given, or recoverable by dlog on weak p)
    x = C.to_int(args.x) if args.x else None
    if x is None and p.bit_length() <= 60:
        print("[*] small p -> recovering x by discrete log ...")
        x = C.discrete_log(g, y, p)
    if x is not None:
        print(f"[*] x = {x}")
        assert pow(g, x, p) == y, "x does not match y!"
        return 0 if show(C.elgamal_decrypt(c1f, c2f, x, p)) else 1

    # 2/3. known-plaintext patterns (nonce reuse / related nonce)
    if known_pair and known_pt is not None:
        c1k, c2k = known_pair
        m_known = as_bytes_or_int(known_pt)
        if c1k == c1f:
            print("[*] c1 identical -> same nonce k (mask reuse)")
            return 0 if show(C.elgamal_key_reuse(c2k, m_known, c2f, p)) else 1
        # related nonce: find small delta with c1k * g^delta == c1f
        print("[*] different c1 -> searching for related nonce delta ...")
        acc = c1k % p
        for delta in range(1, args.max_delta + 1):
            acc = acc * g % p
            if acc == c1f:
                print(f"[*] found delta = {delta}  (c1_flag = c1_known * g^{delta})")
                return 0 if show(C.elgamal_scale_mask(c2k, m_known, c2f, y, p, delta)) else 1
        print(f"[-] no delta <= {args.max_delta}; nonce may be unrelated")

    print("[-] not enough info; supply --x or a known-plaintext pair")
    return 1


if __name__ == "__main__":
    sys.exit(main())
