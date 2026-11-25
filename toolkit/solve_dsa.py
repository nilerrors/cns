#!/usr/bin/env python3
"""
solve_dsa.py -- DSA / ElGamal-signature solver.

Usage:
    ./solve_dsa.py dsa_challenge.json

Recovers the signer's private key x from a broken DSA instance and (if the
challenge ships an encrypted flag keyed on x) decrypts it.

Supported weaknesses:
  * nonce reuse            -- two signatures share r  (k identical)
  * known / constant k     -- pass --k K
  * linear nonce k2=a*k1+b -- pass --a A --b B (needs two signatures)

The message-hash convention (int(sha256(m)) mod q, FIPS truncation, other hash
algorithms) is auto-detected by checking which one makes a given signature verify.
"""
import sys, os, json, argparse, hashlib, itertools, base64, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cnscrypto as C


def norm(s):
    return s.lower().replace("-", "").replace("_", "")


HASHES = {norm(h): h for h in hashlib.algorithms_guaranteed if not h.startswith("shake")}


def hash_candidates(desc):
    """Hash algos mentioned in the description first, then all others as fallback."""
    d = norm(desc or "")
    named = [HASHES[n] for n in HASHES if n in d]
    named.sort(key=lambda h: (d.index(norm(h)), -len(h)))
    return list(dict.fromkeys(named + list(HASHES.values())))


def make_H(algo, q, mode):
    if mode == "int":
        return lambda m: C.H_int_mod(m, q, algo)
    if mode == "fips":
        return lambda m: C.H_fips(m, q, algo)
    if mode == "little":
        return lambda m: int.from_bytes(hashlib.new(algo, m).digest(), "little") % q


def msg_bytes(sig):
    m = sig["message"]
    return m.encode() if isinstance(m, str) else bytes(m)


def detect_hash(p, q, g, y, sigs, desc):
    """Return an H(bytes)->int that verifies the first signature, or None."""
    s0 = sigs[0]
    for algo in hash_candidates(desc):
        for mode in ("int", "fips", "little"):
            H = make_H(algo, q, mode)
            if C.dsa_verify(p, q, g, y, H(msg_bytes(s0)), s0["r"], s0["s"]):
                return H, f"{mode}({algo})"
    return None, None


def try_keystream(x, ct, desc):
    """Reproduce the 'flag XOR keystream' pattern where keystream =
    hash(f'{x}:0') || hash(f'{x}:1') || ... Tries a handful of templates/hashes."""
    def ks_from(algo, template, length):
        out = b""
        for i in itertools.count():
            if len(out) >= length:
                return out[:length]
            out += hashlib.new(algo, template.format(x=x, i=i).encode()).digest()

    templates = ["{x}:{i}", "{x}{i}", "{x}-{i}", "{x}|{i}", "{x}_{i}", "{x},{i}", "{i}:{x}"]
    algos = hash_candidates(desc)
    for algo in algos[:6]:
        for t in templates:
            ks = ks_from(algo, t, len(ct))
            pt = bytes(a ^ b for a, b in zip(ct, ks))
            if C.find_flag(pt) or C.looks_text(pt):
                return pt, f"{algo}('{t}')"
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--k", type=str, help="known nonce k")
    ap.add_argument("--a", type=str, help="linear nonce multiplier")
    ap.add_argument("--b", type=str, help="linear nonce offset")
    args = ap.parse_args()

    o = json.load(open(args.file))
    p, q, g, y = o["p"], o["q"], o["g"], o["y"]
    sigs = o["signatures"]
    desc = o.get("hash", "")

    H, hname = detect_hash(p, q, g, y, sigs, desc)
    if H is None:
        print("[-] no hash convention verified the signatures; using int(sha256) mod q")
        H = make_H("sha256", q, "int")
    else:
        print(f"[*] hash convention: H(m) = {hname} mod q")

    x = None
    # nonce reuse: two signatures sharing r
    for a, b in itertools.combinations(sigs, 2):
        if a["r"] == b["r"] and a["s"] != b["s"]:
            print(f"[*] nonce reuse: signatures share r = {a['r']}")
            x = C.dsa_x_from_nonce_reuse(q, a["r"], a["s"], H(msg_bytes(a)),
                                         b["s"], H(msg_bytes(b)))
            break
    # known k
    if x is None and args.k:
        s = sigs[0]
        x = C.dsa_x_from_known_k(q, s["r"], s["s"], H(msg_bytes(s)), C.to_int(args.k))
        print("[*] used known nonce k")
    # linear nonce
    if x is None and args.a and args.b and len(sigs) >= 2:
        s1, s2 = sigs[0], sigs[1]
        x = C.dsa_x_from_linear_nonce(q, s1["r"], s1["s"], H(msg_bytes(s1)),
                                      s2["r"], s2["s"], H(msg_bytes(s2)),
                                      C.to_int(args.a), C.to_int(args.b))
        print("[*] used linear nonce relation")

    if x is None:
        print("[-] could not recover x (need nonce reuse, --k, or --a/--b)")
        return 1
    if pow(g, x, p) != y:
        print(f"[-] recovered x does not satisfy g^x = y -- wrong hash/relation?\n    x = {x}")
        return 1
    print(f"[+] private key x = {x}")

    enc = o.get("encrypted_flag")
    if enc:
        ct = C.parse_blob(enc)
        pt, how = try_keystream(x, ct, o.get("flag_encryption", desc))
        if pt:
            print(f"[*] flag keystream: {how}")
            print(f"[+] FLAG: {C.find_flag(pt) or pt.decode(errors='replace')}")
        else:
            print("[-] recovered x but could not reproduce the flag keystream;")
            print("    inspect 'flag_encryption' and XOR manually with x =", x)
    return 0


if __name__ == "__main__":
    sys.exit(main())
