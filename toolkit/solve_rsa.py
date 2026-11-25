#!/usr/bin/env python3
"""
solve_rsa.py -- point-and-shoot RSA solver for CNS challenges.

Usage:
    ./solve_rsa.py challenge.json            # auto-detect fields + attack
    ./solve_rsa.py keys.txt ciphertexts.txt  # group-chat style (broadcast / gcd)
    ./solve_rsa.py -n N -e E -c C            # pass values directly
    ./solve_rsa.py -n N -e E -c C --attack wiener

It loads whatever it can (n,e,c,d,p,q, or lists of keys), then tries, in order:
  factors given -> d given -> common-modulus -> broadcast -> shared-prime gcd
  -> factor small n -> fermat (close primes) -> pollard p-1 -> wiener -> low-e root.
Prints the recovered plaintext/flag and the name of the attack that worked.

Everything here is a thin wrapper over cnscrypto.py -- read that for the math.
"""
import sys, os, json, argparse, math
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cnscrypto as C

SMALL_N_BITS = 100           # below this we just factor n outright


# ---------- loading ----------------------------------------------------------

def load_kv_txt(path):
    """Parse the '--- KEY 1 ---\\n n = ...\\n e = ...' blocks and 'c1 = ...' files."""
    d, ctx = {}, None
    for line in open(path):
        line = line.rstrip("\n")
        if line.startswith("--- ") and line.endswith(" ---"):
            ctx = line[4:-4]
        elif not line.strip():
            ctx = None
        elif " = " in line:
            k, v = line.split(" = ", 1)
            try:
                v = C.to_int(v)
            except ValueError:
                pass
            (d.setdefault(ctx, {}) if ctx else d).__setitem__(k.strip(), v)
    return d


def collect(obj, *names):
    for nm in names:
        if isinstance(obj, dict) and nm in obj:
            return obj[nm]
    return None


def normalize(obj):
    """Return a dict with canonical keys pulled from many possible field names."""
    g = {}
    g["n"] = collect(obj, "n", "N", "modulus")
    g["e"] = collect(obj, "e", "E", "exponent", "public_exponent")
    g["d"] = collect(obj, "d", "private_exponent")
    g["p"] = collect(obj, "p", "prime1", "P")
    g["q"] = collect(obj, "q", "prime2", "Q")
    g["c"] = collect(obj, "c", "ct", "ciphertext", "cipher", "C")
    g["e1"] = collect(obj, "e1"); g["e2"] = collect(obj, "e2")
    g["c1"] = collect(obj, "c1"); g["c2"] = collect(obj, "c2")
    g["block_size"] = collect(obj, "block_size", "blocksize")
    g["original_length"] = collect(obj, "original_length", "length", "msg_len")
    for k in ("n", "e", "d", "p", "q", "e1", "e2", "c1", "c2", "block_size", "original_length"):
        if g[k] is not None and not isinstance(g[k], list):
            g[k] = C.to_int(g[k])
    return g


# ---------- output -----------------------------------------------------------

def show(attack, data):
    """Print result bytes/int nicely, highlighting any flag."""
    if isinstance(data, int):
        data = C.long_to_bytes(data)
    flag = C.find_flag(data)
    print(f"\n[+] attack: {attack}")
    if flag:
        print(f"[+] FLAG: {flag}")
    try:
        print(f"[+] plaintext: {data.decode()}")
    except UnicodeDecodeError:
        print(f"[+] plaintext (raw): {data!r}")
        print(f"[+] plaintext (hex): {data.hex()}")
    return flag is not None


def decrypt_blocks(cts, d, n, block_size=None, original_length=None):
    """Decrypt one int, a list of int blocks, or a hex string."""
    if isinstance(cts, str):
        try:
            cts = C.to_int(cts)
        except ValueError:
            cts = C.bytes_to_long(C.parse_blob(cts))
    if isinstance(cts, int):
        return C.long_to_bytes(C.rsa_decrypt(cts, d, n))
    out = bytearray()
    for c in cts:
        c = C.to_int(c)
        m = C.rsa_decrypt(c, d, n)
        out += m.to_bytes(block_size, "big") if block_size else C.long_to_bytes(m)
    if original_length:
        out = out[:original_length]
    return bytes(out)


# ---------- attack cascade ---------------------------------------------------

def solve_single(g, forced=None):
    n, e, c = g["n"], g["e"], g["c"]
    bs, ol = g["block_size"], g["original_length"]

    def finish(name, p, q):
        d = C.rsa_d(e, p, q)
        print(f"[*] p = {p}\n[*] q = {q}\n[*] d = {d}")
        return show(name, decrypt_blocks(c, d, n, bs, ol))

    # explicit factors
    if g["p"] and g["q"] and e:
        return finish("factors-given", g["p"], g["q"])

    # explicit private exponent
    if g["d"] and n:
        print(f"[*] using given d")
        return show("d-given", decrypt_blocks(c, g["d"], n, bs, ol))

    # common modulus (same n, two e/c pairs)
    if n and g["e1"] and g["e2"] and g["c1"] and g["c2"]:
        m = C.common_modulus(n, g["e1"], g["c1"], g["e2"], g["c2"])
        if m:
            return show("common-modulus", m)

    if not (n and e and c is not None):
        print("[-] need at least n, e, c for a single-key attack")
        return False

    attacks = [forced] if forced else \
        ["small-n-factor", "fermat", "pollard-pm1", "wiener", "low-exp-root"]

    for a in attacks:
        if a == "small-n-factor" and n.bit_length() > SMALL_N_BITS and not forced:
            continue
        print(f"[*] trying {a} ...")
        if a in ("small-n-factor", "factor"):
            fac = C.factorize(n)
            if len(fac) >= 2 and math.prod(fac) == n and all(C.is_prime(f) for f in fac):
                p = fac[0]; q = n // p
                return finish(a, p, q)
        elif a == "fermat":
            f = C.fermat_factor(n, max_steps=1 << 22)
            if f:
                return finish("fermat (close primes)", *f)
        elif a == "pollard-pm1":
            dd = C.pollard_pm1(n, bound=200_000)
            if dd and 1 < dd < n:
                return finish("pollard p-1 (smooth prime)", dd, n // dd)
        elif a == "wiener":
            res = C.wiener(e, n)
            if res:
                d, p, q = res
                print(f"[*] wiener d = {d}")
                return finish("wiener (small d)", p, q)
        elif a == "low-exp-root":
            m = C.low_exponent_root(c if isinstance(c, int) else C.to_int(c), e, n,
                                    max_k=1 << 16)
            if m:
                return show("low-exponent root", m)
    print("[-] no single-key attack succeeded")
    return False


def solve_multi(keys, cts):
    """keys: list of dicts with n,e. cts: list of ints (parallel or shared)."""
    ns = [C.to_int(k["n"]) for k in keys]
    es = [C.to_int(k["e"]) for k in keys]
    cs = [C.to_int(x) for x in cts]

    # shared prime between any two moduli?
    hits = C.common_factor(ns)
    if hits:
        i, j, p = hits[0]
        print(f"[*] moduli #{i} and #{j} share a prime!")
        q = ns[i] // p
        d = C.rsa_d(es[i], p, q)
        return show("shared-prime (batch gcd)", decrypt_blocks(cs[i], d, ns[i]))

    # Hastad broadcast: same small e, distinct n, >= e ciphertexts
    if len(set(es)) == 1 and len(cs) >= es[0]:
        e = es[0]
        pairs = list(zip(cs, ns))[:e]
        m = C.hastad_broadcast(pairs, e)
        if m:
            return show(f"hastad broadcast (e={e})", m)
    print("[-] no multi-key attack succeeded (try: same e & >=e ciphertexts for broadcast)")
    return False


# ---------- main -------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="RSA challenge auto-solver")
    ap.add_argument("files", nargs="*", help="challenge.json, or keys.txt ciphertexts.txt")
    ap.add_argument("-n", type=str); ap.add_argument("-e", type=str)
    ap.add_argument("-c", type=str); ap.add_argument("-d", type=str)
    ap.add_argument("-p", type=str); ap.add_argument("-q", type=str)
    ap.add_argument("--attack", help="force one: factor/fermat/pollard-pm1/wiener/low-exp-root")
    args = ap.parse_args()

    # direct values on the command line
    if args.n or args.c:
        g = {k: None for k in
             ("n", "e", "d", "p", "q", "c", "e1", "e2", "c1", "c2", "block_size", "original_length")}
        for k in ("n", "e", "c", "d", "p", "q"):
            v = getattr(args, k)
            if v is not None:
                g[k] = C.to_int(v)
        if g["e"] is None:
            g["e"] = 65537
        return 0 if solve_single(g, args.attack) else 1

    if not args.files:
        ap.print_help(); return 2

    # two-file group-chat style
    if len(args.files) == 2:
        a, b = args.files
        ka = load_kv_txt(a); kb = load_kv_txt(b)
        keys = [v for v in ka.values() if isinstance(v, dict) and "n" in v]
        cts = [v for v in kb.values() if isinstance(v, int)]
        if keys and cts:
            return 0 if solve_multi(keys, cts) else 1

    # single JSON
    raw = open(args.files[0]).read()
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        print("[-] not JSON; parsing as key=value text")
        obj = load_kv_txt(args.files[0])

    # list of keys inside the JSON?
    keylist = collect(obj, "keys", "public_keys", "recipients")
    ctlist = collect(obj, "ciphertexts", "cts")
    if keylist and ctlist:
        return 0 if solve_multi(keylist, ctlist) else 1

    return 0 if solve_single(normalize(obj), args.attack) else 1


if __name__ == "__main__":
    sys.exit(main())
