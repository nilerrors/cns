#!/usr/bin/env python3
"""
factor.py -- factor an integer with the methods that matter for CTF RSA.

Usage:
    ./factor.py 34664911185892166593
    ./factor.py 0x... -e 65537            # also print d = e^-1 mod lcm(p-1,q-1)
    ./factor.py N --fermat                # force Fermat (close primes)
    ./factor.py N --pm1 --bound 1000000   # force Pollard p-1 with a bound

Default order: tiny trial division -> Fermat (cheap, catches close primes)
-> Pollard p-1 (catches smooth p-1) -> Pollard rho (general small factor).
"""
import sys, os, argparse, math, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cnscrypto as C


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("n", type=str)
    ap.add_argument("-e", type=str, help="public exponent; also compute d")
    ap.add_argument("--fermat", action="store_true")
    ap.add_argument("--pm1", action="store_true")
    ap.add_argument("--rho", action="store_true")
    ap.add_argument("--bound", type=int, default=1_000_000)
    args = ap.parse_args()

    n = C.to_int(args.n)
    print(f"[*] n = {n}   ({n.bit_length()} bits)")
    t0 = time.time()

    factors = None
    if args.fermat:
        f = C.fermat_factor(n, max_steps=1 << 26)
        factors = list(f) if f else None
    elif args.pm1:
        d = C.pollard_pm1(n, bound=args.bound)
        factors = [d, n // d] if d else None
    elif args.rho:
        d = C.pollard_rho(n)
        factors = [d, n // d] if d else None
    else:
        factors = C.factorize(n)

    dt = time.time() - t0
    if not factors or math.prod(factors) != n:
        print(f"[-] failed to fully factor (after {dt:.2f}s)")
        print(f"    partial: {factors}")
        return 1

    print(f"[+] factors ({dt:.2f}s):")
    for f in sorted(factors):
        print(f"      {f}   {'prime' if C.is_prime(f) else 'COMPOSITE'}")

    if args.e and len(set(factors)) >= 2:
        e = C.to_int(args.e)
        if len(factors) == 2:
            p, q = factors
            d = C.rsa_d(e, p, q)
            print(f"[+] e = {e}")
            print(f"[+] d = {d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
