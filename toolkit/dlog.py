#!/usr/bin/env python3
"""
dlog.py -- discrete logarithm: find x with g^x = h (mod p).

Usage:
    ./dlog.py -g 2 -h 22 -p 29
    ./dlog.py -g G -t H -p P            # -t / -h both mean the target h
    ./dlog.py -g G -t H -p P --order N  # restrict to a known subgroup order

Picks Pohlig-Hellman when p-1 is smooth (fast), otherwise baby-step/giant-step.
Only feasible for weak parameters -- that is exactly the point of the exercises
(a strong prime p makes this infeasible, which is why DH/ElGamal are secure).
"""
import sys, os, argparse, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cnscrypto as C


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-g", required=True, type=str, help="base / generator")
    ap.add_argument("-H", "-t", "--target", dest="h", required=True, type=str,
                    help="target value h")
    ap.add_argument("-p", required=True, type=str, help="prime modulus")
    ap.add_argument("--order", type=str, help="group/subgroup order (default p-1)")
    args = ap.parse_args()

    g, h, p = C.to_int(args.g), C.to_int(args.h), C.to_int(args.p)
    order = C.to_int(args.order) if args.order else p - 1
    print(f"[*] solving {g}^x = {h} (mod {p}),  order {order.bit_length()} bits")

    t0 = time.time()
    try:
        facs = C.factorize(order)
        smooth = max(facs) < (1 << 44)
    except ValueError:
        smooth = False
    x = C.pohlig_hellman(g, h, p, order) if smooth else C.bsgs(g, h, p, order)
    dt = time.time() - t0

    if x is None:
        print(f"[-] no solution found ({dt:.2f}s) -- parameters likely too strong")
        return 1
    assert pow(g, x, p) == h % p
    print(f"[+] x = {x}   ({'pohlig-hellman' if smooth else 'bsgs'}, {dt:.2f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
