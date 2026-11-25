"""
cnscrypto.py  --  Asymmetric-crypto toolkit for the CNS hacking sessions.

Single-file, no dependencies beyond the standard library + (optional) gmpy2
and pycryptodome, both of which are in the lab venv. Everything degrades to
pure Python if those are missing, so this file works anywhere.

Layout (search for the ===== banners):
    1.  Encoding / IO helpers        (bytes <-> int, hex/b64, flag detection)
    2.  Number theory primitives     (egcd, inverse, crt, isqrt/iroot, primes)
    3.  Discrete log                 (bsgs, pohlig-hellman, primitive root)
    4.  Factoring                    (trial, fermat, pollard rho, pollard p-1)
    5.  RSA attacks                  (d from pq, factor from d, wiener, hastad,
                                      common modulus, common factor, low-e root,
                                      LSB/parity oracle, malleability/CCA)
    6.  ElGamal attacks              (decrypt, key reuse, known plaintext, DH)
    7.  DSA / signatures             (sign, verify, nonce reuse, known/linear k)

Design: functions take plain ints and return plain ints (or bytes). No classes
to fight with at 2 a.m. Each attack has a docstring that says WHEN to use it --
those docstrings are the source for cheatsheet.html.
"""

from __future__ import annotations
import sys, math, hashlib, itertools, base64, re

# ---- optional fast backends -------------------------------------------------
try:
    import gmpy2
    _HAVE_GMPY2 = True
except ImportError:                                            # pragma: no cover
    gmpy2 = None
    _HAVE_GMPY2 = False

try:
    from Crypto.Util.number import long_to_bytes as _ltb, bytes_to_long as _btl
    from Crypto.Util.number import isPrime as _isprime_pc, getPrime
    _HAVE_PYCRYPTO = True
except ImportError:                                            # pragma: no cover
    _HAVE_PYCRYPTO = False


# =============================================================================
# 1. ENCODING / IO HELPERS
# =============================================================================

def long_to_bytes(n: int, blocksize: int = 0) -> bytes:
    """Integer -> big-endian bytes (like pycryptodome)."""
    if _HAVE_PYCRYPTO:
        return _ltb(n, blocksize)
    if n == 0:
        b = b"\x00"
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if blocksize > 0 and len(b) % blocksize:
        b = b"\x00" * (blocksize - len(b) % blocksize) + b
    return b


def bytes_to_long(b: bytes) -> int:
    """Big-endian bytes -> integer."""
    if _HAVE_PYCRYPTO:
        return _btl(b)
    return int.from_bytes(b, "big")


def to_int(v) -> int:
    """Accept int / decimal str / 0x-hex str / bytes -> int. Handy for parsing
    challenge files whose numbers arrive in whatever shape the author felt like."""
    if isinstance(v, int):
        return v
    if isinstance(v, (bytes, bytearray)):
        return bytes_to_long(bytes(v))
    s = str(v).strip().replace("_", "").replace(" ", "")
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def from_hex(s: str) -> bytes:
    return bytes.fromhex(s.strip().replace(" ", "").replace("\n", ""))


def parse_blob(s) -> bytes:
    """Best-effort decode of a ciphertext string: try hex, then base64, then
    treat as raw latin-1. Returns bytes."""
    if isinstance(s, (bytes, bytearray)):
        return bytes(s)
    s = s.strip()
    try:
        return from_hex(s)
    except ValueError:
        pass
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return s.encode("latin-1")


FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,15}\{[^}\n]{1,200}\}")


def find_flag(data) -> str | None:
    """Return the first flag-looking token (e.g. cns{...}) in bytes/str, or None."""
    if isinstance(data, str):
        data = data.encode("latin-1", "replace")
    m = FLAG_RE.search(data)
    return m.group(0).decode("latin-1") if m else None


def looks_text(b: bytes, threshold: float = 0.85) -> bool:
    """Heuristic: does this look like printable ASCII text? Good for scoring
    brute-force candidates."""
    if not b:
        return False
    ok = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return ok / len(b) >= threshold


# =============================================================================
# 2. NUMBER THEORY PRIMITIVES
# =============================================================================

def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclid: returns (g, x, y) with a*x + b*y = g = gcd(a, b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def inverse(a: int, n: int) -> int:
    """Modular inverse a^-1 mod n. Raises if gcd(a,n) != 1."""
    return pow(a % n, -1, n)


def crt(residues: list[int], moduli: list[int]) -> tuple[int, int]:
    """Chinese Remainder Theorem for pairwise-coprime moduli.
    Returns (x, M) with x ≡ residues[i] (mod moduli[i]) and M = prod(moduli).
    Use for: RSA Hastad broadcast, Pohlig-Hellman, 'same msg mod many n'."""
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for a, m in zip(residues, moduli):
        Mi = M // m
        x += a * Mi * inverse(Mi, m)
    return x % M, M


def crt_pair(a1: int, m1: int, a2: int, m2: int) -> tuple[int, int]:
    """CRT for two congruences, moduli NOT necessarily coprime (returns combined
    modulus lcm). Returns (x, lcm) or raises ValueError if inconsistent."""
    g, p, _ = egcd(m1, m2)
    if (a2 - a1) % g:
        raise ValueError("no solution (inconsistent congruences)")
    lcm = m1 // g * m2
    x = (a1 + (a2 - a1) // g * p % (m2 // g) * m1) % lcm
    return x, lcm


def isqrt(n: int) -> int:
    """Integer square root (floor)."""
    if _HAVE_GMPY2:
        return int(gmpy2.isqrt(n))
    return math.isqrt(n)


def is_square(n: int) -> bool:
    if n < 0:
        return False
    r = isqrt(n)
    return r * r == n


def iroot(x: int, k: int) -> tuple[int, bool]:
    """Integer k-th root: returns (r, exact) with r = floor(x**(1/k)).
    Use for: low-exponent RSA (recover m when m^e < n), after CRT broadcast."""
    if x < 0:
        raise ValueError("negative radicand")
    if _HAVE_GMPY2:
        r, exact = gmpy2.iroot(gmpy2.mpz(x), k)
        return int(r), bool(exact)
    if x == 0:
        return 0, True
    # Newton's method, pure python
    r = int(round(x ** (1.0 / k))) if x.bit_length() < 1000 else 1 << (x.bit_length() // k + 1)
    while True:
        t = ((k - 1) * r + x // pow(r, k - 1)) // k
        if t >= r:
            break
        r = t
    while pow(r + 1, k) <= x:
        r += 1
    while pow(r, k) > x:
        r -= 1
    return r, pow(r, k) == x


def is_prime(n: int) -> bool:
    """Probabilistic primality (Miller-Rabin via a fast backend when present)."""
    if n < 2:
        return False
    if _HAVE_GMPY2:
        return gmpy2.is_prime(n) > 0
    if _HAVE_PYCRYPTO:
        return bool(_isprime_pc(n))
    return _miller_rabin(n)


def _miller_rabin(n: int, rounds: int = 40) -> bool:
    """Pure-python Miller-Rabin (the algorithm from the Number-Theory homework)."""
    import random
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d, k = n - 1, 0
    while d % 2 == 0:
        d //= 2
        k += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(k - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def factorize(n: int) -> list[int]:
    """Full prime factorization as a sorted list (with multiplicity).
    Combines trial division, Pollard rho and Fermat. For RSA-sized safe semiprimes
    this will NOT terminate -- it is meant for the small / weak moduli that show
    up in exercises (a few tens of bits, or close primes)."""
    if n <= 1:
        return []
    factors: list[int] = []
    stack = [n]
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if is_prime(m):
            factors.append(m)
            continue
        d = _find_factor(m)
        if d is None or d == m:
            factors.append(m)         # give up: record composite as-is
            continue
        stack.append(d)
        stack.append(m // d)
    return sorted(factors)


def _find_factor(n: int) -> int | None:
    if n % 2 == 0:
        return 2
    for p in range(3, 100000, 2):         # small trial division
        if n % p == 0:
            return p
    # Close primes fall to Fermat in very few steps; far-apart primes never do,
    # so a small budget here is strictly better -- let Pollard rho do the rest.
    f = fermat_factor(n, max_steps=1 << 16)
    if f:
        return f[0]
    return pollard_rho(n)


# =============================================================================
# 3. DISCRETE LOG
# =============================================================================

def primitive_root(p: int) -> int:
    """Smallest primitive root of a prime p (generator of Z_p^*)."""
    if p == 2:
        return 1
    phi = p - 1
    factors = set(factorize(phi))
    for g in range(2, p):
        if all(pow(g, phi // q, p) != 1 for q in factors):
            return g
    raise ValueError("no primitive root found")


def order(a: int, p: int, group_order: int | None = None) -> int:
    """Multiplicative order of a mod p."""
    if group_order is None:
        group_order = p - 1
    o = group_order
    for q in set(factorize(group_order)):
        while o % q == 0 and pow(a, o // q, p) == 1:
            o //= q
    return o


def bsgs(g: int, h: int, p: int, n: int | None = None) -> int | None:
    """Baby-step giant-step: solve g^x ≡ h (mod p), 0 <= x < n.
    n defaults to p-1. O(sqrt(n)) time & memory -- fine up to ~n < 2**50.
    Use for: discrete log in a small(ish) group (Diffie-Hellman / ElGamal when
    q is small or has a small factor; combine with Pohlig-Hellman otherwise)."""
    if n is None:
        n = p - 1
    g %= p
    h %= p
    m = isqrt(n) + 1
    table = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = e * g % p
    factor = pow(inverse(g, p), m, p)      # g^(-m)
    gamma = h
    for i in range(m + 1):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * factor % p
    return None


def pohlig_hellman(g: int, h: int, p: int, group_order: int | None = None) -> int | None:
    """Discrete log g^x ≡ h (mod p) when the group order is SMOOTH (only small
    prime factors). Reduces the big DLP to one small DLP per prime-power factor,
    solved with BSGS, then recombined with CRT.
    Use for: 'q-1 has only small factors', unsafe DH/ElGamal parameters."""
    if group_order is None:
        group_order = p - 1
    fac: dict[int, int] = {}
    for q in factorize(group_order):
        fac[q] = fac.get(q, 0) + 1
    residues, moduli = [], []
    for q, e in fac.items():
        qe = q ** e
        gi = pow(g, group_order // qe, p)      # has order q^e
        hi = pow(h, group_order // qe, p)
        gamma = pow(gi, q ** (e - 1), p)       # has order q
        x = 0                                  # x mod q^e, built digit by digit
        for k in range(e):
            base = (hi * inverse(pow(gi, x, p), p)) % p
            rhs = pow(base, q ** (e - 1 - k), p)   # == gamma^(k-th digit)
            d = bsgs(gamma, rhs, p, q)
            if d is None:
                return None
            x += d * (q ** k)
        residues.append(x % qe)
        moduli.append(qe)
    val, _ = crt(residues, moduli)
    return val


def discrete_log(g: int, h: int, p: int, group_order: int | None = None) -> int | None:
    """Try the cheap DLP methods in order. Not magic: fails on strong parameters
    (that's the point -- strong ElGamal/DH is secure)."""
    if group_order is None:
        group_order = p - 1
    # if order is smooth, pohlig-hellman is far faster
    try:
        if max(factorize(group_order)) < (1 << 40):
            return pohlig_hellman(g, h, p, group_order)
    except ValueError:
        pass
    return bsgs(g, h, p, group_order)


# =============================================================================
# 4. FACTORING
# =============================================================================

def trial_division(n: int, bound: int = 1_000_000) -> list[int]:
    """Return small prime factors found below `bound` (with multiplicity) plus
    the leftover cofactor as the last element if > 1."""
    out = []
    d = 2
    while d < bound and d * d <= n:
        while n % d == 0:
            out.append(d)
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        out.append(n)
    return out


def fermat_factor(n: int, max_steps: int = 1 << 24) -> tuple[int, int] | None:
    """Fermat factorization: fast when p and q are CLOSE (|p-q| small), e.g.
    primes generated next to each other. Returns (p, q) or None.
    Recognize: 'primes too close', 'nextprime(p)' style key generation."""
    if n % 2 == 0:
        return (2, n // 2)
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        if b2 >= 0 and is_square(b2):
            b = isqrt(b2)
            p, q = a - b, a + b
            if p > 1 and p * q == n:
                return (p, q)
        a += 1
    return None


def pollard_rho(n: int, max_tries: int = 20) -> int | None:
    """Pollard's rho (Brent variant). Good general small-factor finder; expected
    O(n**1/4). Use for semiprimes up to ~80-100 bits in exercises."""
    if n % 2 == 0:
        return 2
    if is_prime(n):
        return None
    import random
    for _ in range(max_tries):
        c = random.randrange(1, n)
        f = lambda x: (x * x + c) % n
        x = y = random.randrange(2, n)
        d = 1
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d
    return None


def pollard_pm1(n: int, bound: int = 100_000) -> int | None:
    """Pollard's p-1: factors n when some prime p | n has (p-1) B-smooth.
    Recognize: 'weak prime', CTF moduli built from smooth primes.
    Raise `bound` if it fails and you suspect a slightly-larger smooth factor."""
    a = 2
    for p in _primes_up_to(bound):
        pe = p
        while pe * p <= bound:
            pe *= p
        a = pow(a, pe, n)
        d = math.gcd(a - 1, n)
        if 1 < d < n:
            return d
        if d == n:
            return None
    d = math.gcd(a - 1, n)
    return d if 1 < d < n else None


def _primes_up_to(bound: int):
    """Sieve of Eratosthenes generator."""
    sieve = bytearray([1]) * (bound + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, isqrt(bound) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return [i for i in range(2, bound + 1) if sieve[i]]


def common_factor(moduli: list[int]) -> list[tuple[int, int, int]]:
    """Batch GCD: find any two moduli that SHARE a prime factor (fatal RSA key-gen
    bug: a reused prime factors both keys instantly).
    Returns list of (i, j, shared_prime). Recognize: 'many public keys given'."""
    hits = []
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = math.gcd(moduli[i], moduli[j])
            if g != 1:
                hits.append((i, j, g))
    return hits


# =============================================================================
# 5. RSA ATTACKS
# =============================================================================

def rsa_d(e: int, p: int, q: int) -> int:
    """Private exponent from the factorization. d = e^-1 mod lcm(p-1, q-1)
    (lcm, a.k.a. Carmichael lambda, always works; phi=(p-1)(q-1) also works)."""
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    return inverse(e, lam)


def rsa_decrypt(c: int, d: int, n: int) -> int:
    return pow(c, d, n)


def rsa_recover(e: int, p: int, q: int, c: int) -> bytes:
    """Convenience: given factors, decrypt c to bytes."""
    return long_to_bytes(pow(c, rsa_d(e, p, q), p * q))


def factor_from_d(n: int, e: int, d: int) -> tuple[int, int] | None:
    """Given a private exponent d (and e, n), FACTOR n. Standard result: knowing
    d is equivalent to factoring. Use when a challenge leaks d but not p, q, or
    after Wiener recovers d.
    Also doubles as: recover the OTHER prime / full key from a leaked d."""
    k = e * d - 1
    if k % 2:
        return None
    import random
    r, t = k, 0
    while r % 2 == 0:
        r //= 2
        t += 1
    for _ in range(100):
        g = random.randrange(2, n - 1)
        y = pow(g, r, n)
        if y in (1, n - 1):
            continue
        for _ in range(t - 1):
            x = pow(y, 2, n)
            if x == 1:
                p = math.gcd(y - 1, n)
                return (p, n // p) if 1 < p < n else None
            if x == n - 1:
                break
            y = x
        else:
            p = math.gcd(y - 1, n)
            if 1 < p < n:
                return (p, n // p)
    return None


def phi_from_d_bruteforce(*a, **k):   # alias people reach for
    return factor_from_d(*a, **k)


def wiener(e: int, n: int) -> tuple[int, int, int] | None:
    """Wiener's attack: recovers a SMALL private exponent d (d < n^0.25 / 3).
    Recognize: HUGE e (close to n) -> implies small d. Returns (d, p, q).
    Works via continued-fraction convergents of e/n."""
    def cf(num, den):
        while den:
            a = num // den
            yield a
            num, den = den, num - a * den

    def convergents(num, den):
        n0, n1 = 0, 1
        d0, d1 = 1, 0
        for a in cf(num, den):
            n0, n1 = n1, a * n1 + n0
            d0, d1 = d1, a * d1 + d0
            yield n0, d0           # k/d candidate

    for k, d in convergents(e, n):
        if k == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        # solve x^2 - (n-phi+1)x + n = 0  -> roots p, q
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0 or not is_square(disc):
            continue
        s = isqrt(disc)
        p, q = (b + s) // 2, (b - s) // 2
        if p * q == n:
            return d, p, q
    return None


def hastad_broadcast(pairs: list[tuple[int, int]], e: int) -> bytes | None:
    """Hastad broadcast / low-exponent: the SAME message m was sent to >= e
    recipients, each with exponent e and distinct modulus n_i (no padding).
    Since m^e < prod(n_i), CRT gives m^e exactly, then take the e-th root.
    pairs = [(c_i, n_i), ...]. Recognize: 'same message, e=3, 3 people'."""
    cs = [c for c, _ in pairs]
    ns = [n for _, n in pairs]
    x, _ = crt(cs, ns)
    m, exact = iroot(x, e)
    if not exact:
        return None
    return long_to_bytes(m)


def common_modulus(n: int, e1: int, c1: int, e2: int, c2: int) -> bytes | None:
    """Common-modulus attack: the SAME message encrypted under the SAME n with
    two exponents e1, e2 where gcd(e1, e2) = 1.
    m = c1^a * c2^b mod n  with  a*e1 + b*e2 = 1  (negative exp -> inverse).
    Recognize: one n, two public exponents, two ciphertexts."""
    g, a, b = egcd(e1, e2)
    if g != 1:
        return None
    if a < 0:
        c1 = inverse(c1, n)
        a = -a
    if b < 0:
        c2 = inverse(c2, n)
        b = -b
    m = pow(c1, a, n) * pow(c2, b, n) % n
    return long_to_bytes(m)


def low_exponent_root(c: int, e: int, n: int, max_k: int = 1 << 20) -> bytes | None:
    """Single-ciphertext low-exponent: m is small enough that m^e = c + k*n for a
    small k (often k=0, i.e. m^e < n and no modular wrap). Try k = 0,1,2,...
    Recognize: e=3 (or small), short message, one ciphertext, nothing else given."""
    for k in range(max_k):
        m, exact = iroot(c + k * n, e)
        if exact:
            return long_to_bytes(m)
    return None


def rsa_malleability_factor(e: int, n: int, factor: int = 2) -> int:
    """CCA / homomorphic trick helper: returns (factor^e mod n). Submit
    c' = c * (factor^e) to a decryption oracle; the oracle returns factor*m mod n,
    divide by `factor` to get m. (Textbook CCA from the RSA notes.)
    Recognize: a decrypt oracle that refuses the exact target ciphertext."""
    return pow(factor, e, n)


def rsa_unblind(returned: int, factor: int, n: int) -> bytes:
    """Given oracle output for the malleable ciphertext above, recover m."""
    return long_to_bytes(returned * inverse(factor, n) % n)


def lsb_oracle(n: int, e: int, c: int, oracle, verbose: bool = True) -> bytes:
    """LSB / parity oracle attack. `oracle(cipher)->int` must return the least
    significant bit (parity) of the decryption of `cipher`. Each query halves the
    search interval -> recover m in ~log2(n) queries via binary search.
    Recognize: a service that leaks whether a decryption is even/odd.

    (Also the backbone of a Bleichenbacher-style padding oracle, conceptually.)"""
    from fractions import Fraction
    mult = pow(2, e, n)        # multiply plaintext by 2 each round
    cur = c
    low, high = Fraction(0), Fraction(n)
    for i in range(n.bit_length()):
        cur = cur * mult % n
        mid = (low + high) / 2
        if oracle(cur) == 1:   # 2m mod n is odd -> m lies in the upper half
            low = mid
        else:
            high = mid
        if verbose and i % 32 == 0:
            print(f"  lsb-oracle {i}/{n.bit_length()} bits", file=sys.stderr)
    return long_to_bytes(int(high))


# =============================================================================
# 6. ELGAMAL  (and Diffie-Hellman)
# =============================================================================

def elgamal_encrypt(m: int, y: int, p: int, g: int, k: int) -> tuple[int, int]:
    """Textbook ElGamal with explicit nonce k (for testing/building oracles)."""
    c1 = pow(g, k, p)
    c2 = m * pow(y, k, p) % p
    return c1, c2


def elgamal_decrypt(c1: int, c2: int, x: int, p: int) -> int:
    """Decrypt with the private key x: m = c2 * (c1^x)^-1 mod p."""
    s = pow(c1, x, p)
    return c2 * inverse(s, p) % p


def elgamal_decrypt_with_dlog(c1: int, c2: int, y: int, p: int, g: int) -> bytes | None:
    """No private key? Recover x = dlog_g(y) (only feasible for weak params),
    then decrypt. Recognize: small p, or p-1 smooth."""
    x = discrete_log(g, y, p)
    if x is None:
        return None
    return long_to_bytes(elgamal_decrypt(c1, c2, x, p))


def elgamal_key_reuse(c2_known: int, m_known: int, c2_target: int, p: int) -> int:
    """Nonce (k) reuse: if the same k was used for a known message and the target,
    then both share the same mask K = y^k. So:
        K = c2_known * m_known^-1      (mod p)
        m_target = c2_target * K^-1    (mod p)
    Recognize: 'same c1 for two ciphertexts' (equal c1 <=> equal k)."""
    K = c2_known * inverse(m_known, p) % p
    return c2_target * inverse(K, p) % p


def elgamal_scale_mask(c2_known: int, m_known: int, c2_target: int,
                       y: int, p: int, delta: int = 1) -> int:
    """'fresh_every_time' pattern: target nonce = known nonce + delta, i.e.
    c1_target = c1_known * g^delta  =>  K_target = K_known * y^delta.
        K_known  = c2_known * m_known^-1
        K_target = K_known * y^delta
        m_target = c2_target * K_target^-1
    Recognize: the two c1 values differ by a factor g^delta (often delta=1)."""
    K_known = c2_known * inverse(m_known, p) % p
    K_target = K_known * pow(y, delta, p) % p
    return c2_target * inverse(K_target, p) % p


def dh_shared(their_pub: int, my_priv: int, p: int) -> int:
    """Diffie-Hellman shared secret from your private and their public."""
    return pow(their_pub, my_priv, p)


def dh_break(g: int, p: int, A: int, B: int) -> int | None:
    """Break DH by solving one discrete log (feasible only for weak p)."""
    a = discrete_log(g, A, p)
    if a is None:
        return None
    return pow(B, a, p)


# =============================================================================
# 7. DSA / DIGITAL SIGNATURES
# =============================================================================

def dsa_verify(p, q, g, y, H, r, s) -> bool:
    """Standard DSA verification. H is the integer hash of the message (mod q)."""
    if not (0 < r < q and 0 < s < q):
        return False
    w = inverse(s, q)
    u1 = H * w % q
    u2 = r * w % q
    v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
    return v == r


def dsa_sign(p, q, g, x, H, k) -> tuple[int, int]:
    """DSA sign (explicit k) -- for building test vectors / forgeries."""
    r = pow(g, k, p) % q
    s = inverse(k, q) * (H + x * r) % q
    return r, s


def dsa_x_from_nonce_reuse(q, r, s1, H1, s2, H2) -> int:
    """Nonce reuse: two signatures with the SAME r (=> same k) under one key.
        k = (H1 - H2) / (s1 - s2)   (mod q)
        x = (s1*k - H1) / r         (mod q)
    Recognize: two signatures share r. This is the dsa1 exercise."""
    k = (H1 - H2) * inverse((s1 - s2) % q, q) % q
    x = (s1 * k - H1) * inverse(r, q) % q
    return x


def dsa_x_from_known_k(q, r, s, H, k) -> int:
    """Known / predictable / leaked nonce k: x = (s*k - H) / r (mod q).
    Recognize: k is a constant, small, timestamp, or otherwise guessable."""
    return (s * k - H) * inverse(r, q) % q


def dsa_x_from_linear_nonce(q, r1, s1, H1, r2, s2, H2, a: int, b: int) -> int | None:
    """Linearly related nonces k2 = a*k1 + b (e.g. an LCG, or k2=k1+1).
    Solve the two signing equations for x. Recognize: nonces from a weak PRNG."""
    # s1*k1 = H1 + x*r1 ; s2*k2 = H2 + x*r2 ; k2 = a*k1 + b
    # => k1 = (H1 + x*r1)/s1 ; (a*k1 + b)*s2 = H2 + x*r2
    # => a*s2*(H1 + x*r1)/s1 + b*s2 = H2 + x*r2
    try:
        inv_s1 = inverse(s1, q)
        num = (a * s2 * H1 * inv_s1 + b * s2 - H2) % q
        den = (r2 - a * s2 * r1 * inv_s1) % q
        return num * inverse(den, q) % q
    except ValueError:
        return None


# ---- raw RSA signatures -----------------------------------------------------

def rsa_sign_raw(m: int, d: int, n: int) -> int:
    """Textbook RSA signature s = m^d mod n (no padding)."""
    return pow(m, d, n)


def rsa_verify_raw(m: int, s: int, e: int, n: int) -> bool:
    """Textbook RSA verify: s^e mod n == m."""
    return pow(s, e, n) == m % n


def rsa_forge_product(m1: int, s1: int, m2: int, s2: int, n: int) -> tuple[int, int]:
    """Multiplicative existential forgery of textbook RSA signatures: if s1 signs
    m1 and s2 signs m2, then s1*s2 signs m1*m2 (mod n), because
    (m1 m2)^d = m1^d m2^d. Returns (m1*m2 mod n, s1*s2 mod n).
    Recognize: a signing oracle that signs arbitrary messages and a target that
    factors as a product. Defeated by hashing/padding before signing (RSA-PSS)."""
    return (m1 * m2 % n, s1 * s2 % n)


def rsa_forge_e3_cuberoot(m_padded: int) -> int:
    """'Garbage' low-exponent (e=3) signature forgery idea: when a verifier only
    checks the high bytes of a PKCS#1 v1.5 padded hash, a forger can pick an EM
    whose perfect cube matches those leading bytes (Bleichenbacher '06). This
    helper just returns the integer cube root of a chosen EM so you can build the
    signature s = iroot(EM, 3). Full exploit depends on the verifier's laxness --
    see the cheatsheet entry. Returns floor(EM**(1/3))."""
    r, _ = iroot(m_padded, 3)
    return r


# ---- hash helpers used by DSA challenges ------------------------------------

def H_int_mod(msg: bytes, q: int, algo: str = "sha256") -> int:
    """H(m) = int(hash(m)) mod q  -- the most common course convention."""
    return int.from_bytes(hashlib.new(algo, msg).digest(), "big") % q


def H_fips(msg: bytes, q: int, algo: str = "sha256") -> int:
    """FIPS 186: leftmost min(N, outlen) bits of hash(m), where N = bitlen(q)."""
    d = hashlib.new(algo, msg).digest()
    z = int.from_bytes(d, "big")
    N = q.bit_length()
    if len(d) * 8 > N:
        z >>= len(d) * 8 - N
    return z % q


# =============================================================================
# tiny self-test when run directly
# =============================================================================

if __name__ == "__main__":
    print("cnscrypto self-test")
    assert inverse(7, 120) == 103
    assert crt([2, 3, 2], [3, 5, 7]) == (23, 105)
    assert iroot(27, 3) == (3, True)
    assert is_prime(2 ** 61 - 1)
    assert fermat_factor(10403) == (101, 103)  # 101*103, close primes
    assert sorted(factorize(8051)) == [97, 83][::-1] or set(factorize(8051)) == {83, 97}
    assert bsgs(2, 22, 29) is not None and pow(2, bsgs(2, 22, 29), 29) == 22
    # RSA roundtrip
    p, q, e = 61, 53, 17
    n = p * q
    d = rsa_d(e, p, q)
    assert pow(pow(42, e, n), d, n) == 42
    assert factor_from_d(n, e, d) in [(61, 53), (53, 61)]
    print("  all asserts passed  (gmpy2=%s pycrypto=%s)" % (_HAVE_GMPY2, _HAVE_PYCRYPTO))
