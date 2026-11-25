#!/usr/bin/env python3
"""
Generates cheatsheet.html -- a self-contained, offline, searchable recognition
guide for the CNS hacking sessions. Edit the ATTACKS / TRIAGE data below and
re-run:  python3 build_cheatsheet.py

Content lives here as plain Python (no escaping headaches); code snippets are
emitted into <script type="text/plain"> blocks so Python stays verbatim.
"""
import json, html, os

# =============================================================================
# TRIAGE -- the "what am I looking at?" flow, shown at the top, always visible.
# =============================================================================
TRIAGE = [
    ("You get n, e, c (one key)",
     "Factor n if small (factor.py) -> d. Else: e huge? Wiener. e tiny (3)? "
     "low-exponent root or broadcast. primes close? Fermat. nothing else? pollard p-1."),
    ("Same message to several people (many n, same small e)",
     "Hastad broadcast: CRT the ciphertexts, take the e-th root. Need >= e of them."),
    ("One n, two different e (and two c)",
     "Common-modulus attack via extended Euclid."),
    ("Many public keys handed out at once",
     "Batch-GCD the moduli first -- a shared prime factors a key instantly."),
    ("ElGamal and the two ciphertexts share c1",
     "Same nonce k -> same mask. Known plaintext recovers the other message."),
    ("ElGamal c1 values differ by a factor of g (a 'counter')",
     "Related nonce: scale the mask by y^delta."),
    ("Two signatures share r",
     "DSA nonce reuse -> solve two linear equations for the private key x."),
    ("A service signs/decrypts things you send it",
     "Oracle: RSA is malleable ((2^e)*c -> 2m); LSB/parity oracle -> binary search; "
     "signatures multiply (s1*s2 signs m1*m2)."),
    ("A public-key directory lets anyone register a name",
     "No authentication: register your own key, have the victim encrypt to you, decrypt."),
    ("p is small, or p-1 has only small factors",
     "Discrete log is feasible: BSGS, or Pohlig-Hellman when p-1 is smooth -> break DH/ElGamal."),
]

# =============================================================================
# ATTACKS.  cat drives the colour + filter chip. 'recognize' is what you search.
# =============================================================================
ATTACKS = [
# ---------------------------------------------------------------- RSA --------
dict(id="rsa-pq", cat="RSA", title="Decrypt with p, q known",
 recognize="You already have the two primes (or just factored n).",
 math="phi=(p-1)(q-1); d = e^-1 mod phi (lcm(p-1,q-1) also works). m = c^d mod n.",
 cli="solve_rsa.py ch.json          # auto when p,q present",
 refs=[], tags="basic private key decrypt totient phi lambda",
 code='''import cnscrypto as C
d = C.rsa_d(e, p, q)              # = e^-1 mod lcm(p-1,q-1)
m = pow(c, d, n)
print(C.long_to_bytes(m))'''),

dict(id="rsa-hastad", cat="RSA", title="Hastad broadcast / low public exponent",
 recognize="The SAME message was sent to >= e recipients, each with small e (often 3) and a different modulus n_i. No padding.",
 math="m^e < n1*n2*n3, so CRT gives m^e exactly over the product, then take the integer e-th root.",
 cli="solve_rsa.py public_keys.txt ciphertexts.txt",
 refs=["rsa/group_chat", "rsa/better_group_chat"], tags="broadcast crt cube root e=3 same message multiple recipients group chat",
 code='''import cnscrypto as C
# pairs = [(c1,n1),(c2,n2),(c3,n3)] -- need at least e of them
m = C.hastad_broadcast(pairs, e)        # CRT + e-th root
print(C.find_flag(m))
# manual: x,_ = C.crt([c for c,_ in pairs],[n for _,n in pairs]); m,ok = C.iroot(x,e)'''),

dict(id="rsa-commonmod", cat="RSA", title="Common modulus attack",
 recognize="The SAME message under the SAME n but two different exponents e1, e2 (two ciphertexts). gcd(e1,e2)=1.",
 math="a*e1 + b*e2 = 1 (extended Euclid). m = c1^a * c2^b mod n (negative exponent -> modular inverse).",
 cli="solve_rsa.py ch.json          # auto when n,e1,e2,c1,c2 present",
 refs=["rsa/free_keys"], tags="common modulus same n two exponents gcd bezout euclid",
 code='''import cnscrypto as C
m = C.common_modulus(n, e1, c1, e2, c2)
print(C.find_flag(m))
# manual: g,a,b = C.egcd(e1,e2); flip c to its inverse where exponent is negative'''),

dict(id="rsa-batchgcd", cat="RSA", title="Shared prime / batch GCD",
 recognize="Several RSA public keys handed out together. A weak generator reused a prime between two of them.",
 math="gcd(n_i, n_j) = p (a nontrivial common factor). Then q=n_i/p and you have the key.",
 cli="solve_rsa.py public_keys.txt ciphertexts.txt   # tries gcd first",
 refs=[], tags="shared prime common factor batch gcd weak rng reused prime many keys",
 code='''import cnscrypto as C, math
hits = C.common_factor([n1, n2, n3, ...])   # [(i,j,shared_prime), ...]
i, j, p = hits[0]
q = n1 // p; d = C.rsa_d(e, p, q)'''),

dict(id="rsa-wiener", cat="RSA", title="Wiener's attack (small private d)",
 recognize="e is HUGE (close to n). A huge e implies a small d (d < n^0.25 / 3).",
 math="Convergents k/d of the continued fraction of e/n reveal d; then solve x^2-(n-phi+1)x+n=0 for p,q.",
 cli="solve_rsa.py ch.json --attack wiener",
 refs=["rsa/sports_car_desire"], tags="wiener small d large e continued fraction convergents low private exponent",
 code='''import cnscrypto as C
d, p, q = C.wiener(e, n)
print(C.long_to_bytes(pow(c, d, n)))'''),

dict(id="rsa-factor-small", cat="RSA", title="Factor a small / weak modulus",
 recognize="n is small (tens of bits), or you suspect weak primes. Decrypt is one factorization away.",
 math="Pollard rho ~ O(n^1/4) finds a factor; then d = e^-1 mod lcm(p-1,q-1).",
 cli="factor.py N -e 65537    |    solve_rsa.py ch.json",
 refs=["rsa/sifting_sand"], tags="factor small n pollard rho weak modulus block decrypt",
 code='''import cnscrypto as C
p = C.pollard_rho(n); q = n // p
d = C.rsa_d(e, p, q)
# block-encoded? decrypt each block to block_size bytes, trim to original_length'''),

dict(id="rsa-fermat", cat="RSA", title="Fermat factorization (close primes)",
 recognize="p and q are close together (e.g. generated with nextprime(p)). |p-q| small.",
 math="n = a^2 - b^2 = (a-b)(a+b). Start a=ceil(sqrt(n)), increment until a^2-n is a perfect square.",
 cli="factor.py N --fermat",
 refs=[], tags="fermat close primes near square difference of squares nextprime",
 code='''import cnscrypto as C
p, q = C.fermat_factor(n)
d = C.rsa_d(e, p, q)'''),

dict(id="rsa-pm1", cat="RSA", title="Pollard p-1 (smooth prime)",
 recognize="One prime p has (p-1) built only from small factors (a 'smooth' prime). Common weak-key trick.",
 math="a = 2^(B!) mod n; gcd(a-1, n) reveals p when (p-1) is B-smooth.",
 cli="factor.py N --pm1 --bound 1000000",
 refs=[], tags="pollard p-1 smooth prime weak key b-smooth",
 code='''import cnscrypto as C
p = C.pollard_pm1(n, bound=1_000_000); q = n // p'''),

dict(id="rsa-lowroot", cat="RSA", title="Low-exponent root (one ciphertext)",
 recognize="Small e (3), a single short message, nothing else. m^e didn't wrap much mod n.",
 math="m^e = c + k*n for a small k (often k=0). Try k=0,1,2,... and take the exact e-th root.",
 cli="solve_rsa.py -n N -e 3 -c C --attack low-exp-root",
 refs=[], tags="low exponent cube root short message no padding single ciphertext",
 code='''import cnscrypto as C
m = C.low_exponent_root(c, e, n, max_k=1<<16)
print(C.find_flag(m))'''),

dict(id="rsa-dleak", cat="RSA", title="Factor n from a leaked d",
 recognize="The challenge leaks d (or Wiener gave you d) but not p, q. Knowing d == being able to factor.",
 math="k=ed-1=2^t*r. For random g: repeatedly square g^r; a nontrivial sqrt of 1 gives gcd(y-1,n)=p.",
 cli="(library call)",
 refs=[], tags="factor from d leaked private exponent equivalent to factoring",
 code='''import cnscrypto as C
p, q = C.factor_from_d(n, e, d)'''),

dict(id="rsa-cca", cat="RSA", title="Malleability / chosen-ciphertext (oracle)",
 recognize="A service decrypts ciphertexts for you but refuses the exact target c. Textbook RSA is malleable.",
 math="Send c' = c*(2^e) mod n. Oracle returns 2m mod n. Divide by 2. (E(m1)E(m2)=E(m1 m2).)",
 cli="(interactive)",
 refs=[], tags="chosen ciphertext cca malleable homomorphic oracle blinding 2^e",
 code='''import cnscrypto as C
blind = C.rsa_malleability_factor(e, n, factor=2)  # = 2^e mod n
y = oracle(c * blind % n)                           # oracle returns (2m) mod n
m = C.rsa_unblind(y, 2, n)'''),

dict(id="rsa-lsb", cat="RSA", title="LSB / parity oracle",
 recognize="A service leaks ONE bit per query: whether the decryption is even or odd.",
 math="Each doubling (c*2^e) and parity check halves the interval for m. ~log2(n) queries.",
 cli="(interactive)",
 refs=[], tags="lsb parity oracle binary search one bit leak even odd",
 code='''import cnscrypto as C
# oracle(cipher) must return the least-significant bit of its decryption
m = C.lsb_oracle(n, e, c, oracle)
print(C.find_flag(m))'''),

dict(id="rsa-sigforge", cat="RSA", title="Signature forgery (textbook RSA)",
 recognize="A signing oracle signs arbitrary messages with raw RSA (no hash/pad), and the target is a product.",
 math="s1 signs m1, s2 signs m2  =>  s1*s2 signs (m1*m2) mod n. Defeated by RSA-PSS (hash+pad).",
 cli="(library call)",
 refs=[], tags="signature forgery existential multiplicative raw rsa pss blind",
 code='''import cnscrypto as C
m_forged, s_forged = C.rsa_forge_product(m1, s1, m2, s2, n)
assert C.rsa_verify_raw(m_forged, s_forged, e, n)'''),

# ---------------------------------------------------------------- ElGamal ----
dict(id="eg-dec", cat="ElGamal", title="Decrypt with the private key x",
 recognize="You have x (given, or recovered via discrete log on a weak p).",
 math="shared s = c1^x mod p; m = c2 * s^-1 mod p.",
 cli="solve_elgamal.py ch.json --x X",
 refs=[], tags="elgamal decrypt private key basic",
 code='''import cnscrypto as C
m = C.elgamal_decrypt(c1, c2, x, p)
print(C.long_to_bytes(m))'''),

dict(id="eg-reuse", cat="ElGamal", title="Nonce reuse (equal c1) + known plaintext",
 recognize="Two ElGamal ciphertexts share the SAME c1 => same nonce k => same mask K=y^k. One plaintext is known.",
 math="K = c2_known * m_known^-1 mod p; then m_target = c2_target * K^-1 mod p.",
 cli="solve_elgamal.py ch.json",
 refs=["elgamal/asymmetric_nonsense"], tags="elgamal nonce reuse same k mask known plaintext equal c1",
 code='''import cnscrypto as C
m_known = C.bytes_to_long(b"This message is public")
m = C.elgamal_key_reuse(c2_known, m_known, c2_flag, p)'''),

dict(id="eg-scale", cat="ElGamal", title="Related nonce (counter, c1'=c1*g^d)",
 recognize="The two c1 values differ by a factor of g^delta (a counter 'nonce' instead of a random one).",
 math="K_target = K_known * y^delta. Recover K_known from the known plaintext, scale, divide.",
 cli="solve_elgamal.py ch.json          # finds delta automatically",
 refs=["elgamal/fresh_every_time"], tags="elgamal related nonce counter linear increment g^delta mask scale",
 code='''import cnscrypto as C
m = C.elgamal_scale_mask(c2_known, m_known, c2_flag, y, p, delta=1)'''),

dict(id="eg-dlog", cat="ElGamal", title="Recover x by discrete log (weak p)",
 recognize="No private key, but p is small or p-1 is smooth, so dlog_g(y) is feasible.",
 math="x = dlog_g(y) mod p (BSGS / Pohlig-Hellman), then decrypt normally.",
 cli="dlog.py -g G -t Y -p P    then    solve_elgamal.py ch.json --x X",
 refs=[], tags="elgamal discrete log recover private key weak prime smooth",
 code='''import cnscrypto as C
x = C.discrete_log(g, y, p)
m = C.elgamal_decrypt(c1, c2, x, p)'''),

# ---------------------------------------------------------------- DSA --------
dict(id="dsa-reuse", cat="DSA", title="Nonce reuse (two signatures share r)",
 recognize="Two signatures under one key have the SAME r. Same r means the same secret nonce k.",
 math="k=(H1-H2)/(s1-s2) mod q; x=(s1*k-H1)/r mod q. Verify g^x=y.",
 cli="solve_dsa.py dsa_challenge.json",
 refs=["digital_signatures/dsa1"], tags="dsa nonce reuse same r recover private key signing double spend",
 code='''import cnscrypto as C
H = lambda m: C.H_int_mod(m, q)         # H(m)=int(sha256(m)) mod q
x = C.dsa_x_from_nonce_reuse(q, r, s1, H(m1), s2, H(m2))
assert pow(g, x, p) == y'''),

dict(id="dsa-knownk", cat="DSA", title="Known / predictable nonce k",
 recognize="k is a constant, small, a timestamp, or otherwise guessable/leaked.",
 math="x = (s*k - H(m)) / r mod q.",
 cli="solve_dsa.py ch.json --k K",
 refs=[], tags="dsa known nonce constant small timestamp predictable recover x",
 code='''import cnscrypto as C
x = C.dsa_x_from_known_k(q, r, s, C.H_int_mod(m, q), k)'''),

dict(id="dsa-linear", cat="DSA", title="Linear / LCG nonce (k2=a*k1+b)",
 recognize="Nonces come from a weak PRNG with a known relation between consecutive k's.",
 math="Two signing equations + k2=a*k1+b -> one linear equation in x. Solve mod q.",
 cli="solve_dsa.py ch.json --a A --b B",
 refs=[], tags="dsa linear nonce lcg prng related k recover x",
 code='''import cnscrypto as C
x = C.dsa_x_from_linear_nonce(q, r1,s1,H1, r2,s2,H2, a, b)'''),

dict(id="dsa-hash", cat="DSA", title="Figure out the hash convention",
 recognize="Signatures won't verify -- you guessed the wrong H(m) (algorithm or int-vs-truncation).",
 math="Try int(hash) mod q, FIPS leftmost-bits truncation, different hash algos; keep the one that verifies.",
 cli="solve_dsa.py ch.json          # auto-detects",
 refs=[], tags="dsa hash convention sha256 fips truncation verify which hash",
 code='''import cnscrypto as C
for H in (lambda m: C.H_int_mod(m,q), lambda m: C.H_fips(m,q)):
    if C.dsa_verify(p,q,g,y, H(msg), r, s): break'''),

# ---------------------------------------------------------------- DH ---------
dict(id="dh-break", cat="Diffie-Hellman", title="Break DH via discrete log",
 recognize="You see g, p, A=g^a, B=g^b and p is weak (small or smooth p-1).",
 math="Recover a=dlog_g(A); shared secret = B^a mod p.",
 cli="dlog.py -g G -t A -p P",
 refs=[], tags="diffie hellman discrete log shared secret weak prime break",
 code='''import cnscrypto as C
secret = C.dh_break(g, p, A, B)'''),

dict(id="dh-mitm", cat="Diffie-Hellman", title="Man-in-the-middle (no authentication)",
 recognize="DH key exchange with NO signatures/certificates. You sit between Alice and Bob.",
 math="Swap each public value for your own: share K1 with Bob, K2 with Alice, relay/alter traffic.",
 cli="(interactive / protocol)",
 refs=[], tags="diffie hellman mitm man in the middle unauthenticated swap public key",
 code='''# For each side, send YOUR public value, keep two shared keys:
#   with Alice: K2 = (YA)^xd2 ;  with Bob: K1 = (YB)^xd1
# decrypt from one, re-encrypt to the other. Fix: authenticate with signatures/certs.'''),

# ---------------------------------------------------------------- Dlog -------
dict(id="dl-bsgs", cat="Discrete Log", title="Baby-step giant-step",
 recognize="You need a discrete log in a group small enough for ~sqrt(n) work (n up to ~2^50).",
 math="Write x=i*m+j, m=ceil(sqrt(n)). Table of g^j; match h*(g^-m)^i.",
 cli="dlog.py -g G -t H -p P",
 refs=[], tags="bsgs baby step giant step discrete log meet in the middle",
 code='''import cnscrypto as C
x = C.bsgs(g, h, p)          # optional 4th arg = subgroup order'''),

dict(id="dl-ph", cat="Discrete Log", title="Pohlig-Hellman (smooth order)",
 recognize="The group order (usually p-1) factors into only SMALL primes.",
 math="Solve the dlog modulo each prime-power factor (small BSGS each), recombine with CRT.",
 cli="dlog.py -g G -t H -p P          # auto when p-1 is smooth",
 refs=[], tags="pohlig hellman smooth order crt discrete log small factors subgroup",
 code='''import cnscrypto as C
x = C.pohlig_hellman(g, h, p)        # group_order defaults to p-1'''),

# ---------------------------------------------------------------- Key dist ---
dict(id="kd-directory", cat="Key Distribution", title="Unauthenticated public-key directory",
 recognize="A key directory / server lets ANYONE register a public key under ANY name, and the victim encrypts to a name.",
 math="Register (name, y=g^x) with YOUR x. Ask the victim to send to that name. Decrypt with x.",
 cli="python key_distribution/solve.py URL myname",
 refs=["key_distribution"], tags="public directory no authentication register key impersonate elgamal rsa send to",
 code='''# 1) GET /params -> p,g      2) POST /directory {name, y=g^x}  (x is yours)
# 3) GET /send?to=name -> (c1,c2)
import cnscrypto as C
m = C.elgamal_decrypt(c1, c2, x, p)     # your own key -> you can read it'''),

dict(id="kd-mitm-pub", cat="Key Distribution", title="Forged public announcement / MITM",
 recognize="Public keys are shared by plain announcement or an unauthenticated channel.",
 math="Substitute your public key for the victim's; messages 'to them' come to you. Fix: certificates (X.509) signed by a CA.",
 cli="(protocol)",
 refs=[], tags="public announcement forge mitm certificate authority x509 trust",
 code='''# No code -- protocol attack. Anyone can forge an announcement and spread
# their own key. Certificates bind name<->key with a CA signature:
#   cert = Sign(PR_CA, [name || PU_name || validity]); verify with PU_CA.'''),

dict(id="kd-replay", cat="Key Distribution", title="KDC / session-key replay",
 recognize="A key-distribution protocol reuses a session key or lacks fresh nonces/timestamps.",
 math="Replay an old step-3 message so the victim re-uses a compromised old session key.",
 cli="(protocol)",
 refs=[], tags="kdc replay nonce timestamp session key freshness needham schroeder kerberos",
 code='''# Defence = freshness: nonces (N1,N2) and timestamps (Tb) in every exchange,
# so an old recorded message is rejected. Kerberos uses timestamps + short-lived
# tickets + a one-time authenticator for exactly this.'''),

# ---------------------------------------------------------------- Numth ------
dict(id="nt-inv", cat="Number Theory", title="Modular inverse (extended Euclid)",
 recognize="You need a^-1 mod n (to divide mod n, build d, undo a multiply).",
 math="EEA gives x,y with a*x+n*y=gcd. If gcd=1, x mod n is the inverse.",
 cli="(library call)",
 refs=[], tags="modular inverse extended euclid eea divide mod reciprocal",
 code='''import cnscrypto as C
C.inverse(a, n)         # or just: pow(a, -1, n)  in Python 3.8+'''),

dict(id="nt-crt", cat="Number Theory", title="Chinese Remainder Theorem",
 recognize="You know x mod m1, x mod m2, ... and want x (RSA broadcast, Pohlig-Hellman, CRT speedup).",
 math="x = sum(a_i * M_i * (M_i^-1 mod m_i)) mod M, M=prod(m_i), M_i=M/m_i.",
 cli="(library call)",
 refs=[], tags="crt chinese remainder theorem reconstruct combine congruence",
 code='''import cnscrypto as C
x, M = C.crt([a1, a2, a3], [m1, m2, m3])       # pairwise-coprime moduli
# non-coprime pair: C.crt_pair(a1, m1, a2, m2)'''),

dict(id="nt-iroot", cat="Number Theory", title="Exact integer e-th root",
 recognize="You have m^e as an exact integer (after CRT, or small m) and want m.",
 math="Integer root with an exactness flag -- don't trust floats for big ints.",
 cli="(library call)",
 refs=[], tags="integer root cube root nth root iroot exact gmpy2",
 code='''import cnscrypto as C
m, exact = C.iroot(x, e)
assert exact'''),

dict(id="nt-primroot", cat="Number Theory", title="Primitive root of a prime",
 recognize="You need a generator g of Z_p^* (to build/verify ElGamal or DH parameters).",
 math="g is primitive iff g^((p-1)/q) != 1 for every prime q | (p-1).",
 cli="(library call)",
 refs=[], tags="primitive root generator order discrete log parameter",
 code='''import cnscrypto as C
g = C.primitive_root(p)
C.order(a, p)           # multiplicative order of a mod p'''),

dict(id="nt-prime", cat="Number Theory", title="Primality test (Miller-Rabin)",
 recognize="You need to check a big number is prime (after factoring, or validating params).",
 math="Probabilistic: writes n-1=2^k*q and checks a^q, a^(2^j q) for random a.",
 cli="(library call)",
 refs=[], tags="miller rabin primality test probable prime isprime",
 code='''import cnscrypto as C
C.is_prime(n)
C.factorize(n)          # full factorization (small / weak n only)'''),

# ---------------------------------------------------------------- Encoding ---
dict(id="enc-int", cat="Encoding", title="Integer <-> bytes <-> text",
 recognize="Plaintext came out as a giant integer, or you need to turn text into m.",
 math="Big-endian. long_to_bytes(m) / bytes_to_long(b).",
 cli="(library call)",
 refs=[], tags="encoding long to bytes bytes to long integer text ascii decode",
 code='''import cnscrypto as C
C.long_to_bytes(m).decode()      # int -> text
C.bytes_to_long(b"cns{...}")     # text -> int'''),

dict(id="enc-parse", cat="Encoding", title="Decode a ciphertext blob",
 recognize="The ciphertext is a hex string, base64, or a list of block integers and you're not sure which.",
 math="Try hex, then base64, then raw. For block lists: decrypt each, trim to original_length.",
 cli="(library call)",
 refs=[], tags="hex base64 decode blob parse blocks ciphertext format",
 code='''import cnscrypto as C
raw = C.parse_blob(s)            # hex -> b64 -> raw, best effort
flag = C.find_flag(raw)          # regex for cns{...} etc.'''),
]

# =============================================================================
# HTML emit
# =============================================================================
CATS = ["RSA", "ElGamal", "DSA", "Diffie-Hellman", "Discrete Log",
        "Key Distribution", "Number Theory", "Encoding"]

HEAD = """<meta charset="utf-8">
<meta name="claude:viewport-fit-sides" content="cover">
<title>Crypto Attack Finder</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;700&display=swap">
<style>
/* Layout: sticky command bar (search + category chips) over a responsive card grid, grouped by category. */
:root{
  --bg:#f4f5f7; --panel:#ffffff; --panel2:#eef0f3; --fg:#1b1f24; --muted:#5c6773;
  --line:#d8dde3; --accent:#0a7d6b; --accent2:#0b6fb8; --flag:#0a7d6b;
  --warn:#9a6b00; --code-bg:#f3f4f6; --chip:#e7eaee;
  --rsa:#b0472b; --elgamal:#8d5bb0; --dsa:#0b6fb8; --dh:#2f8f4e;
  --dl:#6b7280; --kd:#b08400; --nt:#0a7d6b; --enc:#5c6773;
  --radius:12px; --mono:"JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0e1116; --panel:#171b21; --panel2:#1d222a; --fg:#e4e8ee; --muted:#9aa4b2;
  --line:#2a313b; --accent:#2dd4bf; --accent2:#4aa8ff; --flag:#5ef1b0;
  --warn:#e6b450; --code-bg:#11151b; --chip:#232a33;
  --rsa:#ff7a5c; --elgamal:#c89cff; --dsa:#6fb8ff; --dh:#6fd48a;
  --dl:#9aa4b2; --kd:#e6b450; --nt:#2dd4bf; --enc:#9aa4b2; color-scheme:dark;
}}
:root[data-theme="dark"]{
  --bg:#0e1116; --panel:#171b21; --panel2:#1d222a; --fg:#e4e8ee; --muted:#9aa4b2;
  --line:#2a313b; --accent:#2dd4bf; --accent2:#4aa8ff; --flag:#5ef1b0;
  --warn:#e6b450; --code-bg:#11151b; --chip:#232a33;
  --rsa:#ff7a5c; --elgamal:#c89cff; --dsa:#6fb8ff; --dh:#6fd48a;
  --dl:#9aa4b2; --kd:#e6b450; --nt:#2dd4bf; --enc:#9aa4b2; color-scheme:dark;
}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:Inter,system-ui,sans-serif;line-height:1.5}
.wrap{max-width:1180px;margin:0 auto;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px));padding-block:0}
a{color:var(--accent2)}
code,kbd{font-family:var(--mono)}

header.bar{position:sticky;top:env(safe-area-inset-top,0px);z-index:20;background:var(--panel);border-bottom:1px solid var(--line)}
body::before{content:"";position:fixed;inset:0 0 auto;height:env(safe-area-inset-top,0px);background:var(--panel);z-index:21}
.bar .wrap{padding-block:12px;display:flex;flex-direction:column;gap:10px}
.titlerow{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
h1{font-family:"Space Grotesk",sans-serif;font-size:1.15rem;font-weight:700;margin:0;letter-spacing:-.01em}
h1 .mono{font-family:var(--mono);color:var(--accent)}
.sub{color:var(--muted);font-size:.82rem}
.count{margin-left:auto;color:var(--muted);font-size:.78rem;font-family:var(--mono)}
.searchrow{display:flex;gap:8px;align-items:center}
#q{flex:1;min-width:0;background:var(--panel2);border:1px solid var(--line);color:var(--fg);
   border-radius:10px;padding:10px 12px;font-size:.95rem;font-family:var(--mono)}
#q:focus{outline:2px solid var(--accent);outline-offset:0}
.tbtn{background:var(--chip);border:1px solid var(--line);color:var(--fg);border-radius:10px;
   padding:9px 12px;cursor:pointer;font-size:.8rem;white-space:nowrap}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{background:var(--chip);border:1px solid var(--line);color:var(--muted);border-radius:999px;
   padding:4px 11px;font-size:.76rem;cursor:pointer;font-weight:500;user-select:none}
.chip[aria-pressed="true"]{color:var(--bg);background:var(--fg);border-color:var(--fg)}

.triage{margin:16px 0;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);overflow:hidden}
.triage summary{cursor:pointer;padding:12px 16px;font-family:"Space Grotesk",sans-serif;font-weight:600;
   list-style:none;display:flex;align-items:center;gap:8px}
.triage summary::-webkit-details-marker{display:none}
.triage summary::before{content:"▸";color:var(--accent);transition:transform .15s}
.triage[open] summary::before{transform:rotate(90deg)}
.triage .inner{padding:0 16px 8px}
.tri{padding:10px 0;border-top:1px solid var(--line);display:grid;grid-template-columns:minmax(0,0.9fr) minmax(0,1.3fr);gap:14px}
.tri .if{font-family:var(--mono);font-size:.84rem;color:var(--fg);font-weight:500}
.tri .then{color:var(--muted);font-size:.86rem}

main .wrap{padding-bottom:60px}
.cat{font-family:"Space Grotesk",sans-serif;font-weight:700;font-size:.82rem;letter-spacing:.08em;
   text-transform:uppercase;margin:26px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--catc);color:var(--catc)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px;align-items:start}
.card{border:1px solid var(--line);border-left:3px solid var(--catc);border-radius:var(--radius);
   background:var(--panel);padding:14px 15px;display:flex;flex-direction:column;gap:9px;min-width:0}
.card h3{font-family:"Space Grotesk",sans-serif;font-size:1rem;font-weight:600;margin:0}
.rec{font-family:var(--mono);font-size:.82rem;background:var(--panel2);border:1px solid var(--line);
   border-radius:8px;padding:8px 10px;color:var(--fg)}
.rec b{color:var(--warn);font-weight:700;font-family:Inter,sans-serif;font-size:.68rem;letter-spacing:.08em;
   text-transform:uppercase;display:block;margin-bottom:3px}
.math{font-family:var(--mono);font-size:.78rem;color:var(--muted);white-space:pre-wrap;word-break:break-word}
.codewrap{position:relative;min-width:0}
pre{margin:0;background:var(--code-bg);border:1px solid var(--line);border-radius:8px;padding:10px 11px;
   overflow-x:auto;font-family:var(--mono);font-size:.78rem;line-height:1.45}
pre code{color:var(--fg)}
.copy{position:absolute;top:6px;right:6px;background:var(--chip);border:1px solid var(--line);color:var(--muted);
   border-radius:6px;padding:3px 8px;font-size:.68rem;cursor:pointer;font-family:var(--mono)}
.copy:hover{color:var(--fg)}
.meta{display:flex;flex-wrap:wrap;gap:6px;align-items:center;font-size:.72rem}
.cli{font-family:var(--mono);font-size:.74rem;color:var(--accent);background:var(--code-bg);
   border:1px solid var(--line);border-radius:6px;padding:4px 8px;overflow-x:auto;max-width:100%}
.ref{font-family:var(--mono);font-size:.7rem;color:var(--muted);background:var(--chip);border-radius:6px;padding:3px 7px}
.ref b{color:var(--dh)}
.empty{color:var(--muted);text-align:center;padding:50px 0;font-family:var(--mono)}
.foot{color:var(--muted);font-size:.74rem;margin-top:30px;border-top:1px solid var(--line);padding-top:14px}
@media (max-width:560px){.tri{grid-template-columns:1fr;gap:4px}.count{display:none}}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>"""


def esc(s):
    return html.escape(str(s), quote=True)


def build():
    parts = [HEAD]
    # ---- header / command bar ----
    parts.append('<header class="bar"><div class="wrap">')
    parts.append('<div class="titlerow"><h1>Crypto Attack Finder <span class="mono">cns{}</span></h1>'
                 '<span class="sub">type a symptom &mdash; hit <kbd>/</kbd> to search</span>'
                 '<span class="count" id="count"></span></div>')
    parts.append('<div class="searchrow">'
                 '<input id="q" type="search" placeholder="e.g. same r, small d, shared c1, close primes, broadcast, directory..." '
                 'autocomplete="off" spellcheck="false" aria-label="search attacks">'
                 '<button class="tbtn" id="theme" title="toggle theme">theme</button></div>')
    chips = ['<button class="chip" data-cat="all" aria-pressed="true">all</button>']
    for c in CATS:
        chips.append(f'<button class="chip" data-cat="{esc(c)}" aria-pressed="false">{esc(c)}</button>')
    parts.append('<div class="chips">' + "".join(chips) + '</div>')
    parts.append('</div></header>')

    # ---- triage ----
    parts.append('<main><div class="wrap">')
    parts.append('<details class="triage" open><summary>Triage &mdash; what am I looking at?</summary><div class="inner">')
    for cond, action in TRIAGE:
        parts.append(f'<div class="tri"><div class="if">{esc(cond)}</div><div class="then">{esc(action)}</div></div>')
    parts.append('</div></details>')

    # ---- raw code blocks (verbatim, no escaping of python) ----
    for a in ATTACKS:
        parts.append(f'<script type="text/plain" id="code-{esc(a["id"])}">{html.escape(a["code"])}</script>')

    # ---- cards container (rendered by JS so search/filter is live) ----
    parts.append('<div id="cards"></div>')
    parts.append('<div class="empty" id="empty" hidden>no match &mdash; try fewer / different words</div>')
    parts.append('<div class="foot">Prepared toolkit for the CNS hacking sessions. '
                 'Every snippet assumes <code>import cnscrypto as C</code>. '
                 'Allowed in the session: your own notes and code. Not allowed: LLMs. '
                 'Flags look like <code>cns{...}</code>.</div>')
    parts.append('</div></main>')

    # ---- data + script ----
    meta = [dict(id=a["id"], cat=a["cat"], title=a["title"], recognize=a["recognize"],
                 math=a["math"], cli=a["cli"], refs=a["refs"], tags=a["tags"]) for a in ATTACKS]
    data_json = json.dumps(meta, ensure_ascii=False)
    cats_json = json.dumps(CATS)
    key = {"RSA": "rsa", "ElGamal": "elgamal", "DSA": "dsa", "Diffie-Hellman": "dh",
           "Discrete Log": "dl", "Key Distribution": "kd", "Number Theory": "nt", "Encoding": "enc"}
    key_json = json.dumps(key)

    script = """
<script>
const META = __DATA__, CATS = __CATS__, CATKEY = __KEY__;
const cards = document.getElementById('cards'), empty = document.getElementById('empty'),
      countEl = document.getElementById('count'), q = document.getElementById('q');
let activeCat = 'all', term = '';

function code(id){ const e=document.getElementById('code-'+id); return e?e.textContent:''; }
function hay(a){ return (a.title+' '+a.recognize+' '+a.math+' '+a.tags+' '+a.cat+' '+a.refs.join(' ')+' '+code(a.id)).toLowerCase(); }

function cardHTML(a){
  const refs = a.refs.map(r=>`<span class="ref">solved: <b>${r}</b></span>`).join('');
  const cli = a.cli && a.cli!=='(library call)' ? `<div class="cli">$ ${escapeHtml(a.cli)}</div>` : '';
  return `<div class="card" style="--catc:var(--${CATKEY[a.cat]})">
    <h3>${escapeHtml(a.title)}</h3>
    <div class="rec"><b>recognize when</b>${escapeHtml(a.recognize)}</div>
    <div class="math">${escapeHtml(a.math)}</div>
    <div class="codewrap"><button class="copy" data-id="${a.id}">copy</button><pre><code>${escapeHtml(code(a.id))}</code></pre></div>
    ${cli}
    <div class="meta">${refs}</div>
  </div>`;
}
function escapeHtml(s){return s.replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}

function render(){
  const words = term.split(/\\s+/).filter(Boolean);
  const match = a => (activeCat==='all'||a.cat===activeCat) && words.every(w=>hay(a).includes(w));
  const shown = META.filter(match);
  let html='';
  for(const cat of CATS){
    const items = shown.filter(a=>a.cat===cat);
    if(!items.length) continue;
    html += `<div class="cat" style="--catc:var(--${CATKEY[cat]})">${cat}</div><div class="grid">`;
    html += items.map(cardHTML).join('');
    html += `</div>`;
  }
  cards.innerHTML = html;
  empty.hidden = shown.length>0;
  countEl.textContent = shown.length+' / '+META.length;
}

q.addEventListener('input', ()=>{ term=q.value.trim().toLowerCase(); render(); });
document.querySelectorAll('.chip').forEach(ch=>ch.addEventListener('click',()=>{
  activeCat = ch.dataset.cat;
  document.querySelectorAll('.chip').forEach(c=>c.setAttribute('aria-pressed', c===ch));
  render();
}));
cards.addEventListener('click', async e=>{
  const b = e.target.closest('.copy'); if(!b) return;
  const txt = code(b.dataset.id);
  try{ await navigator.clipboard.writeText(txt); b.textContent='copied'; }
  catch{ const r=document.createRange(); r.selectNodeContents(b.closest('.codewrap').querySelector('code'));
         const s=getSelection(); s.removeAllRanges(); s.addRange(r); b.textContent='selected'; }
  setTimeout(()=>b.textContent='copy',1200);
});
document.addEventListener('keydown', e=>{
  if(e.key==='/' && document.activeElement!==q){ e.preventDefault(); q.focus(); }
  if(e.key==='Escape'){ q.value=''; term=''; render(); q.blur(); }
});
// theme toggle (system -> light -> dark), stored per-browser
const tb = document.getElementById('theme');
function applyTheme(t){ if(t==='system') document.documentElement.removeAttribute('data-theme');
                        else document.documentElement.setAttribute('data-theme',t); }
let theme='system'; try{ theme=localStorage.getItem('caf-theme')||'system'; }catch{}
applyTheme(theme);
tb.addEventListener('click',()=>{ theme = theme==='system'?'light':theme==='light'?'dark':'system';
  applyTheme(theme); tb.textContent='theme: '+theme; try{localStorage.setItem('caf-theme',theme);}catch{} });
render();
</script>"""
    script = script.replace("__DATA__", data_json).replace("__CATS__", cats_json).replace("__KEY__", key_json)
    parts.append(script)
    return "\n".join(parts)


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cheatsheet.html")
    open(out, "w").write(build())
    print("wrote", out, "(", len(ATTACKS), "attacks )")
