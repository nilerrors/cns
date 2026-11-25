# CNS hacking-session toolkit

Prepared code for the UAntwerpen CNS hacking sessions. Notes and prepared code
are allowed in the session; LLMs are not. This is the prepared code.

Lives at `sessions/toolkit/` so it can grow across sessions. Today it covers
**asymmetric encryption** (RSA, ElGamal, DSA / signatures, Diffie-Hellman,
discrete log, key distribution); add modules alongside `cnscrypto.py` for the
symmetric / hashing / MAC topics when preparing hacking session 3.

The asymmetric parts are verified against the already-solved exercises in
`../asymmetric_encryption/{rsa,elgamal,digital_signatures}` — the toolkit
reproduces every one of those flags (run `test_toolkit.py`).

```
toolkit/
├── cnscrypto.py        core library: import this. number theory + every attack.
├── solve_rsa.py        CLI: auto-detect & run the right RSA attack on a file
├── solve_elgamal.py    CLI: ElGamal (key reuse, related nonce, dlog)
├── solve_dsa.py        CLI: DSA (nonce reuse / known-k / linear-k) + flag keystream
├── factor.py           CLI: factor an integer (trial / fermat / p-1 / rho)
├── dlog.py             CLI: discrete log (BSGS / Pohlig-Hellman)
├── remote.py           helper for interactive / server challenges (no pwntools)
├── cheatsheet.html     OPEN THIS: searchable symptom→attack recognition guide
└── build_cheatsheet.py regenerates cheatsheet.html (edit content there)
```

## Setup

Uses the existing `../venv` (pycryptodome + gmpy2). gmpy2 just makes big-int
roots/gcd fast; the library falls back to pure Python without it.

```bash
cd sessions
./venv/bin/python toolkit/cnscrypto.py     # self-test
./venv/bin/python toolkit/test_toolkit.py  # reproduce solved flags + related attacks
```

In the lab, put `cnscrypto.py` next to your solve script (or `sys.path.insert`)
and `import cnscrypto as C`.

## The one tool to open first

**`cheatsheet.html`** — open it in a browser (works offline). Type a *symptom*
("same r", "small d", "shared c1", "close primes", "broadcast", "directory") and
it shows the matching attack, the math, a copy-paste snippet, the CLI command,
and which of your solved exercises used it. Press `/` to jump to search.
Also published (private) at the Crypto Attack Finder artifact for browser/pin use.

## CLI quick reference

All examples are real and were run against the solved exercises.

```bash
py=../venv/bin/python     # run these from inside toolkit/
ex=../asymmetric_encryption

# RSA — auto-detects the attack from the fields present
$py solve_rsa.py $ex/rsa/sifting_sand/challenge.json          # small n → factor
$py solve_rsa.py $ex/rsa/free_keys/challenge.json             # common modulus
$py solve_rsa.py $ex/rsa/sports_car_desire/challenge.json     # Wiener (small d)
$py solve_rsa.py $ex/rsa/group_chat/public_keys.txt $ex/rsa/group_chat/ciphertexts.txt  # broadcast
$py solve_rsa.py -n N -e E -c C                              # pass values directly
$py solve_rsa.py -n N -e E -c C --attack wiener             # force one attack

# factoring
$py factor.py 34664911185892166593 -e 65537                  # factor + compute d
$py factor.py N --fermat          # close primes
$py factor.py N --pm1 --bound 1000000   # smooth prime

# ElGamal
$py solve_elgamal.py $ex/elgamal/asymmetric_nonsense/challenge.json   # nonce reuse
$py solve_elgamal.py $ex/elgamal/fresh_every_time/ElGamal_challenge.json  # related nonce
$py solve_elgamal.py ch.json --x 12345                      # private key known

# DSA
$py solve_dsa.py $ex/digital_signatures/dsa1_challenge.json   # nonce reuse + flag
$py solve_dsa.py ch.json --k 42                             # known nonce
$py solve_dsa.py ch.json --a 1 --b 1                        # linear nonce k2=k1+1

# discrete log
$py dlog.py -g 2 -t 22 -p 29
```

## Library API (import cnscrypto as C)

**Number theory**: `egcd` `inverse` `crt` `crt_pair` `isqrt` `iroot` `is_prime`
`factorize` `primitive_root` `order`
**Encoding**: `long_to_bytes` `bytes_to_long` `to_int` `parse_blob` `find_flag` `looks_text`
**Discrete log**: `bsgs` `pohlig_hellman` `discrete_log`
**Factoring**: `trial_division` `fermat_factor` `pollard_rho` `pollard_pm1` `common_factor`
**RSA**: `rsa_d` `rsa_decrypt` `wiener` `hastad_broadcast` `common_modulus`
`low_exponent_root` `factor_from_d` `lsb_oracle` `rsa_malleability_factor`
`rsa_unblind` `rsa_sign_raw` `rsa_verify_raw` `rsa_forge_product`
**ElGamal / DH**: `elgamal_encrypt` `elgamal_decrypt` `elgamal_key_reuse`
`elgamal_scale_mask` `elgamal_decrypt_with_dlog` `dh_shared` `dh_break`
**DSA**: `dsa_sign` `dsa_verify` `dsa_x_from_nonce_reuse` `dsa_x_from_known_k`
`dsa_x_from_linear_nonce` `H_int_mod` `H_fips`

Every function has a docstring saying **when** to use it (those are the source
for the cheatsheet).

## Session workflow

1. Read the challenge. Note what you're given (fields, how many keys/ciphertexts,
   whether there's a server/oracle).
2. Open `cheatsheet.html`, search the symptom, or use the **Triage** box at the top.
3. Point the matching `solve_*.py` at the file, or copy the snippet and adapt.
4. For interactive challenges, use `remote.py` (`Tube` for TCP, `http_json` for HTTP).

## Exercise → attack map

| solved exercise | attack |
|---|---|
| rsa/sifting_sand | factor small n (Pollard rho) → d, block decrypt |
| rsa/free_keys | common modulus (gcd(e1,e2)=1) |
| rsa/group_chat, better_group_chat | Håstad broadcast (e=3) |
| rsa/sports_car_desire | Wiener (small d) |
| elgamal/asymmetric_nonsense | nonce reuse (equal c1) + known plaintext |
| elgamal/fresh_every_time | related nonce (c1'=c1·g), scale the mask |
| digital_signatures/dsa1 | DSA nonce reuse (shared r) → x → keystream flag |
| key_distribution | unauthenticated public directory (register own key) |

## Related attacks included (not in the exercises yet, but fair game)

Fermat (close primes), Pollard p-1 (smooth prime), batch-GCD shared prime,
factor-from-leaked-d, low-exponent single-ciphertext root, LSB/parity oracle,
RSA malleability (CCA), RSA signature product-forgery, ElGamal key recovery by
discrete log, DSA known/linear nonce, BSGS & Pohlig-Hellman discrete log,
Diffie-Hellman break & MITM, KDC replay, forged public announcement / X.509 idea.
