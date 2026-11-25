import sys
import re
import json
import base64
import hashlib
import itertools
import Crypto.Util.number

params = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "dsa1_challenge.json", "r"))

p = params["p"]
q = params["q"]
g = params["g"]
y = params["y"]
hash_desc = params.get("hash", "")
signatures = params["signatures"]
encrypted_flag = params["encrypted_flag"]
flag_desc = params.get("flag_encryption", "")


# DSA:
#   y = g^x (mod p)
#   r = (g^k mod p) mod q
#   s = k^-1 * (H(m) + x*r) (mod q)
#
# Double entry => the same nonce k is used twice ==> same r for both signatures
#   s1 = k^-1 * (H1 + x*r)
#   s2 = k^-1 * (H2 + x*r)
#   ==> s1 - s2 = k^-1 * (H1 - H2)
#   ==> k = (H1 - H2) / (s1 - s2)       (mod q)
#   ==> x = (s1*k - H1) / r             (mod q)


# ---------- hash functions ----------

def norm(name):
    return name.lower().replace("-", "").replace("_", "")


HASHES = {norm(h): h for h in hashlib.algorithms_guaranteed if not h.startswith("shake")}


def hashes_in(desc):
    """hash names mentioned in a description, longest names first (sha3_256 before sha256)"""
    d = norm(desc)
    found = sorted((n for n in HASHES if n in d), key=lambda n: (d.index(n), -len(n)))
    # drop names that are substrings of an already matched longer name (sha256 inside sha3256)
    result = []
    for n in found:
        if not any(n != m and n in m and m in d for m in found):
            result.append(HASHES[n])
    # mentioned ones first, then everything else as a fallback
    return result + [h for h in HASHES.values() if h not in result]


def H_mod(h):
    # H(m) = int(hash(m)) mod q
    return lambda m: int.from_bytes(hashlib.new(h, m).digest(), "big") % q


def H_trunc(h):
    # FIPS 186: H(m) = leftmost min(N, outlen) bits of hash(m)
    N = q.bit_length()
    def H(m):
        d = hashlib.new(h, m).digest()
        z = int.from_bytes(d, "big")
        if len(d) * 8 > N:
            z >>= len(d) * 8 - N
        return z % q
    return H


def H_little(h):
    return lambda m: int.from_bytes(hashlib.new(h, m).digest(), "little") % q


def verify(H, m, r, s):
    if not (0 < r < q and 0 < s < q):
        return False
    w = pow(s, -1, q)
    u1 = H(m) * w % q
    u2 = r * w % q
    return (pow(g, u1, p) * pow(y, u2, p) % p) % q == r


def find_hash():
    """pick the hash interpretation under which the given signatures verify"""
    m, r, s = msg(signatures[0]), signatures[0]["r"], signatures[0]["s"]
    for h in hashes_in(hash_desc):
        for variant in (H_mod, H_trunc, H_little):
            H = variant(h)
            if verify(H, m, r, s):
                return H, f"{variant.__name__}({h})"
    return None, None


def msg(sig):
    m = sig["message"]
    return m.encode() if isinstance(m, str) else bytes(m)


# ---------- recover x ----------

def recover_x(H):
    # find two signatures sharing the same r (= same k)
    for a, b in itertools.combinations(signatures, 2):
        if a["r"] != b["r"] or a["s"] == b["s"]:
            continue
        r = a["r"]
        H1, H2 = H(msg(a)), H(msg(b))
        k = (H1 - H2) * pow(a["s"] - b["s"], -1, q) % q
        x = (a["s"] * k - H1) * pow(r, -1, q) % q
        if pow(g, x, p) == y:
            return x, k
    return None, None


H, H_name = find_hash()
if H is not None:
    print("Hash:", H_name)
    x, k = recover_x(H)
else:
    # signatures do not verify with any interpretation: brute force, check y = g^x
    print("No hash verified the signatures, trying all of them")
    x = k = None
    for h in hashes_in(hash_desc):
        for variant in (H_mod, H_trunc, H_little):
            x, k = recover_x(variant(h))
            if x is not None:
                print("Hash:", f"{variant.__name__}({h})")
                break
        if x is not None:
            break

assert x is not None, "could not recover the private key"
assert pow(g, x, p) == y
print("k =", k)
print("x =", x)


# ---------- decrypt the flag ----------
#   flag XOR keystream, keystream = hash(f'{x}:0') || hash(f'{x}:1') || ...

def parse_ciphertext(c):
    c = c.strip()
    try:
        return bytes.fromhex(c)
    except ValueError:
        return base64.b64decode(c)


def described_template():
    """turn e.g. "sha256(f'{x}:0')" into the python format string "{x}:{i}" """
    templates = re.findall(r"\(\s*f?(['\"])(.*?)\1\s*\)", flag_desc)
    if not templates:
        return None
    t = templates[0][1]
    names = re.findall(r"\{(\w*)\}", t)
    counter_names = {"i", "j", "n", "ctr", "counter", "idx", "index", "block", "c"}
    key_names = {"x", "key", "priv", "private_key", "sk", "d"}
    # placeholders: counter-like -> {i}, everything else -> {x}
    for name in names:
        if name in counter_names and name not in key_names:
            t = t.replace("{" + name + "}", "{i}")
        else:
            t = t.replace("{" + name + "}", "{x}")
    if "{i}" not in t:
        # counter is written as a literal (0) outside the braces: replace the last one
        parts = re.split(r"(\{[^}]*\})", t)
        for idx in range(len(parts) - 1, -1, -1):
            if not parts[idx].startswith("{") and re.search(r"\d+", parts[idx]):
                parts[idx] = re.sub(r"\d+(?!.*\d)", "{i}", parts[idx])
                break
        t = "".join(parts)
    return t


def keystream_str(h, template, x, length):
    out = b""
    for i in itertools.count():
        if len(out) >= length:
            return out[:length]
        out += hashlib.new(h, template.format(x=x, i=i).encode()).digest()


def keystream_bytes(h, x, length, counter_len, order):
    xb = Crypto.Util.number.long_to_bytes(x)
    out = b""
    for i in itertools.count():
        if len(out) >= length:
            return out[:length]
        ib = i.to_bytes(counter_len, "big")
        out += hashlib.new(h, xb + ib if order == "xi" else ib + xb).digest()


def keystream_repeat(h, x, length):
    d = hashlib.new(h, str(x).encode()).digest()
    return (d * (length // len(d) + 1))[:length]


def candidates(x, length):
    templates = [described_template()] + ["{x}:{i}", "{x}{i}", "{x}|{i}", "{x}-{i}", "{x},{i}",
                                          "{x}_{i}", "{x} {i}", "{i}:{x}", "{i}{x}"]
    templates = list(dict.fromkeys(t for t in templates if t))
    for h in hashes_in(flag_desc):
        for t in templates:
            yield f"{h}('{t}')", keystream_str(h, t, x, length)
    for h in hashes_in(flag_desc):
        for counter_len in (1, 4, 8):
            for order in ("xi", "ix"):
                yield f"{h}(bytes {order}, {counter_len})", keystream_bytes(h, x, length, counter_len, order)
        yield f"{h}(str(x)) repeated", keystream_repeat(h, x, length)


def score(pt):
    try:
        s = pt.decode()
    except UnicodeDecodeError:
        return 0
    if not s.isprintable():
        return 0
    return 2 if re.fullmatch(r"[\w\-]*\{.*\}", s) else 1


ct = parse_ciphertext(encrypted_flag)
best = (0, None, None)
for name, ks in candidates(x, len(ct)):
    pt = bytes(a ^ b for a, b in zip(ct, ks))
    sc = score(pt)
    if sc > best[0]:
        best = (sc, name, pt)
    if sc == 2:
        break

assert best[2] is not None, "could not decrypt the flag"
print("Keystream:", best[1])
print("Flag:", best[2].decode())
