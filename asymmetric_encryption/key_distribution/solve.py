import sys
import secrets
import requests
import Crypto.Util.number

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://cns-test.idlab.uantwerpen.be:50011"
MY_NAME = sys.argv[2] if len(sys.argv) > 2 else "saba"


# The public key directory has no authentication: anyone may register a key
# under any name, and Alice is willing to encrypt her secret to ANY name in it.
#
# ElGamal encryption to a public key y = g^x (mod p):
#   k random, c1 = g^k, c2 = m * y^k   (mod p)
# decryption with the private key x:
#   m = c2 * (c1^x)^-1   (mod p)        since c1^x = g^(k*x) = (g^x)^k = y^k
#
# Alice's secret is the same whoever she sends it to, so we don't need Bob's
# private key. We register a key whose private key WE chose, ask Alice to
# encrypt her secret to that name, and decrypt it ourselves.


def unwrap(obj, *keys):
    """pull one of several possible field names out of a JSON object"""
    for k in keys:
        if isinstance(obj, dict) and k in obj:
            return obj[k]
    raise KeyError(f"none of {keys} in {obj}")


def as_int(v):
    # accept ints, decimal strings or hex strings
    if isinstance(v, int):
        return v
    s = str(v).strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


# Step 1: fetch the public parameters
params = requests.get(f"{BASE}/params").json()
p = as_int(unwrap(params, "p"))
g = as_int(unwrap(params, "g"))
print(f"p = {p}")
print(f"g = {g}")

# Step 2: pick our own private key and register the matching public key
x = secrets.randbelow(p - 3) + 2
y = pow(g, x, p)
reg = requests.post(f"{BASE}/directory", json={"name": MY_NAME, "y": y})
print(f"registered {MY_NAME!r} -> y = {y}  (HTTP {reg.status_code})")

# Step 3: have Alice encrypt her secret to our key
resp = requests.get(f"{BASE}/send", params={"to": MY_NAME}).json()
# tolerate the common shapes: {c1, c2} / {a, b} / {"ciphertext": [c1, c2]}
if isinstance(resp, (list, tuple)):
    c1, c2 = resp
elif "ciphertext" in resp or "c" in resp:
    c1, c2 = unwrap(resp, "ciphertext", "c")
else:
    c1 = unwrap(resp, "c1", "a", "C1", "r")
    c2 = unwrap(resp, "c2", "b", "C2", "s")
c1, c2 = as_int(c1), as_int(c2)
print(f"c1 = {c1}")
print(f"c2 = {c2}")

# Step 4: decrypt with our private key
m = c2 * pow(pow(c1, x, p), -1, p) % p
secret = Crypto.Util.number.long_to_bytes(m)
print(f"m = {m}")
try:
    print("Secret:", secret.decode())
except UnicodeDecodeError:
    print("Secret (raw bytes):", secret)
