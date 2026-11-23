import math
import Crypto.Util.number
import gmpy2


def read_dictionary(file: str, val_types: tuple[type] | None = None):
    lines = open(file, "r").readlines()
    dictionary = {}
    in_context = None
    for line in lines:
        if line.endswith("\n"):
            line = line[:-1]
        if line.startswith("--- ") and line.endswith(" ---"):
            in_context = line.replace("--- ", "").replace(" ---", "")
        elif line == "":
            in_context = None
        else:
            kv_pair = line.split(" = ", 1)
            if len(kv_pair) != 2:
                # wrong format, expected key-value pair got a value
                return None
            key, val = kv_pair
            if val_types is not None:
                # default type will always be string
                for t in val_types:
                    try:
                        val = t(val)
                        break
                    except Exception as e:
                        continue
            if in_context is not None:
                dictionary.setdefault(in_context, {})
                dictionary[in_context][key] = val
            else:
                dictionary[key] = val
    return dictionary




ciphertexts = read_dictionary("ciphertexts.txt", (int,))
public_keys = read_dictionary("public_keys.txt", (int,))

# print(ciphertexts)
# print(public_keys)

# c_i = A (mod n_i)
#     where A = M^e
#     (*note: only works when M and e is the same for all*)

# To find the original M, we have to do:
#   1. Find A = M^e using CRT (chinese remainder theorem)
#   2. Find M using iroot

cs = ciphertexts.values()

es = [public_keys[key]["e"] for key in public_keys]
assert len(set(es)) == 1
e = es[0]
assert len(es) == e
ns = [public_keys[key]["n"] for key in public_keys]
# print(ns)

# Step 1: CRT

N = math.prod(ns)
# print(N)

Ns = [math.prod(ns[:i] + ns[i+1:]) for i,_ in enumerate(ns)]
# print(Ns)

ps = [Ni * pow(Ni, -1, ni) for Ni, ni in zip(Ns, ns)]

A = (sum(c * p for c, p in zip(cs, ps))) % (N)
# print(A)

# Step 2

M, exact = gmpy2.iroot(A, e)
if not exact:
    print("Not exact: ", end="")

print(M)
print("Flag:", Crypto.Util.number.long_to_bytes(M).decode("ascii"))
