import json
import Crypto.Util.number
import gmpy2


params = json.load(open("challenge.json", "r"))

n = params["n"]
e1 = params["e1"]  # 65537 = 2**16 + 1
e2 = params["e2"]  # 17    = 2**4  + 1
c1 = params["c1"]
c2 = params["c2"]


# {c1, c2, e1, e2, n} known
# c1 = m**e1 (mod n), e1 = 2**16 + 1
# c2 = m**e2 (mod n), e2 = 2**4  + 1
# calculate m

# gcd(e1, e2) = 1
# a*e1 + b*e2 = 1     # find a, b using extended euclidean algorithm (EEA)
gcd, a, b = gmpy2.gcdext(e1, e2)
assert gcd == 1
print(a, b)
# c1**a * c2**b = m**(a*e1) * m**(b*e2) = m**(a*e1 + b*e2) = m     (mod n)
m = (pow(c1, a, n) * pow(c2, b, n)) % n
print(m)
FLAG = Crypto.Util.number.long_to_bytes(m)
print(FLAG.decode())
