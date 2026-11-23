import Crypto.Util.number
import math

n = 34664911185892166593
# n = 125513
# n = 8051
e = 65537

## Fermat:
# x = math.ceil(math.sqrt(n))
# a = None
# p = None
# q = None
# while x < n:
#     f, a = math.modf(math.sqrt(pow(x, 2) - n))
#     a = round(a)
#     #print(x, pow(x, 2), pow(x, 2) - n, math.sqrt(x*x - n))
#     if f == 0.0:
#         p, q = x + a, x - a
#         if Crypto.Util.number.isPrime(p) and Crypto.Util.number.isPrime(q):
#             break
#     x += 1
# print(x, a)
# print(p, q)

# Pollard's rho
g = lambda x: (pow(x, 2) + 1) % n

x = 2
y = x
p = 1
while p == 1:
    x = g(x)
    y = g(g(y))
    p = math.gcd(abs(x - y), n)
print(p)
qf, qi = math.modf(n / p)
if qf != 0.0:
    print("failed")
q = round(qi)
print(q)

if not Crypto.Util.number.isPrime(p) or not Crypto.Util.number.isPrime(q):
    print("not primes")

print(p, q)

totient_n = (p - 1) * (q - 1)
print("totient(n) =", totient_n)

# d = e^-1 (mod totient(n))
d = pow(e, -1, totient_n)
print("d =", d)
