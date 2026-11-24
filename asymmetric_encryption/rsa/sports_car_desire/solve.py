import json
import math
import Crypto.Util.number

params = json.load(open("challenge.json", "r"))

n = params["n"]
e = params["e"]
c = params["c"]

# Wiener's theorem
#  ed == 1 (mod totient(n))
#  ==> ed = k(p-1)(q-1) + 1
    # nd = pqd
#  ==> (ed)/(nd) = k/d (1-t), where t (= ((p-1)(q-1) + 1)/pq) small
#  ==> e/n ~= k/d
#  ==> e, n known, guess k and d


def cfexp(num, den):
    """continued fraction expansion for num/den"""
    while den:
        quotient = num // den
        yield quotient
        num, den = den, num - quotient * den


def convergents(num, den, k = 1):
    """
    k/d =
        0 : 0/1 = 0
        5 : 0 + 1/5 = 1/5
        29: 0 + 1/(5 + 1/29) = 1/((5*29 + 1)/29) = 29/(5*29 + 1)
        4 : 0 + 1/(5 + 1/(29 + 1/4)) = 1/(5 + 1/((29*4 + 1)/4)) = 1/(5 + 4/(29*4 + 1)) = 1/((5*(29*4 + 1) + 4)/(29*4 + 1)) = (29*4 + 1)/(5*(29*4 + 1) + 4)
        3 : 0 + 1/(5 + 1/(29 + 1/(4 + (1/3)))) = 1/(5 + 1/(29 + 1/((4*3 + 1)/3))) = 1/(5 + 1/(29 + 3/(4*3 + 1))) = 1/(5 + (4*3 + 1)/(29*(4*3 + 1) + 3)) = (29*(4*3 + 1) + 3)/(5*(29*(4*3 + 1) + 3) + (4*3 + 1))
    
    k's evolution:
         -2  : 0
         -1  : 1
        0(0) : 0 = 0 * 1 + 0
        1(5) : 1 = 5 * 0 + 1
        2(29): 29 = 29 * 1 + 0
        3(4) : (29*4 + 1) = (4*(29 + 1)
        4(3) : (29*(4*3 + 1) + 3) = (3*(4*29 + 1) + 29)
        k_{n+1} = q * k_{n} + k_{n-1}, 
    
    d's evolution:
         -2  : 1
         -1  : 0
        0(0) : 1 = 0 * 0 + 1
        1(5) : 5 = 5 * 1 + 0
        2(29): (5*29 + 1) = 
        3(4) : (5*(29*4 + 1) + 4)
        4(3) : (5*(29*(4*3 + 1) + 3) + (4*3 + 1))
        d_{n+1} = q * d_{n} + d_{n-1}
    """
    kp, k = 0, 1
    dp, d = 1, 0
    for q in cfexp(num, den):
        kp, k = k, q * k + kp
        dp, d = d, q * d + dp
        if k == num and d == den:
            return k, d
        yield k, d


def totient(e, d, k):
    """returns: totient(N), exact?"""
    return (e * d - 1) // k, ((e * d - 1) % k) == 0


def solve_quadratic_exact(a, b, c):
    D = b * b - 4 * a * c
    if D < 0: return None, None
    sD = math.isqrt(D)
    if sD ** 2 != D: return None, None
    x = lambda s: (-b + s)//(2*a)
    return x(-sD), x(+sD)


def wiener(e, n):
    for k, d in convergents(e, n):
        if k == 0: continue
        ton, exact = totient(e, d, k)
        if not exact: continue
        p, q = solve_quadratic_exact(1, n - ton + 1, n)
        if (p, q) != (None, None) and p * q == n:
            return d, p, q
    return None, None, None


d, p, q = wiener(e, n)
print(Crypto.Util.number.long_to_bytes(pow(c, d, n)).decode())
