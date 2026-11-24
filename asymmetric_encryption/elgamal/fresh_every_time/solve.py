import json
import Crypto.Util.number

params = json.load(open("ElGamal_challenge.json", "r"))

q = params["p"]
alpha = params["g"]
Y_A = params["y"]
known_plaintext = params["known_plaintext"]
C1_known, C2_known = params["cipher_known"]
C1_flag, C2_flag = params["cipher_flag"]

M_known = Crypto.Util.number.bytes_to_long(known_plaintext.encode())

# C1_flag == C1_known * alpha
assert C1_flag == C1_known * alpha
# ==> C1_known = (alpha)^k   (mod q)
# ==> C1_flag = (C1_known * alpha) = (alpha^k * alpha) = (alpha)^(k+1)   (mod q)
# ==> K_known = (Y_A)^k and ==> Y_flag = (Y_A)^(k+1)   (mod q)

K_known = pow(pow(C2_known, 1, q) * pow(M_known, -1, q), 1, q)
K_flag = pow(K_known * pow(Y_A, 1, q), 1, q)

M_flag = pow(pow(C2_flag, 1, q) * pow(K_flag, -1, q), 1, q)
print(Crypto.Util.number.long_to_bytes(M_flag).decode())
