import json
import Crypto.Util.number

params = json.load(open("challenge.json", "r"))

n = params["n"]
e = params["e"]
c = params["c"]

d = Crypto.Util.number.bytes_to_long(b"F1")

print(Crypto.Util.number.long_to_bytes(pow(c, d, n)))
