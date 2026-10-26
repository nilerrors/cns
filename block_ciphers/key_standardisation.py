# { "namespace": "IOTDEV", "message": "74eb40cf03b84d0bc4cd2c6e0fe97fb4e70546d3e09c530d35b344e530351bac" }

from Crypto.Cipher import DES
import itertools

key = b"IOTDEV"
ct = bytes.fromhex("74eb40cf03b84d0bc4cd2c6e0fe97fb4e70546d3e09c530d35b344e530351bac")


def to_ascii(lst: list[int]) -> str:
    return ''.join(chr(v) for v in lst)

def most(it) -> bool:
    count_true = 0
    count_total = 0
    for i in it:
        count_total += 1
        count_true += 1 if i else 0
    return count_true >= count_total//2

def is_readable(bs: bytes) -> bool:
    return most(32 <= b < 127 for b in bs)

for pi, pj in itertools.product(range(2**7), repeat=2):
    padded_key = key + (chr(pi) + chr(pj)).encode('ascii')

    c = DES.new(padded_key, DES.MODE_ECB)
    dec = c.decrypt(ct)
    da = to_ascii(c.decrypt(ct))
    if is_readable(dec) and da.startswith('cns'):
        print(padded_key)
        print(da)

