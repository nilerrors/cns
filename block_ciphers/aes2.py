from Crypto.Cipher import AES
import itertools

ct = bytes.fromhex("df7c7dfbd5e1ba2af108d658132d5f20d34de27da16375ceabd7a79cbfe738244027a4a0b26ec498a2c223a545b9567c20bf423bb38514e6cd6f043ab9e23a84ffa6745294c224068e1cffd9e8c9e294")

enc = open("enc.bmp", "rb").read()

for k1, k2 in itertools.product(range(2**20), repeat=2):
    K1 = k1.to_bytes(3, "big") + b"\x00"*13
    K2 = k2.to_bytes(3, "big") + b"\x00"*13

    dec = AES.new(K1, AES.MODE_ECB).decrypt(AES.new(K2, AES.MODE_ECB).decrypt(ct))
    if dec[:4] == b'cns{':
        print(dec)
        exit(0)
