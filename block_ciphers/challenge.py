from Crypto.Cipher import AES
from Crypto.Util import Counter

def encrypt(key, nonce, msg):
    ctr = Counter.new(64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(msg)


if __name__ == "__main__":
    def xor_bytes(a: bytes, b: bytes, longest=False) -> bytes:
        return bytes((a[i] if len(a) > i else 0) ^ (b[i] if len(b) > i else 0) for i in range((min if not longest else max)(len(a), len(b))))

    pt_known = open("know_message.txt", "rb").read()
    ct_known = bytes.fromhex(open("ciphertext_known.hex", "r").read())
    ks = xor_bytes(pt_known, ct_known)

    ct = bytes.fromhex(open("ciphertext_flag.hex", "r").read())
    pt = xor_bytes(ks, ct)
    print(pt.decode('ascii'))

