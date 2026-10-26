class DutchExclusive:
    def __init__(self, key: str):
        self.key = self.hex_parse(key)

    def hex_val(self, c: str) -> int:
        if ord('0') <= ord(c) <= ord('9'):
            return ord(c) - ord('0')
        if ord('a') <= ord(c) <= ord('f'):
            return 10 + ord(c) - ord('a')
        raise ValueError("invalid hex letter")

    def hex_byte_to_int(self, h: str) -> int:
        if len(h) == 1:
            return self.hex_val(h)
        if len(h) == 2:
            return 16 * self.hex_val(h[0]) + self.hex_val(h[1])
        raise ValueError("invalid hex value")

    def hex_parse(self, msg: str) -> list[int]:
        msg = msg.replace(" ", "").replace("\n", "")
        lst = []
        while msg != "":
            if len(msg) == 1:
                lst.append(msg)
                msg = ""
                break
            lst.append(msg[0:2])
            msg = msg[2:]
        return [self.hex_byte_to_int(h) for h in lst]

    def to_ascii(self, lst: list[int]) -> str:
        return ''.join(chr(v) for v in lst)

    def decrypt(self, msg: str) -> str:
        ct = self.hex_parse(msg)
        ct_len = len(ct)
        key_len = len(self.key)

        result_hex = ""
        for i in range(ct_len//key_len + (0 if ct_len%key_len == 0 else 1)):
            range_end = key_len * (i + 1) if i - 1 < ct_len//key_len else -1
            snippet = ct[key_len * i:range_end]
            for i, c in enumerate(snippet):
                snippet[i] = c ^ self.key[i]
            result_hex += ''.join(chr(c) for c in snippet)

        return self.to_ascii(self.hex_parse(result_hex))

de = DutchExclusive("636f6d7075746572656e6e65747765726b7365637572697479697374686562657374636f75727365")

print(de.decrypt("555c4d461054524145590c45434045445353525a55400d544f515342594555535342564f47165353514f5b455542065253594e534d5753434b450043471649434e49454548535445454243591652455043585e5047104545524e585d544150525d16455111525e4d595f15545f5042571754555c55444245550a4d421154534a45585f45434145445e53570755455a544e5d53435a4554035342054f42425352544f5b4155425352535b4e53175752414b440 1"))

