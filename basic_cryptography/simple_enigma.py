import string

def rotate_string(s: str, n: int):
    if not s:
        return s
    n %= len(s)
    return s[n:] + s[:n]

class SimpleEnigma:
    def __init__(self, rotors: list[str]):
        # assumed each rotor of len = 26
        self.origin_rotors = rotors.copy()
        self.rotors = rotors

    def rotate_rotors(self, rotations: list[int]):
        for i, rotation in enumerate(rotations):
            self.rotors[i] = rotate_string(self.rotors[i], rotation)

    def rotate_left(self):
        for i, _ in enumerate(self.rotors):
            self.rotors[i] = rotate_string(self.rotors[i], 1)
            if self.rotors[i] != self.origin_rotors[i]:
                break

    def decrypt(self, ct):
        dec = []
        for c in ct:
            if c not in string.ascii_uppercase:
                dec.append(c)
                continue
            self.rotate_left()
            for rotor in reversed(self.rotors):
                c =  string.ascii_uppercase[rotor.find(c)]
            dec.append(c)
        return "".join(dec)


se = SimpleEnigma([
    "MACHINEBDFGJKLOPQRSTUVWXYZ",
    "ORBITACDEFGHJKLMNPQSUVWXYZ",
    "CIPHERABDFGJKLMNOQSTUVWXYZ",
])
print(se.decrypt("HKV{BSBU-B-SJYZNNB-DNFW-IXH-YTA-RPL-RTXOLWFQ}"))
