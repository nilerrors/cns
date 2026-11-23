import string

class Caesar:
    def __init__(self, shift_by = 3):
        self.shift_by = shift_by

    def shift(self, c: str, by: int) -> str:
        if c not in string.ascii_lowercase + string.ascii_uppercase:
            return c
        start = ord('a' if c in string.ascii_lowercase else 'A')
        cord = ord(c)
        return chr(start + (cord - start + by) % 26)

    def encrypt(self, msg: str) -> str:
        return ''.join([self.shift(c, self.shift_by) for c in msg])

    def decrypt(self, msg: str) -> str:
        return ''.join([self.shift(c, -self.shift_by) for c in msg])

cipher = input()
for i in range(26):
    caesar = Caesar(i)
    print(caesar.decrypt(cipher))

