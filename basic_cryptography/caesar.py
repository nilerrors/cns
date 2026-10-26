import string

class Caesar:
    def __init__(self, shift_by = 3):
        self.shift_by = shift_by

    def shift(self, c: str, by: int) -> str:
        if c not in string.ascii_lowercase:
            return c
        start = ord('a')
        cord = ord(c)
        return chr(start + (cord - start + by) % 26)

    def encrypt(self, msg: str) -> str:
        return ''.join([self.shift(c, self.shift_by) for c in msg])

    def decrypt(self, msg: str) -> str:
        return ''.join([self.shift(c, -self.shift_by) for c in msg])

caesar = Caesar()
print(caesar.decrypt(input()))

