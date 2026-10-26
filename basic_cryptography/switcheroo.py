class Switcheroo:
    def __init__(self, mapping_from: str, mapping_to: str):
        self.mapping_from = mapping_from
        self.mapping_to = mapping_to

    def map(self, c, f, t):
        if c not in f:
            return c
        return t[f.find(c)]

    def encrypt(self, msg: str) -> str:
        return ''.join([self.map(c, self.mapping_from, self.mapping_to) for c in msg])

    def decrypt(self, msg: str) -> str:
        return ''.join([self.map(c, self.mapping_to, self.mapping_from) for c in msg])

agent = Switcheroo("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "QWERTYUIOPASDFGHJKLZXCVBNM")
print(agent.decrypt(input()))

