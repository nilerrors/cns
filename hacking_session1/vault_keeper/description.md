The Vault hands you a session token when you log in, and checks its integrity tag before trusting it. The token is in three parts separated by dots [ header.blob.tag] and the header is plain, readable metadata that says which algorithms the token uses.

The middle part is an encrypted blob, the last part is the integrity tag. You have a guest token, get into /admin as an administrator.

> GET /login → your guest token GET /admin → send your token in the Authorization: Bearer header

Target: http://cns-test.idlab.uantwerpen.be:50010

Tip: decode each part (base64url). Look closely at who decides how the tag is checked
