"""Re-wrap the site's content key with a new password (writes key.json)."""
import base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
ck_b64, pw = os.environ.get("CONTENT_KEY", "").strip(), os.environ.get("SITE_PASSWORD", "")
if not ck_b64 or not pw:
    sys.exit("Missing secret: add CONTENT_KEY and SITE_PASSWORD in Settings > Secrets and variables > Actions")
if len(pw) < 8:
    sys.exit("SITE_PASSWORD must be at least 8 characters")
ck = base64.b64decode(ck_b64)
assert len(ck) == 32, "CONTENT_KEY is not valid"
b64 = lambda b: base64.b64encode(b).decode()
salt, iv, it = os.urandom(16), os.urandom(12), 600000
kek = PBKDF2HMAC(hashes.SHA256(), 32, salt, it).derive(pw.encode())
json.dump({"salt": b64(salt), "it": it, "iv": b64(iv), "wk": b64(AESGCM(kek).encrypt(iv, ck, None))}, open("key.json", "w"))
print("key.json updated")
