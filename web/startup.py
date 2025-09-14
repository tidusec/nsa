import os
from Crypto.PublicKey import RSA


# Generate BWT key
os.makedirs("config", exist_ok=True)
key_path = os.environ.get("BWT_KEY_FILE", os.path.join("config", "private.key"))
with open(key_path, "wb") as f:
    key = RSA.generate(2048)
    f.write(key.export_key(format="DER"))

os.execvp(
    "gunicorn", ["gunicorn", "--bind", "0.0.0.0:1337", "--workers", "4", "server:app"]
)
