# decrypt_from_base64.py

import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PASS_PHRASE = "secret_password"

B64_PAYLOAD = "payload"

PBKDF2_ITERATIONS = 200_000

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))

def decrypt_from_base64(b64_payload: str, passphrase: str) -> str:
    data = base64.b64decode(b64_payload)
    if len(data) < 16 + 12 + 16:
        raise ValueError("wrong input: data is too short.")
    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext_bytes.decode("utf-8")

if __name__ == "__main__":
    try:
        plaintext = decrypt_from_base64(B64_PAYLOAD, PASS_PHRASE)
        print(plaintext)
    except Exception as e:
        print(f"failed to decrypt: {e}")
