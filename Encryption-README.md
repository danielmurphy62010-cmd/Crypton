# `Encryption.py` — Cryptographic Utilities

`Encryption.py` collects hashing, key derivation, symmetric encryption, key agreement, digital signatures, key serialization, and certificate-generation helpers. `network.py` uses a subset of these helpers for Crypton's custom authenticated TCP protocol. The TLS certificate helper is separate from that protocol.

> **Security note:** These helpers are building blocks, not a protocol security review. Prefer authenticated encryption, protect private keys, and have the full protocol reviewed before using it for high-risk data.

## Requirements

Install the Python packages used by this module:

```bash
python -m pip install cryptography argon2-cffi blake3
```

The project-local `util.py` module is imported as well. `blake3` is optional for this module's hashing/KDF fallback, but the current `client.py` and `server.py` import `blake3` directly, so it is required to run the full application.

## API overview

| Function | Purpose |
|---|---|
| `HASH(data, l=32, hex=False)` | Hashes bytes and returns a digest or hexadecimal text. Uses BLAKE3 when installed; otherwise uses SHA-3/SHAKE fallback logic. |
| `basic_kdf(master_pw, salt, length=32)` | Lightweight deterministic derivation helper. It is not a password-hardening KDF. |
| `kdf(password, salt, level=5)` | Argon2id derivation; returns 512 bytes in the current implementation. |
| `kdf_fast(password, salt)` / `kdf_slow(password, salt)` | Argon2id convenience wrappers for levels 0 and 10. |
| `encrypt(data, key)` / `decrypt(blob, key)` | AES-CTR encryption. This format has no authentication tag and does not detect tampering. |
| `encryptGCM(data, key, aad=None)` / `decryptGCM(blob, key, aad=None)` | AES-GCM authenticated encryption and decryption. AAD must match. |
| `gen_chacha20()` | Generates a random 32-byte key. |
| `encrypt_chacha(data, key, auth=True)` / `decrypt_chacha(blob, key, auth=True)` | ChaCha20-Poly1305 with `auth=True`; raw ChaCha20 stream encryption without authentication with `auth=False`. |
| `gen_x25519(overkill=False)` / `shared_secret(private, public)` | Generates X25519 keys and derives a shared secret; `overkill=True` selects X448. |
| `gen_ed25519(overkill=False)` / `ed25519_sign(private, data)` / `ed25519_verify(public, blob)` | Generates Ed25519 signing keys and signs/verifies data; `overkill=True` selects Ed448 for key generation. |
| `frame_key`, `detect_key_type`, `get_pub`, `load_keys` | Encode/decode the module's tagged raw-key format and load matching asymmetric keys. |
| `generate_tls(...)` | Writes a self-signed ECDSA P-256 TLS certificate and an unencrypted PEM private key. |
| `gen_CA(...)` | Writes a signing key, public key, and certificate files. Review its implementation before using it as part of a production PKI. |

## Hashing and key derivation

```python
import os
import Encryption as enc

payload = b"sample data"
digest_hex = enc.HASH(payload, l=32, hex=True)

salt = os.urandom(16)
key = enc.kdf(b"a user-supplied password", salt, level=5)
assert len(digest_hex) == 64
```

Use a unique random salt for each password-derived key and persist the salt with the material it protects. `basic_kdf` is intended for deriving subkeys from existing key material; it is not a substitute for Argon2id when hardening a human password.

**Compatibility warning:** Installing or removing `blake3` changes the implementation of `HASH` and `basic_kdf`. The BLAKE3 and fallback outputs are not byte-for-byte compatible. Keep the same environment/configuration for all participants that derive or verify the same key material.

## Authenticated symmetric encryption (AES-GCM)

```python
import os
import Encryption as enc

master_key = os.urandom(32)
plaintext = b"Sensitive information"
associated_data = b"record:123"

ciphertext = enc.encryptGCM(plaintext, master_key, aad=associated_data)
recovered = enc.decryptGCM(ciphertext, master_key, aad=associated_data)
assert recovered == plaintext
```

The signatures are `encryptGCM(data, key, aad=None)` and `decryptGCM(encrypted, key, aad=None)`. They do not accept a `secure_kdf` argument. The serialized value contains a 12-byte nonce, a 32-byte salt, and the AES-GCM ciphertext/tag. The helper derives a subkey from the supplied key and random salt. Decryption fails if the ciphertext/tag or supplied AAD is invalid.

## AES-CTR and ChaCha20 caveat

`encrypt()` serializes a 16-byte IV, a 32-byte salt, and the AES-CTR ciphertext. There is no authentication tag; modifications can result in modified plaintext without a reliable integrity error.

`encrypt_chacha(..., auth=True)` uses ChaCha20-Poly1305 and includes a random salt and nonce. With `auth=False`, it uses raw ChaCha20 stream encryption and provides no authentication. Prefer AEAD modes for application data unless a separate, correctly designed integrity mechanism is already provided.

## Key agreement

```python
import Encryption as enc

alice_private, alice_public = enc.gen_x25519()
bob_private, bob_public = enc.gen_x25519()

alice_secret = enc.shared_secret(alice_private, bob_public)
bob_secret = enc.shared_secret(bob_private, alice_public)
assert alice_secret == bob_secret
```

Keys are returned in Crypton's tagged format, not as bare raw key bytes. `gen_x25519(overkill=True)` selects X448. Keep private keys secret and use derived secrets only in protocols that provide authentication and appropriate key separation.

## Digital signatures

```python
import Encryption as enc

private_key, public_key = enc.gen_ed25519()
message = b"Data to be signed"
signed_blob = enc.ed25519_sign(private_key, message)
verified_message = enc.ed25519_verify(public_key, signed_blob)
assert verified_message == message
```

The current format is `signature || original_message`; verification returns the original message and raises if verification fails. Ed25519 signatures are 64 bytes and Ed448 signatures are 114 bytes. Do not assume a fixed signature length if handling both algorithms.

## Certificate helpers

```python
import Encryption as enc

enc.generate_tls(
    cert_path="cert.pem",
    key_path="key.pem",
    common_name="localhost",
    san_dns=["localhost"],
    valid_days=365,
)
```

`generate_tls` creates a self-signed ECDSA P-256 certificate. It returns without regenerating if both output paths already exist. The private key is written without encryption; protect it with filesystem permissions and encrypted storage. A self-signed certificate is not automatically trusted by clients.

The `network.py` transport uses its own signed-key handshake and AES-GCM messages. It does **not** use this X.509/TLS certificate helper, so generating a certificate does not make the Crypton transport TLS.

## Security checklist

- Prefer AES-GCM or ChaCha20-Poly1305 over unauthenticated AES-CTR or raw ChaCha20.
- Do not use `basic_kdf` to harden weak passwords; use Argon2id with a unique random salt.
- Do not reuse nonce/key combinations with AEAD algorithms.
- Keep private keys, salts, and protected state together in reliable, access-controlled backups.
- Treat BLAKE3-available and fallback environments as different cryptographic configurations.
- Independently review the protocol before relying on it for sensitive or high-risk workloads.
