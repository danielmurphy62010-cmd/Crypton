# Crypton Networking Module (`network.py`)

`network.py` implements the custom TCP authentication and encrypted-message layer used by Crypton. It handles administrator and client authentication, TOTP bootstrap enrollment, key agreement, authenticated payloads, exchange IDs, per-session counters, and application callbacks. The compiled native `backend` extension handles the actual TCP I/O and its transport queues/workers.

> **Transport and trust warning:** This is a custom protocol, not TLS. The existence of AES-GCM and public-key signatures does not establish that the whole handshake is secure or independently audited. The transport implementation does not use `Encryption.generate_tls()`.

## Dependencies

```bash
python -m pip install cryptography argon2-cffi blake3 zxcvbn pyotp
```

The local `Encryption.py` and `util.py` modules and a compiled/importable `backend` extension are also required. See `SETUP.md` and `backend-README.md` for the extension build process.

## Authentication and local state

Crypton has separate administrator TOTP, bootstrap TOTP, client password, and server password roles:

- **Server password:** Derives the key protecting server-side signing/TOTP material. `network.py` uses `zxcvbn` and rejects password estimates at or below 9 log10 guesses. A 64-byte salt is kept in `./server keys/SERVER SALT`.
- **Administrator TOTP:** Used for the administrator console. The server creates the secret when needed and prints the Base32 secret at startup; store it in an authenticator and keep it private.
- **Bootstrap TOTP:** A separate secret configured and verified in the administrator console. New client enrollment is rejected unless bootstrap is enabled.
- **Client password:** Derives the key protecting a client's local identity key. It is not the administrator TOTP or bootstrap TOTP.
- **Client identity:** A normal client stores its encrypted signing private key at `./client keys/auth_key` and the associated 64-byte salt at `./client keys/salt`. These paths are relative to the client's current working directory. The server signing key pin is stored at `./client keys/server_cert`.
- **Server state:** The network layer uses `./server keys/` for the server salt, administrator TOTP, bootstrap TOTP, and signing key, and `./auth keys/` for persistent enrolled-client identity records.

The current code does not accept a client identity-file path as a `TCPClient` argument. The identity location is hard-coded under `./client keys/`; see `client-README.md` for a note about the currently unused command-line path argument.

Recommended enrollment sequence:

1. Start the server and securely record its displayed server signing public key (the code calls this a server certificate).
2. From `client.py`, enter administrator mode and authenticate with the administrator TOTP.
3. Configure a separate bootstrap TOTP, add the secret to an authenticator, and verify a current code.
4. Enable bootstrap enrollment only while authorized clients are being enrolled.
5. On a new client, provide the trusted server public key when prompted, enter a strong client password, and enter a current bootstrap TOTP code when prompted.
6. Disable bootstrap enrollment as soon as enrollment is complete.

Do not obtain the server public key from an untrusted connection and blindly accept it. Verify it through a trusted channel before pasting it into the first-use prompt.

## Cryptographic flow (high level)

The code uses X448 for ephemeral key agreement (`Encryption.gen_x25519(True)`), Ed448 signing keys for the server/client identity flow (`Encryption.gen_ed25519(True)`), and AES-GCM for protected handshake and application payloads. Per-message counters and authenticated associated data bind encrypted messages to the exchange ID and direction. Receivers reject invalid or non-increasing counters.

This is a description of the implementation, not a security proof. The handshake, certificate/key pinning flow, error handling, and whole deployment model need independent review before the service is exposed to untrusted networks.

## Exchange IDs and packet flow

Exchange IDs (EIDs) are exactly 8 bytes. If no ID is supplied to `send`, the module generates one with `os.urandom(8)`. `send` returns the ID used for that exchange; callers use the same ID for `recv`.

```python
from network import TCPClient

client = TCPClient(
    host="127.0.0.1",
    port=9000,
    password="replace-with-a-strong-client-password",
)
try:
    eid = client.send(b"Hello, Crypton")
    response = client.recv(eid, timeout=5.0)
    if response is None:
        print("No response before timeout")
    else:
        print(response)
finally:
    client.close()
```

On first use, a normal `TCPClient` may prompt for a server signing key and bootstrap TOTP. The example assumes the enrollment/trust steps above have been completed. Use interactive prompts or a protected secret store instead of hard-coded credentials in real deployments.

Application payload framing is the caller's responsibility. `client.py` and `server.py` use a four-byte big-endian metadata length, JSON metadata, and an optional binary payload.

## `TCPServer` API

Current constructor:

```python
TCPServer(
    host,
    port,
    password,
    newTOTP=False,
    on_exchange=None,
    simult_exchanges=4,
)
```

- `host`, `port`: TCP bind address and port.
- `password`: Required server password used for at-rest key derivation.
- `newTOTP`: When true, regenerates the administrator TOTP secret.
- `on_exchange`: Optional callback with signature `(server, eid, data, client_id)`; `data` is decrypted application data.
- `simult_exchanges`: Worker/concurrency option passed to the native backend.

Useful methods:

| Method | Behavior |
|---|---|
| `send(payload, eid=None, client_id=None)` | Sends an encrypted message to an authenticated client. `client_id` is required. If `eid` is omitted, an 8-byte EID is generated. |
| `recv(client_id, eid, timeout=10)` | Waits for a matching exchange and returns its decrypted payload, or `None` on timeout. The Python layer caps the timeout at 10 seconds. |
| `close_client(client_id, close=True)` | Closes the backend connection (unless `close=False`) and clears session state. |
| `set_backpressure(client_id, enabled=True)` | Passes the per-client backpressure toggle to the native backend. |
| `close()` | Stops the backend and clears in-memory session state. |

The current constructor does **not** accept `auth_key_dir` or `simult_handshakes`, despite those names appearing in older documentation. Server identity records are addressed by hard-coded paths in `network.py`.

## `TCPClient` API

Current constructor:

```python
TCPClient(
    host,
    port,
    password,
    admin_auth_code=None,
    on_exchange=None,
    simult_exchanges=4,
)
```

- `host`, `port`: Server hostname/IP and TCP port.
- `password`: Required positional argument. For normal clients, it protects the local client identity at rest. In administrator mode, `client.py` passes an empty string and supplies `admin_auth_code` instead.
- `admin_auth_code`: Current administrator TOTP code when opening an administrator session; omit it for normal-client authentication.
- `on_exchange`: Optional callback with signature `(client, eid, payload)` for decrypted incoming exchanges.
- `simult_exchanges`: Worker/concurrency option passed to the native backend.

Useful methods:

- `send(payload, eid=None)` — sends a message and returns the 8-byte EID.
- `recv(eid, timeout=10)` — returns a decrypted payload or `None` on timeout. The Python layer caps finite timeouts at 10 seconds.
- `set_backpressure(enabled=True)` — toggles the client's backpressure setting in the native backend.
- `close()` — closes the backend client and clears local in-memory session-key/counter state.

Both send/receive methods validate EIDs as 8-byte `bytes` objects. Protocol, decryption, or authentication errors can raise exceptions; callers should handle them and close failed connections.

## Queues, concurrency, and backpressure

`network.py` exposes `simult_exchanges` and `set_backpressure(...)`, but the actual TCP framing, worker pools, send/receive queues, queue limits, overflow policy, and transport backpressure behavior live in the compiled `backend` extension. Those limits cannot be accurately specified from `network.py` alone. Check `backend.cpp` and `backend-README.md` before documenting numeric queue capacities, maximum pending exchanges, drop/reject behavior, or backpressure thresholds. Do not assume queues are unlimited.

## Operational/security notes

- Protect `./server keys/`, `./auth keys/`, and `./client keys/`; preserve salts alongside the encrypted material they protect.
- Do not change or delete a salt independently of the protected state. The current server initialization can reset key-state directories when stored signing/TOTP material cannot be decrypted.
- Client deauthorization removes the persistent server-side identity record. It does not necessarily terminate an already-active session; use the explicit disconnect operation for immediate termination.
- Payloads are plaintext inside client/server processes, and file contents are stored as ordinary files by `server.py`.
- Use a firewall and an independently reviewed deployment design before exposing the custom protocol to untrusted networks.
