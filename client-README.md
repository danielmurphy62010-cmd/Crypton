# Crypton Client (`client.py`)

`client.py` provides the user-facing client and remote filesystem adapters. It mounts the remote share on Windows and Linux and exposes a Python API for direct file operations. On Windows it selects `winfuse3`; on Linux it selects the project's `vfs` adapter.

> **Data handling:** Messages are encrypted while travelling through Crypton's custom protocol, but `server.py` writes file content as ordinary plaintext files in the server's shared directory. Local mount/cache behavior may also create local plaintext copies.

## Requirements

The Python components require packages including:

```bash
python -m pip install cryptography argon2-cffi blake3 zxcvbn pyotp
```

The project-local `Encryption.py`, `network.py`, and `util.py` modules and the compiled `backend` extension are required. The Linux mount also needs the project's `vfs` module and compatible FUSE packages. The Windows mount needs `winfuse3` and its filesystem dependencies. See `SETUP.md`, `network-README.md`, and `backend-README.md`.

The current entry point supports Windows and Linux; unsupported platforms raise a runtime error.

## Start the client

```bash
python client.py
```

The startup flow asks whether to authenticate as an administrator, then asks for the server host/IP. Normal-client mode requests a client password unless the optional `TPM_client` integration supplies one. On first use, Crypton asks for the server signing public key (the code calls it a server certificate). Verify that key through a trusted channel before pasting its hex representation into the prompt.

The mount point is `~/mount` on both supported platforms. Local client identity material is stored relative to the process's current working directory under `./client keys/`.

**Current implementation caveat:** `client.py` reads an optional first command-line argument into a variable named `key_path`, but that variable is not passed to `TCPClient` and does not change the identity-file location. The effective identity path remains `./client keys/auth_key`, with `./client keys/salt` and `./client keys/server_cert` alongside it. Do not rely on `python client.py ./auth_key` to select a different identity path until the source is corrected.

## First-time enrollment

A server administrator must configure enrollment before a new client can join:

1. Start `client.py` in administrator mode and enter the current administrator TOTP code.
2. In the administrator console, generate a separate bootstrap TOTP secret.
3. Add that Base32 secret to an authenticator app and verify a current code in the console.
4. Enable bootstrap enrollment for the planned enrollment window.
5. Start the new normal client, provide the trusted server public key, enter a strong client password, and supply the current `Auth Key Security Code` when prompted.
6. Disable bootstrap enrollment as soon as authorized clients have enrolled.

The administrator TOTP, bootstrap TOTP, and client password are separate credentials. Never give the administrator TOTP secret to ordinary clients. The client password protects the local client signing key at rest; the server authorizes the enrolled signing key.

The client and server both use a password-strength check through `zxcvbn`; the current helper rejects estimates at or below 9 log10 guesses. Keep passwords and identity state protected. See `network-README.md` for the authentication flow and file locations.

## Python API: generic remote storage

The generic API can be used without mounting a drive:

```python
from client import RemoteStorage

storage = RemoteStorage(
    host="192.0.2.10",  # Replace with your server's address.
    port=9000,
    password=None,       # Prompts interactively when omitted or empty.
)

print(storage.listdir("/"))
storage.write_file_from_local("./local_document.pdf", "/remote_document.pdf")
with storage.open_read("/remote_document.pdf") as remote_file:
    remote_file.seek(1024)
    sample = remote_file.read(512)

print(storage.get_size("/remote_document.pdf"))
```

The current constructor is `RemoteStorage(host="127.0.0.1", port=9000, password=None)`. It does **not** accept `key_path` or `auth_key_code_callback` arguments. Bootstrap and server-key prompts are handled by `network.TCPClient`.

Common `RemoteStorage` methods:

| Method | Purpose |
|---|---|
| `read(path)` | Reads a complete remote file into memory. |
| `read_chunk(path, offset, length=CHUNK_SIZE)` | Reads a portion of a file. |
| `write_chunk(path, offset, data)` | Writes data at a byte offset. |
| `write_file_from_local(source, destination)` | Uploads a local file through the standard chunked-write command. This is not transactional. |
| `open_read(path)` | Returns a `RemoteReader` supporting `read`, `seek`, and `tell`. |
| `listdir(path)` / `list_keys()` | Lists entries or recursively enumerates remote files. |
| `exists(path)` / `is_dir(path)` / `get_size(path)` | Queries existence, directory status, or size. |
| `get_hash(path)` | Requests a server-computed hash; may return `None` when the request does not succeed. |
| `mkdir(path)` / `make_directory(path)` | Creates a remote directory. |
| `delete(path)` | Deletes a remote path. This changes server-side data. |
| `rename(source, destination)` / `move(source, destination)` | Moves or renames a remote path. |
| `copy(source, destination)` | Copies a remote path. |
| `truncate(path, size)` | Changes a remote file's length. |
| `on(event, callback)` | Registers `read`, `write`, `delete`, or `mkdir` callbacks. |

The current server's standard `info` response does not include a modification-time field, although generic `RemoteStorage.stat()` reads one if present. As a result, the generic stat method currently falls back to a zero modification time. The Linux VFS path uses separate metadata commands.

## Linux VFS adapter and transactional upload

On Linux, the mount entry point selects `LinuxRemoteStorage`, which uses `vfs_*` requests for filesystem metadata and writes. The adapter includes a transactional upload workflow:

- It begins an upload with a destination, expected size, and BLAKE3 digest.
- It sends chunks to a server-side temporary file.
- The server checks upload completeness and content hash before commit.
- If an expected version was supplied, commit checks that the destination's version token has not changed.
- An aborted or idle upload can be cleaned up without replacing the destination file.

`LinuxRemoteStorage.write_file_from_local_if_unchanged(source, destination, expected_version)` exposes an expected-version upload. The version token used by the current server is derived from filesystem metadata, not a full historical content-version database. The generic `RemoteStorage.write_file_from_local()` API does not use this transactional flow.

Detailed cache and journal behavior also depends on the Linux `vfs` mount module, which is a separate component. Keep working-directory state and recovery files intact until pending writes are known to have committed.

## Mount behavior

- **Windows:** Uses the `winfuse3` adapter. Accessing a placeholder may hydrate content onto local storage. Deleting a mounted file can delete the remote file; do not treat mounted contents as a disposable cache directory.
- **Linux:** Uses the `vfs` adapter and FUSE. VFS commands expose filesystem metadata and transactional upload semantics. Cache implementation details should be confirmed in the `vfs` source.

The program attaches diagnostic callbacks to report reads, writes, and deletes. These messages are not a substitute for a server-side audit log or authorization enforcement.

## Administration and revocation

Run `client.py` and choose administrator mode to open the admin console. Current operations include listing registered users and active connections, checking bootstrap status, setting up/verifying bootstrap TOTP, enabling/disabling enrollment, retrieving the server signing public key, renaming a registered client, deauthorizing a client, and disconnecting an active connection.

Deauthorization removes the persistent server-side client record. It does not by itself guarantee that an already-connected session is terminated; use the disconnect action when immediate termination is required.

## Security notes and troubleshooting

- Keep the server signing public key pinned through a trusted channel; do not accept an unexpected key without verification.
- Protect local `./client keys/` files and use a strong client password.
- The server can read plaintext files in `~/Shared`. Use encrypted server storage and operating-system access controls for at-rest confidentiality.
- Do not expose the custom protocol to untrusted networks without an independent threat-model and security review.
- If connection fails, verify the IP, TCP port `9000`, server status, firewall/routing, server key pin, credentials, and that `backend` imports successfully.
- If enrollment fails, confirm bootstrap TOTP has been configured and verified, bootstrap is enabled, the code is current, and the server key shown to the client is correct.
- If the mount does not start, verify the platform's `winfuse3` or `vfs`/FUSE dependencies and review terminal output.
