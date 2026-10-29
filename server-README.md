# Crypton Server (`server.py`)

`server.py` implements the remote filesystem command handler and writes file data beneath a shared directory. It uses `network.py` for authentication and encrypted application messages and the compiled `backend` extension for TCP I/O.

> **Important:** The server decrypts incoming requests before processing them and writes file contents as ordinary files. The current implementation does not encrypt the shared directory at rest. Anyone with sufficient access to the server filesystem can read stored content.

## Requirements

```bash
python -m pip install cryptography argon2-cffi blake3 zxcvbn pyotp pybind11 setuptools
```

The project-local `Encryption.py`, `network.py`, `util.py`, and compiled `backend` extension must be available. See `SETUP.md`, `network-README.md`, and `backend-README.md`.

## Storage and paths

The shared directory is fixed by the module-level constant in `server.py`:

```python
SHARED_DIR = os.path.expanduser("~/Shared")
```

The server creates it if necessary. `FileServer` does not currently expose a supported shared-directory parameter; edit `SHARED_DIR` in the source if a different directory is required.

The current networking code stores persistent state in paths relative to the server process's working directory:

| Path | Purpose |
|---|---|
| `./server keys/SERVER SALT` | 64-byte salt used to derive the server at-rest key. |
| `./server keys/SIGNING KEY` | Server signing private key, encrypted with the derived at-rest key. |
| `./server keys/ADMIN - TOTP` | Encrypted administrator TOTP secret. |
| `./server keys/BOOTSTRAP - TOTP` | Encrypted bootstrap TOTP secret after configuration. |
| `./auth keys/` | Persistent registered-client identity records, signed by the server. |

Run the server from a stable, protected working directory so these relative paths resolve consistently. Do not move, replace, or restore a salt independently of the material it protects. The current startup code can remove and recreate the `./auth keys/` and `./server keys/` directories if the signing key or administrator TOTP material cannot be decrypted; a wrong server password or damaged state can therefore cause loss of enrolled-client state. Back up and test restoration before changing credentials or state files.

Do not put unrelated files in `./auth keys/`. The network layer treats files in that directory as registered-client records.

## Start the server

```bash
python server.py
```

The command-line entry point tries to determine a local interface address and falls back to `127.0.0.1` if detection fails. It prompts for a server password and first-run administrator TOTP setup when needed. On initial setup, securely copy the displayed Base32 administrator TOTP secret into an authenticator. The server also displays its signing public key; clients use that public key as the server trust anchor.

The default port is TCP `9000`. Use an address reachable by intended clients and configure firewall/routing rules accordingly. Binding to `127.0.0.1` allows local-only connections; binding to `0.0.0.0` exposes the listener on all local interfaces and should only be done deliberately.

Programmatic constructor:

```python
from server import FileServer

file_server = FileServer(
    host="127.0.0.1",
    port=9000,
    password="replace-with-a-strong-server-password",
)
try:
    input("Server running; press Enter to stop.\n")
finally:
    file_server.server.close()
```

The `password` argument is required. Do not pass `auth_key_dir` from older examples: `FileServer` forwards extra keyword arguments to `network.TCPServer`, whose current constructor does not accept `auth_key_dir`. The `FileServer.auth_key_dir` attribute is not the storage path used by the current `network.py` implementation.

## Administrator access and enrollment

1. Start `client.py` and choose administrator mode.
2. Enter the server address and current administrator TOTP code. If prompted, provide the server signing public key through the trusted first-use flow.
3. In the administrator console, generate a separate bootstrap TOTP secret.
4. Add the bootstrap secret to an authenticator and verify a current code.
5. Enable bootstrap enrollment while adding authorized clients.
6. Have each new client enroll using a current bootstrap TOTP code.
7. Disable bootstrap enrollment when enrollment is complete.

Keep administrator and bootstrap secrets separate. The administrator console also lists users/connections, retrieves the server public key, renames registered clients, deauthorizes clients, and disconnects active sessions. Deauthorization deletes persistent client identity state but does not necessarily close an already-open session; use disconnect for immediate session termination.

## Filesystem protocol and transfer behavior

`server.py` expects a packet containing a four-byte big-endian metadata length, UTF-8 JSON metadata, and an optional binary payload. It handles the command families below:

| Command family | Examples |
|---|---|
| Standard metadata and transfer | `list`, `info`, `download_chunk`, `upload_chunk`, `get_hash`, `truncate` |
| Standard file operations | `mkdir`, `move`, `copy`, `delete` |
| Linux VFS metadata | `vfs_stat`, `vfs_list`, `vfs_statfs`, `vfs_posix_metadata` |
| Linux VFS mutations/uploads | `vfs_mkdir`, `vfs_delete`, `vfs_move`, `vfs_begin_upload`, `vfs_upload_chunk`, `vfs_commit_upload`, `vfs_abort_upload` |
| Administration | `admin_list_connections`, `admin_list_users`, bootstrap status/setup/verification/enable/disable, server certificate/key lookup, and client rename/deauthorization/disconnect |

### Standard transfers

- The standard file chunk size is **12 MiB**.
- `upload_chunk` writes directly to the target at the requested byte offset. An interrupted standard transfer can leave a partially written file.
- `info` currently returns path, file/directory status, size, chunk size, and total chunk count. It does not currently return the modification-time field expected by generic `RemoteStorage.stat()`, so that generic API falls back to modification time `0`.
- `IO_CHUNK_SIZE` is defined as 16 MiB in the source; do not interpret it as a throughput guarantee.

### Linux VFS transactional uploads

The Linux VFS path stages a new file in a temporary file in the destination directory and supports begin/chunk/commit/abort operations. Before replacing the destination, the server checks chunk coverage, expected size, and (when supplied) the BLAKE3 content hash. It can also compare an `expected_version` token to detect a destination change during the upload.

Current VFS upload settings in `server.py` are:

| Setting | Value |
|---|---:|
| Upload idle timeout | 3,600 seconds (1 hour) |
| Maximum individual VFS upload chunk | 32 MiB |
| Standard file chunk size | 12 MiB |

The 32 MiB maximum is an implementation limit, not a recommended throughput target. An idle incomplete upload can be discarded. A version mismatch returns a conflict rather than replacing the file. The expected-version token is derived from filesystem metadata; it is not a persistent version-history database.

## Filesystem boundary and security

The `safe_path()` helper resolves requested paths relative to `~/Shared` and rejects resolved targets outside that directory. This helps prevent straightforward path traversal, but it is not a substitute for OS isolation or a security audit. Symlinks, races, concurrent path changes, and platform-specific filesystem behavior still matter.

Additional deployment protections:

- Put `~/Shared` on an encrypted volume if server-side at-rest confidentiality is required.
- Restrict filesystem permissions for the shared directory and all key/salt/TOTP state.
- Use strong, unique passwords and protect administrator/bootstrap TOTP secrets.
- Keep the listener behind a firewall; do not expose this custom protocol to untrusted networks without an independent review.
- Back up file data and the Crypton key/salt/TOTP state together, and test the restore procedure.

## Troubleshooting

**Server does not start:** Check Python dependencies, confirm `backend` imports, verify the port is free, and confirm the current working directory permits access to `./auth keys/` and `./server keys/`.

**Client cannot connect:** Verify the bind address, TCP port `9000`, firewall/routing, server process, and native `backend` extension.

**Administrator login fails:** Verify the administrator TOTP secret and device time. A server state reset or regenerated TOTP invalidates the previous authenticator secret.

**Bootstrap enrollment fails:** Confirm bootstrap TOTP is configured and verified, enrollment is enabled, the code is current, and the client has the correct server signing public key.

**A deauthorized client remains connected:** Persistent deauthorization does not guarantee termination of an existing session. Disconnect that connection separately.
