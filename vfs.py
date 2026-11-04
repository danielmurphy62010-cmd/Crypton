from __future__ import annotations
import errno, blake3, json, logging, os, posixpath, shutil, sqlite3, stat, tempfile, threading, time, uuid
from dataclasses import dataclass
from typing import BinaryIO, Optional
if os.name != "posix":raise RuntimeError("This program requires a POSIX operating system.")
try:from fuse import FUSE, Operations, FuseOSError
except ImportError as exc:raise RuntimeError("The 'fusepy' package and the system FUSE library are required. Install fusepy and your distribution's FUSE package first.") from exc
CHUNK_SIZE = 64 * 1024 * 1024
CACHE_TTL = 60 * 2
CACHE_SWEEP_INTERVAL = 1
CACHE_DIR = "./cache"
BACKING_DIR = "./storage"
MOUNT_DIR = "./mount"
DB_PATH = "./cache_meta.db"
JOURNAL_PATH = "./sync_journal.db"
REFRESH_INTERVAL = 5
HASH_BATCH_DIVISOR = 5
HASH_MAX_INTERVAL = 30
WORKING_PREFIX = ".vfs-working-"
logging.basicConfig(level=logging.INFO,format="%(asctime)s [%(levelname)s] %(message)s",datefmt="%H:%M:%S",)
logger = logging.getLogger("VFS")
@dataclass(frozen=True)
class BackingStat:
    is_directory: bool
    size: int
    creation_time: float
    access_time: float
    modified_time: float
class BackingStore:
    def initialize(self):pass
    def listdir(self, relative_path):raise NotImplementedError
    def stat(self, relative_path) -> BackingStat:raise NotImplementedError
    def open_read(self, relative_path) -> BinaryIO:raise NotImplementedError
    def write_file_from_local(self, source_path, relative_path):raise NotImplementedError
    def make_directory(self, relative_path):raise NotImplementedError
    def lexists(self, relative_path):raise NotImplementedError
    def delete(self, relative_path, is_directory):raise NotImplementedError
    def move(self, source_relative_path, destination_relative_path):raise NotImplementedError
    def get_hash(self, relative_path):return None
    def describe(self):return type(self).__name__
    def get_posix_metadata(self, relative_path):return None
    def set_metadata(self, relative_path, *, mode=None, uid=None, gid=None,atime=None, mtime=None):return False
    def write_file_from_local_if_unchanged(self, source_path, relative_path,expected_version):return None
    def statfs(self, relative_path=""):return None
TEMPORARY_NAME_PARTS = (".tmp", ".crdownload", ".part", ".download", ".temp", ".bak", ".vfs-tmp-")
MISSING_VERSION = "<VFS-MISSING>"
def is_temporary_file(path: str) -> bool:
    name = posixpath.basename(str(path)).lower()
    return any(part in name for part in TEMPORARY_NAME_PARTS) or "~" in name
def clean_backend_path(path: str) -> str:
    if path is None:raise ValueError("Path cannot be None")
    path = str(path)
    if "\x00" in path:raise ValueError("NUL byte in path")
    path = path.lstrip("/")
    parts = path.split("/") if path else []
    if any(part == ".." for part in parts):raise PermissionError(errno.EACCES, "Path escapes the VFS root", path)
    parts = [part for part in parts if part not in ("", ".")]
    return "/".join(parts)
def join_backend_path(parent: str, child: str) -> str:return child if not parent else f"{parent}/{child}"
def _version_token(st: BackingStat) -> str:return json.dumps([bool(st.is_directory),int(st.size),round(float(st.creation_time), 9),round(float(st.modified_time), 9),], separators=(",", ":"))
def _get_version(backend: BackingStore, relative_path: str) -> str:
    try:return _version_token(backend.stat(relative_path))
    except FileNotFoundError:return MISSING_VERSION
    except OSError as exc:
        if exc.errno == errno.ENOENT:return MISSING_VERSION
        raise
def _blake3_file(path: str) -> str:
    hasher = blake3.blake3()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):hasher.update(block)
    return hasher.digest(64)
def _blake3_stream(stream: BinaryIO) -> str:
    hasher = blake3.blake3()
    while True:
        block = stream.read(4 * 1024 * 1024)
        if not block:break
        hasher.update(block)
    return hasher.digest(64)
def _errno_for_exception(exc: BaseException) -> int:
    if isinstance(exc, FuseOSError):return getattr(exc, "errno", errno.EIO) or errno.EIO
    if isinstance(exc, OSError) and exc.errno:return exc.errno
    if isinstance(exc, FileNotFoundError):return errno.ENOENT
    if isinstance(exc, FileExistsError):return errno.EEXIST
    if isinstance(exc, IsADirectoryError):return errno.EISDIR
    if isinstance(exc, NotADirectoryError):return errno.ENOTDIR
    if isinstance(exc, PermissionError):return errno.EACCES
    return errno.EIO
def _raise_fuse_error(exc: BaseException):
    if isinstance(exc, FuseOSError):raise exc
    raise FuseOSError(_errno_for_exception(exc)) from exc
class CacheManager:
    def __init__(self, db_path=DB_PATH, cache_dir=CACHE_DIR,chunk_size=CHUNK_SIZE, ttl=CACHE_TTL):
        self.db_path = os.path.abspath(db_path)
        self.cache_dir = os.path.abspath(cache_dir)
        self.chunk_size = int(chunk_size)
        self.ttl = float(ttl)
        if self.chunk_size <= 0:raise ValueError("chunk_size must be positive")
        if self.ttl <= 0:raise ValueError("ttl must be positive")
        os.makedirs(self.cache_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._lock = threading.RLock()
        self._key_locks_guard = threading.Lock()
        self._key_locks = {}
        self._stop_event = threading.Event()
        self._sweeper = None
        self._initialize_db()
        with self._lock:self._purge_expired_locked(time.time())
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        return conn
    def _initialize_db(self):
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                table = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chunks'").fetchone()
                if table:
                    columns = {row[1] for row in conn.execute("PRAGMA table_info(chunks)")}
                    required = {"cache_filename", "backing_path", "chunk_index", "version", "byte_length", "last_accessed"}
                    if not required.issubset(columns):
                        old_names = [row[0] for row in conn.execute("SELECT cache_filename FROM chunks")]
                        for filename in old_names:
                            try:os.remove(os.path.join(self.cache_dir, filename))
                            except OSError:pass
                        conn.execute("DROP TABLE chunks")
                conn.execute("CREATE TABLE IF NOT EXISTS chunks (cache_filename TEXT PRIMARY KEY,backing_path TEXT NOT NULL,chunk_index INTEGER NOT NULL,version TEXT NOT NULL,byte_length INTEGER NOT NULL,last_accessed REAL NOT NULL)")
                duplicates = conn.execute("SELECT backing_path, chunk_index FROM chunks GROUP BY backing_path, chunk_index HAVING COUNT(*) > 1").fetchall()
                for backing_path, chunk_index in duplicates:
                    names = conn.execute("SELECT cache_filename FROM chunks WHERE backing_path=? AND chunk_index=? ORDER BY last_accessed DESC", (backing_path, chunk_index)).fetchall()
                    for (filename,) in names[1:]:
                        try:os.remove(os.path.join(self.cache_dir, filename))
                        except OSError:pass
                        conn.execute("DELETE FROM chunks WHERE cache_filename=?", (filename,))
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_chunks_path_index ON chunks(backing_path, chunk_index)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_chunks_last_accessed ON chunks(last_accessed)")
                conn.commit()
            finally:conn.close()
    @staticmethod
    def _new_cache_filename():return uuid.uuid4().hex + ".chunk"
    def _key_lock(self, backing_path, chunk_index):
        key = (backing_path, int(chunk_index))
        with self._key_locks_guard:
            lock = self._key_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[key] = lock
            return lock
    def _remove_row_locked(self, conn, cache_filename):
        cache_path = os.path.join(self.cache_dir, cache_filename)
        try:os.remove(cache_path)
        except FileNotFoundError:pass
        except OSError as exc:logger.warning("Could not remove cached chunk %s: %s", cache_path, exc)
        conn.execute("DELETE FROM chunks WHERE cache_filename = ?", (cache_filename,))
    def _purge_expired_locked(self, now):
        threshold = now - self.ttl
        conn = self._connect()
        try:
            rows = conn.execute("SELECT cache_filename FROM chunks WHERE last_accessed <= ?",(threshold,),).fetchall()
            for (filename,) in rows:self._remove_row_locked(conn, filename)
            conn.commit()
        finally:conn.close()
        if rows:logger.debug("Dehydrated %d idle cache chunk(s)", len(rows))
    def purge_expired(self):
        with self._lock:self._purge_expired_locked(time.time())
    def start(self):
        if self._sweeper is not None and self._sweeper.is_alive():return
        self._stop_event.clear()
        def worker():
            while not self._stop_event.wait(CACHE_SWEEP_INTERVAL):
                try:self.purge_expired()
                except Exception:logger.exception("Cache dehydration pass failed")
        self._sweeper = threading.Thread(target=worker, name="VFSCacheDehydrator", daemon=True)
        self._sweeper.start()
    def stop(self):
        self._stop_event.set()
        if self._sweeper is not None:
            self._sweeper.join(timeout=3)
            self._sweeper = None
    def _lookup_cached_chunk(self, backing_path, chunk_index, version):
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT cache_filename, version FROM chunks WHERE backing_path = ? AND chunk_index = ?",(backing_path, int(chunk_index)),).fetchone()
                if row is None:return None
                filename, saved_version = row
                cache_path = os.path.join(self.cache_dir, filename)
                if saved_version != version or not os.path.isfile(cache_path):
                    self._remove_row_locked(conn, filename)
                    conn.commit()
                    return None
                try:
                    with open(cache_path, "rb") as stream:data = stream.read()
                except FileNotFoundError:
                    self._remove_row_locked(conn, filename)
                    conn.commit()
                    return None
                conn.execute("UPDATE chunks SET last_accessed = ? WHERE cache_filename = ?",(time.time(), filename),)
                conn.commit()
                return data
            finally:conn.close()
    def _store_chunk(self, backing_path, chunk_index, version, data):
        filename = self._new_cache_filename()
        final_path = os.path.join(self.cache_dir, filename)
        temp_path = final_path + ".tmp"
        try:
            with open(temp_path, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, final_path)
            with self._lock:
                conn = self._connect()
                try:
                    old = conn.execute("SELECT cache_filename FROM chunks WHERE backing_path = ? AND chunk_index = ?",(backing_path, int(chunk_index)),).fetchone()
                    if old:self._remove_row_locked(conn, old[0])
                    conn.execute("INSERT OR REPLACE INTO chunks (cache_filename, backing_path, chunk_index, version, byte_length, last_accessed) VALUES (?, ?, ?, ?, ?, ?)",(filename, backing_path, int(chunk_index), version,len(data), time.time()),)
                    conn.commit()
                finally:conn.close()
        finally:
            try:os.remove(temp_path)
            except FileNotFoundError:pass
    def read_chunk(self, backend: BackingStore, backing_path: str,chunk_index: int, snapshot: BackingStat) -> bytes:
        if snapshot.is_directory:raise IsADirectoryError(backing_path)
        chunk_index = int(chunk_index)
        if chunk_index < 0:raise ValueError("Negative chunk index")
        start = chunk_index * self.chunk_size
        if start >= snapshot.size:return b""
        expected_length = min(self.chunk_size, snapshot.size - start)
        version = _version_token(snapshot)
        key_lock = self._key_lock(backing_path, chunk_index)
        with key_lock:
            cached = self._lookup_cached_chunk(backing_path, chunk_index, version)
            if cached is not None and len(cached) == expected_length:return cached
            if cached is not None:
                self.invalidate_chunk(backing_path, chunk_index)
            for attempt in range(2):
                before = backend.stat(backing_path)
                before_version = _version_token(before)
                if before.is_directory:raise IsADirectoryError(backing_path)
                if start >= before.size:return b""
                want = min(self.chunk_size, before.size - start)
                with backend.open_read(backing_path) as stream:
                    stream.seek(start)
                    data = stream.read(want)
                after = backend.stat(backing_path)
                if _version_token(after) != before_version:
                    snapshot = after
                    start = chunk_index * self.chunk_size
                    continue
                if len(data) != want:raise OSError(errno.EIO,f"Short backing read for {backing_path!r}: wanted {want}, got {len(data)}")
                self._store_chunk(backing_path, chunk_index, before_version, data)
                return data
            raise OSError(errno.EBUSY, f"Backing file changed repeatedly while reading {backing_path!r}")
    def invalidate_chunk(self, backing_path, chunk_index):
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT cache_filename FROM chunks WHERE backing_path = ? AND chunk_index = ?",(backing_path, int(chunk_index)),).fetchone()
                if row:self._remove_row_locked(conn, row[0])
                conn.commit()
            finally:conn.close()
    def delete_file_chunks(self, backing_path, include_descendants=False):
        backing_path = clean_backend_path(backing_path)
        with self._lock:
            conn = self._connect()
            try:
                if include_descendants:
                    rows = conn.execute("SELECT cache_filename, backing_path FROM chunks").fetchall()
                    targets = [name for name, path in rows if path == backing_path or path.startswith(backing_path + "/")]
                else:
                    rows = conn.execute("SELECT cache_filename FROM chunks WHERE backing_path = ?",(backing_path,),).fetchall()
                    targets = [row[0] for row in rows]
                for filename in targets:self._remove_row_locked(conn, filename)
                conn.commit()
            finally:conn.close()
class SyncJournal:
    def __init__(self, path=JOURNAL_PATH):
        self.path = os.path.abspath(path)
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._lock = threading.RLock()
        self._db = None
    def initialize(self):
        with self._lock:
            self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
            self._db.execute("PRAGMA busy_timeout=30000")
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("CREATE TABLE IF NOT EXISTS operations (id INTEGER PRIMARY KEY AUTOINCREMENT,operation TEXT NOT NULL,source_path TEXT,destination_path TEXT,backend_path TEXT,is_directory INTEGER NOT NULL DEFAULT 0,created_at REAL NOT NULL,expected_version TEXT,target_hash TEXT)")
            existing = {row[1] for row in self._db.execute("PRAGMA table_info(operations)")}
            for name, definition in (("expected_version", "TEXT"),("target_hash", "TEXT"),):
                if name not in existing:self._db.execute(f"ALTER TABLE operations ADD COLUMN {name} {definition}")
            self._db.execute("CREATE TABLE IF NOT EXISTS file_hashes (backend_path TEXT PRIMARY KEY,hash TEXT,version TEXT,last_check REAL,next_check REAL,unchanged_checks INTEGER NOT NULL DEFAULT 0)")
            cols = {row[1] for row in self._db.execute("PRAGMA table_info(file_hashes)")}
            if "version" not in cols:self._db.execute("ALTER TABLE file_hashes ADD COLUMN version TEXT")
            if "next_check" not in cols:self._db.execute("ALTER TABLE file_hashes ADD COLUMN next_check REAL")
            if "unchanged_checks" not in cols:self._db.execute("ALTER TABLE file_hashes ADD COLUMN unchanged_checks INTEGER NOT NULL DEFAULT 0")
            self._db.execute("UPDATE file_hashes SET next_check = COALESCE(next_check, last_check, 0)")
            self._db.commit()
    def add(self, operation, source_path=None, destination_path=None,backend_path=None, is_directory=False, expected_version=None,target_hash=None):
        with self._lock:
            cur = self._db.execute("INSERT INTO operations (operation, source_path, destination_path, backend_path, is_directory, created_at, expected_version, target_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",(operation, source_path, destination_path, backend_path,int(is_directory), time.time(), expected_version, target_hash),)
            self._db.commit()
            return cur.lastrowid
    def remove(self, operation_id):
        with self._lock:
            self._db.execute("DELETE FROM operations WHERE id = ?", (operation_id,))
            self._db.commit()
    def update_operation_source(self, operation_id, source_path):
        with self._lock:
            self._db.execute("UPDATE operations SET source_path = ? WHERE id = ?",(source_path, operation_id))
            self._db.commit()
    def pending(self):
        with self._lock:rows = self._db.execute("SELECT id, operation, source_path, destination_path, backend_path, is_directory, expected_version, target_hash FROM operations ORDER BY id").fetchall()
        return [{"id": row[0], "operation": row[1], "source_path": row[2],"destination_path": row[3], "backend_path": row[4],"is_directory": bool(row[5]), "expected_version": row[6],"target_hash": row[7],} for row in rows]
    def get_file_hash_state(self, backend_path):
        backend_path = clean_backend_path(backend_path)
        with self._lock:row = self._db.execute("SELECT hash, version, last_check, next_check, unchanged_checks FROM file_hashes WHERE backend_path = ?", (backend_path,)).fetchone()
        if row is None:return None
        return {"hash": row[0], "version": row[1], "last_check": row[2],"next_check": row[3], "unchanged_checks": row[4]}
    def set_file_hash_state(self, backend_path, file_hash, version,last_check, next_check, unchanged_checks):
        backend_path = clean_backend_path(backend_path)
        with self._lock:
            self._db.execute("INSERT INTO file_hashes (backend_path, hash, version, last_check, next_check, unchanged_checks) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(backend_path) DO UPDATE SET hash=excluded.hash, version=excluded.version, last_check=excluded.last_check, next_check=excluded.next_check, unchanged_checks=excluded.unchanged_checks",(backend_path, file_hash, version, last_check, next_check, unchanged_checks),)
            self._db.commit()
    def schedule_file_check(self, backend_path, next_check, unchanged_checks=None):
        backend_path = clean_backend_path(backend_path)
        with self._lock:
            if unchanged_checks is None:self._db.execute("UPDATE file_hashes SET next_check = ? WHERE backend_path = ?",(next_check, backend_path),)
            else:self._db.execute("UPDATE file_hashes SET next_check = ?, unchanged_checks = ? WHERE backend_path = ?",(next_check, unchanged_checks, backend_path),)
            self._db.commit()
    def delete_file_hash_state(self, backend_path, include_descendants=False):
        backend_path = clean_backend_path(backend_path)
        with self._lock:
            if include_descendants:
                rows = self._db.execute("SELECT backend_path FROM file_hashes").fetchall()
                targets = [r[0] for r in rows if r[0] == backend_path or r[0].startswith(backend_path + "/")]
                self._db.executemany("DELETE FROM file_hashes WHERE backend_path = ?",[(p,) for p in targets])
            else:self._db.execute("DELETE FROM file_hashes WHERE backend_path = ?", (backend_path,))
            self._db.commit()
    def get_all_file_hashes(self):
        with self._lock:rows = self._db.execute("SELECT backend_path FROM file_hashes").fetchall()
        return [row[0] for row in rows]
    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
class _OpenFileState:
    def __init__(self, path: str, version: str):
        self.path = path
        self.version = version
        self.working_path: Optional[str] = None
        self.dirty = False
        self.detached = False
        self.refs = 0
        self.pending_operation_id = None
        self.lock = threading.RLock()
class StorageVFS(Operations):
    def __init__(self, backing_store: BackingStore, mount_dir: str,cache_manager: Optional[CacheManager] = None,journal: Optional[SyncJournal] = None,refresh_interval: float = REFRESH_INTERVAL):
        self.backing_store = backing_store
        self.mount_dir = os.path.abspath(mount_dir)
        self.cache_mgr = cache_manager or CacheManager()
        self.journal = journal or SyncJournal()
        self.refresh_interval = max(1.0, float(refresh_interval))
        self._state_lock = threading.RLock()
        self._namespace_lock = threading.RLock()
        self._states = {}
        self._handles = {}
        self._handle_flags = {}
        self._handle_baselines = {}
        self._next_fh = 1
        self._refresh_stop = threading.Event()
        self._refresh_thread = None
    def start(self):
        self.cache_mgr.start()
        self._refresh_stop.clear()
        self._refresh_thread = threading.Thread(target=self._refresh_worker, name="VFSRemoteRefresh", daemon=True)
        self._refresh_thread.start()
    def stop(self):
        self._refresh_stop.set()
        if self._refresh_thread is not None:
            self._refresh_thread.join(timeout=3)
            self._refresh_thread = None
        self.cache_mgr.stop()
    def _path(self, path):return clean_backend_path(path)
    def _state_for_path(self, rel_path):
        with self._state_lock:return self._states.get(rel_path)
    def _state_for_handle(self, fh):
        if fh is None:return None
        with self._state_lock:return self._handles.get(fh)
    def _alloc_handle(self, state, flags):
        with self._state_lock:
            fh = self._next_fh
            self._next_fh += 1
            self._handles[fh] = state
            self._handle_flags[fh] = int(flags)
            self._handle_baselines[fh] = state.version
            state.refs += 1
            return fh
    def _all_handles_for_state(self, state):
        with self._state_lock:return [fh for fh, item in self._handles.items() if item is state]
    def _optional_posix_metadata(self, rel_path):
        hook = getattr(self.backing_store, "get_posix_metadata", None)
        if hook is not None:
            try:
                value = hook(rel_path)
                if value:return value
            except (NotImplementedError, OSError):pass
        return {}
    def _make_stat_dict(self, rel_path, st: BackingStat, working_path=None):
        extra = self._optional_posix_metadata(rel_path)
        if working_path and os.path.isfile(working_path):
            local = os.stat(working_path)
            size = local.st_size
            mtime = local.st_mtime
            atime = local.st_atime
        else:
            size = 0 if st.is_directory else int(st.size)
            mtime = float(st.modified_time)
            atime = float(st.access_time)
        is_dir = bool(st.is_directory)
        default_mode = (stat.S_IFDIR | 0o755) if is_dir else (stat.S_IFREG | 0o644)
        mode = int(extra.get("st_mode", default_mode))
        result = {"st_mode": mode,"st_nlink": int(extra.get("st_nlink", 2 if is_dir else 1)),"st_size": int(size),"st_ctime": float(extra.get("st_ctime", st.creation_time)),"st_mtime": float(mtime if working_path else extra.get("st_mtime", mtime)),"st_atime": float(atime if working_path else extra.get("st_atime", atime)),"st_uid": int(extra.get("st_uid", os.getuid() if hasattr(os, "getuid") else 0)),"st_gid": int(extra.get("st_gid", os.getgid() if hasattr(os, "getgid") else 0)),"st_ino": int(extra.get("st_ino", 0)),"st_dev": int(extra.get("st_dev", 0)),"st_blocks": int(extra.get("st_blocks", (size + 511) // 512)),"st_blksize": int(extra.get("st_blksize", 4096)),}
        return result
    def _stat(self, rel_path):
        try:return self.backing_store.stat(rel_path)
        except Exception as exc:_raise_fuse_error(exc)
    def _ensure_parent_directory(self, rel_path):
        parent = posixpath.dirname(rel_path)
        try:parent_st = self.backing_store.stat(parent)
        except Exception as exc:_raise_fuse_error(exc)
        if not parent_st.is_directory:raise FuseOSError(errno.ENOTDIR)
    def _new_working_file(self):
        fd, path = tempfile.mkstemp(prefix=WORKING_PREFIX, dir=self.cache_mgr.cache_dir)
        os.close(fd)
        return path
    def _hydrate_working_file(self, state: _OpenFileState, expected_version: str):
        st = self._stat(state.path)
        if st.is_directory:raise FuseOSError(errno.EISDIR)
        start_version = _version_token(st)
        if expected_version != start_version:raise FuseOSError(errno.EBUSY)
        working_path = self._new_working_file()
        try:
            with open(working_path, "wb") as output:
                chunk_count = (int(st.size) + self.cache_mgr.chunk_size - 1) // self.cache_mgr.chunk_size
                for index in range(chunk_count):
                    data = self.cache_mgr.read_chunk(self.backing_store, state.path, index, st)
                    expected = min(self.cache_mgr.chunk_size,max(0, int(st.size) - index * self.cache_mgr.chunk_size))
                    if len(data) != expected:raise OSError(errno.EIO, f"Short chunk while staging {state.path!r}")
                    output.write(data)
                output.flush()
                os.fsync(output.fileno())
            metadata = self._optional_posix_metadata(state.path)
            original_mode = metadata.get("st_mode") if metadata else None
            if original_mode is not None:os.chmod(working_path, stat.S_IMODE(int(original_mode)))
            after = self._stat(state.path)
            if _version_token(after) != start_version:raise FuseOSError(errno.EBUSY)
            state.working_path = working_path
            return working_path
        except Exception:
            try:os.remove(working_path)
            except OSError:pass
            raise
    def _write_backend_conditionally(self, source_path, rel_path, expected_version):
        hook = getattr(self.backing_store, "write_file_from_local_if_unchanged", None)
        hook_overridden = (hook is not None and type(self.backing_store).write_file_from_local_if_unchanged is not BackingStore.write_file_from_local_if_unchanged)
        if hook_overridden:
            result = hook(source_path, rel_path, expected_version)
            if result is True:return
            if result is False:raise FuseOSError(errno.EBUSY)
        current = _get_version(self.backing_store, rel_path)
        if current != expected_version:raise FuseOSError(errno.EBUSY)
        self.backing_store.write_file_from_local(source_path, rel_path)
    def _commit_state(self, state: _OpenFileState):
        with state.lock:
            if state.detached or not state.dirty:return
            if not state.working_path or not os.path.isfile(state.working_path):raise FuseOSError(errno.EIO)
            rel_path = state.path
            expected_version = state.version
            current_version = _get_version(self.backing_store, rel_path)
            if current_version != expected_version:raise FuseOSError(errno.EBUSY)
            target_hash = _blake3_file(state.working_path)
            if state.pending_operation_id is None:state.pending_operation_id = self.journal.add("write", source_path=state.working_path,backend_path=rel_path, expected_version=expected_version,target_hash=target_hash,)
            else:self.journal.update_operation_source(state.pending_operation_id, state.working_path)
            try:
                self._write_backend_conditionally(state.working_path, rel_path, expected_version)
                saved = self._stat(rel_path)
                if saved.is_directory or int(saved.size) != os.path.getsize(state.working_path):raise OSError(errno.EIO, f"Backing write verification failed for {rel_path!r}")
                self.journal.remove(state.pending_operation_id)
                state.pending_operation_id = None
                self.cache_mgr.delete_file_chunks(rel_path)
                new_version = _version_token(saved)
                state.version = new_version
                with self._state_lock:
                    for fh, item in self._handles.items():
                        if item is state:self._handle_baselines[fh] = new_version
                old_working = state.working_path
                state.working_path = None
                state.dirty = False
                try:os.remove(old_working)
                except OSError:logger.warning("Could not remove committed working file %s", old_working)
                self.journal.set_file_hash_state(rel_path, None, new_version, time.time(), time.time(), 0)
            except Exception:raise
    def _preserve_recovery_file(self, state: _OpenFileState):
        if not state.working_path or not os.path.exists(state.working_path):return None
        recovery_dir = os.path.join(self.cache_mgr.cache_dir, "recovery")
        os.makedirs(recovery_dir, exist_ok=True)
        name = posixpath.basename(state.path) or "root"
        safe_name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
        target = os.path.join(recovery_dir, f"{safe_name}.{int(time.time())}.{uuid.uuid4().hex[:8]}.conflict")
        try:
            shutil.move(state.working_path, target)
            if state.pending_operation_id is not None:
                self.journal.remove(state.pending_operation_id)
                state.pending_operation_id = None
            state.working_path = None
            state.dirty = False
            logger.error("Uncommitted data for %s was preserved at %s because it could not be committed",state.path, target,)
            return target
        except Exception:
            logger.exception("Failed to preserve uncommitted data for %s", state.path)
            return None
    def _begin_detach_state(self, rel_path, state):
        with state.lock:
            if state.working_path is None:
                state.version = _version_token(self._stat(rel_path))
                self._hydrate_working_file(state, state.version)
            state.detached = True
            with self._state_lock:
                if self._states.get(rel_path) is state:self._states.pop(rel_path, None)
    def _cleanup_state_if_unused(self, state):
        with self._state_lock:
            if state.refs > 0:return
            if self._states.get(state.path) is state:self._states.pop(state.path, None)
        if state.detached:
            if state.working_path:
                try:os.remove(state.working_path)
                except OSError:pass
                state.working_path = None
            return
        if state.dirty:self._preserve_recovery_file(state)
        elif state.working_path:
            try:os.remove(state.working_path)
            except OSError:pass
            state.working_path = None
    def _run_journaled(self, operation, *, backend_path=None,source_path=None, destination_path=None,is_directory=False, expected_version=None, target_hash=None,callback):
        operation_id = self.journal.add(operation, source_path=source_path,destination_path=destination_path, backend_path=backend_path,is_directory=is_directory, expected_version=expected_version,target_hash=target_hash,)
        callback()
        self.journal.remove(operation_id)
    def _get_or_create_empty_file(self, rel_path, mode):
        self._ensure_parent_directory(rel_path)
        temp_path = self._new_working_file()
        try:
            with open(temp_path, "wb"):pass
            expected = _get_version(self.backing_store, rel_path)
            if expected != MISSING_VERSION:raise FuseOSError(errno.EEXIST)
            target_hash = _blake3_file(temp_path)
            op_id = self.journal.add("write", source_path=temp_path, backend_path=rel_path,expected_version=MISSING_VERSION, target_hash=target_hash,)
            try:
                self._write_backend_conditionally(temp_path, rel_path, MISSING_VERSION)
                self.journal.remove(op_id)
            except Exception:raise
            metadata_hook = getattr(self.backing_store, "set_metadata", None)
            if metadata_hook is not None:
                try:metadata_hook(rel_path, mode=mode)
                except (OSError, NotImplementedError):pass
        finally:
            try:os.remove(temp_path)
            except OSError:pass
    def access(self, path, mode):
        rel_path = self._path(path)
        try:
            st = self._stat(rel_path)
            metadata = self._make_stat_dict(rel_path, st)
            file_mode = metadata["st_mode"]
            if not mode:return 0
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                if mode & os.X_OK and not (file_mode & 0o111):raise FuseOSError(errno.EACCES)
                return 0
            uid = metadata["st_uid"]
            gid = metadata["st_gid"]
            euid = os.geteuid() if hasattr(os, "geteuid") else uid
            egid = os.getegid() if hasattr(os, "getegid") else gid
            if euid == uid:bits = (file_mode >> 6) & 7
            elif egid == gid:bits = (file_mode >> 3) & 7
            else:bits = file_mode & 7
            requested = (4 if mode & os.R_OK else 0) | (2 if mode & os.W_OK else 0) | (1 if mode & os.X_OK else 0)
            if requested & ~bits:raise FuseOSError(errno.EACCES)
            return 0
        except Exception as exc:_raise_fuse_error(exc)
    def getattr(self, path, fh=None):
        rel_path = self._path(path)
        handle_state = self._state_for_handle(fh)
        state = handle_state or self._state_for_path(rel_path)
        if handle_state is not None:rel_path = handle_state.path
        try:
            if state is not None and state.working_path and (state.dirty or state.detached):
                try:backend_st = self.backing_store.stat(rel_path)
                except OSError:backend_st = BackingStat(False, os.path.getsize(state.working_path),os.path.getctime(state.working_path),os.path.getatime(state.working_path),os.path.getmtime(state.working_path))
                return self._make_stat_dict(rel_path, backend_st, state.working_path)
            st = self._stat(rel_path)
            working = state.working_path if state is not None and state.working_path else None
            return self._make_stat_dict(rel_path, st, working)
        except Exception as exc:_raise_fuse_error(exc)
    def readdir(self, path, fh):
        rel_path = self._path(path)
        try:
            st = self._stat(rel_path)
            if not st.is_directory:raise FuseOSError(errno.ENOTDIR)
            names = self.backing_store.listdir(rel_path)
            return [".", ".."] + sorted(name for name in names if not is_temporary_file(name))
        except Exception as exc:_raise_fuse_error(exc)
    def statfs(self, path):
        rel_path = self._path(path)
        try:
            hook = getattr(self.backing_store, "statfs", None)
            value = hook(rel_path) if hook is not None else None
            if value:return value
            stv = os.statvfs(self.cache_mgr.cache_dir)
            return {key: getattr(stv, key) for key in ("f_bavail", "f_bfree", "f_blocks", "f_bsize", "f_favail","f_ffree", "f_files", "f_flag", "f_frsize", "f_namemax")}
        except Exception as exc:_raise_fuse_error(exc)
    def open(self, path, flags):
        rel_path = self._path(path)
        try:
            with self._namespace_lock:
                st = self._stat(rel_path)
                if st.is_directory:raise FuseOSError(errno.EISDIR)
                if flags & os.O_TRUNC:
                    self.truncate(path, 0)
                    st = self._stat(rel_path)
                version = _version_token(st)
                with self._state_lock:
                    state = self._states.get(rel_path)
                    if state is None:
                        state = _OpenFileState(rel_path, version)
                        self._states[rel_path] = state
                with state.lock:
                    if not state.dirty and not state.detached and state.version != version:
                        state.version = version
                        self.cache_mgr.delete_file_chunks(rel_path)
                return self._alloc_handle(state, flags)
        except Exception as exc:_raise_fuse_error(exc)
    def create(self, path, mode, fi=None):
        rel_path = self._path(path)
        try:
            with self._namespace_lock:
                self._get_or_create_empty_file(rel_path, mode)
                st = self._stat(rel_path)
                with self._state_lock:previous = self._states.get(rel_path)
                if previous is not None:
                    with previous.lock:
                        if previous.dirty:raise FuseOSError(errno.EBUSY)
                state = _OpenFileState(rel_path, _version_token(st))
                with self._state_lock:self._states[rel_path] = state
                if isinstance(fi, dict):flags = fi.get("flags", os.O_RDWR)
                else:flags = getattr(fi, "flags", os.O_RDWR) if fi is not None else os.O_RDWR
                return self._alloc_handle(state, flags)
        except Exception as exc:_raise_fuse_error(exc)
    def read(self, path, size, offset, fh):
        rel_path = self._path(path)
        if size <= 0:return b""
        if offset < 0:raise FuseOSError(errno.EINVAL)
        state = self._state_for_handle(fh) or self._state_for_path(rel_path)
        try:
            if state is not None:
                with state.lock:
                    if state.working_path and os.path.isfile(state.working_path):
                        with open(state.working_path, "rb") as stream:
                            stream.seek(offset)
                            return stream.read(size)
                    rel_path = state.path
            st = self._stat(rel_path)
            if st.is_directory:raise FuseOSError(errno.EISDIR)
            if offset >= st.size:return b""
            amount = min(int(size), int(st.size) - int(offset))
            end = offset + amount
            first = offset // self.cache_mgr.chunk_size
            last = (end - 1) // self.cache_mgr.chunk_size
            output = bytearray()
            for index in range(first, last + 1):
                chunk = self.cache_mgr.read_chunk(self.backing_store, rel_path, index, st)
                chunk_start = index * self.cache_mgr.chunk_size
                inner_start = max(0, offset - chunk_start)
                inner_end = min(len(chunk), end - chunk_start)
                if inner_end <= inner_start:continue
                output.extend(chunk[inner_start:inner_end])
            return bytes(output)
        except Exception as exc:_raise_fuse_error(exc)
    def write(self, path, data, offset, fh):
        rel_path = self._path(path)
        if offset < 0:raise FuseOSError(errno.EINVAL)
        if not data:return 0
        state = self._state_for_handle(fh)
        if state is None:
            st = self._stat(rel_path)
            state = _OpenFileState(rel_path, _version_token(st))
            with self._state_lock:self._states.setdefault(rel_path, state)
        flags = 0
        with self._state_lock:
            if fh in self._handle_flags:flags = self._handle_flags[fh]
        try:
            with state.lock:
                if state.detached:
                    if state.working_path is None:raise FuseOSError(errno.EIO)
                elif not state.dirty:
                    current = _get_version(self.backing_store, state.path)
                    with self._state_lock:baseline = self._handle_baselines.get(fh, state.version)
                    if current != baseline:raise FuseOSError(errno.EBUSY)
                    state.version = current
                    self._hydrate_working_file(state, current)
                if state.working_path is None:raise FuseOSError(errno.EIO)
                with open(state.working_path, "r+b") as stream:
                    if flags & os.O_APPEND:stream.seek(0, os.SEEK_END)
                    else:stream.seek(offset)
                    stream.write(data)
                    stream.flush()
                if not state.detached:state.dirty = True
                return len(data)
        except Exception as exc:_raise_fuse_error(exc)
    def flush(self, path, fh):
        state = self._state_for_handle(fh)
        if state is None:return 0
        try:
            self._commit_state(state)
            return 0
        except Exception as exc:_raise_fuse_error(exc)
    def fsync(self, path, datasync, fh):
        state = self._state_for_handle(fh)
        if state is None:return 0
        try:
            self._commit_state(state)
            return 0
        except Exception as exc:_raise_fuse_error(exc)
    def release(self, path, fh):
        with self._state_lock:
            state = self._handles.pop(fh, None)
            self._handle_flags.pop(fh, None)
            self._handle_baselines.pop(fh, None)
        if state is None:return 0
        failure = None
        try:self._commit_state(state)
        except Exception as exc:
            failure = exc
            logger.error("Could not commit %s on close: %s", state.path, exc)
        with self._state_lock:state.refs = max(0, state.refs - 1)
        if state.refs == 0:
            if failure is not None and state.dirty:self._preserve_recovery_file(state)
            self._cleanup_state_if_unused(state)
        if failure is not None:_raise_fuse_error(failure)
        return 0
    def truncate(self, path, length, fh=None):
        rel_path = self._path(path)
        if length < 0:raise FuseOSError(errno.EINVAL)
        state = self._state_for_handle(fh) or self._state_for_path(rel_path)
        owned_state = False
        try:
            with self._namespace_lock:
                if state is None:
                    st = self._stat(rel_path)
                    if st.is_directory:raise FuseOSError(errno.EISDIR)
                    state = _OpenFileState(rel_path, _version_token(st))
                    owned_state = True
                with state.lock:
                    if state.detached:
                        if state.working_path is None:raise FuseOSError(errno.EIO)
                    elif not state.dirty:
                        current = _get_version(self.backing_store, state.path)
                        if current != state.version:raise FuseOSError(errno.EBUSY)
                        self._hydrate_working_file(state, current)
                    with open(state.working_path, "r+b") as stream:
                        stream.truncate(length)
                        stream.flush()
                    if not state.detached:state.dirty = True
                if owned_state:
                    self._commit_state(state)
                    self._cleanup_state_if_unused(state)
            return 0
        except Exception as exc:
            if owned_state and state is not None and state.dirty:self._preserve_recovery_file(state)
            _raise_fuse_error(exc)
    def mkdir(self, path, mode):
        rel_path = self._path(path)
        if not rel_path:raise FuseOSError(errno.EEXIST)
        try:
            with self._namespace_lock:
                self._ensure_parent_directory(rel_path)
                if self.backing_store.lexists(rel_path):raise FuseOSError(errno.EEXIST)
                self._run_journaled("mkdir", backend_path=rel_path, is_directory=True,callback=lambda: self.backing_store.make_directory(rel_path),)
                hook = getattr(self.backing_store, "set_metadata", None)
                if hook is not None:
                    try:hook(rel_path, mode=mode)
                    except (OSError, NotImplementedError):pass
            return 0
        except Exception as exc:_raise_fuse_error(exc)
    def unlink(self, path):
        rel_path = self._path(path)
        if not rel_path:raise FuseOSError(errno.EISDIR)
        try:
            with self._namespace_lock:
                st = self._stat(rel_path)
                if st.is_directory:raise FuseOSError(errno.EISDIR)
                state = self._state_for_path(rel_path)
                if state is not None and state.refs > 0:self._begin_detach_state(rel_path, state)
                self._run_journaled("delete", backend_path=rel_path, is_directory=False,expected_version=_version_token(st),callback=lambda: self.backing_store.delete(rel_path, False),)
                self.cache_mgr.delete_file_chunks(rel_path)
                self.journal.delete_file_hash_state(rel_path)
            return 0
        except Exception as exc:_raise_fuse_error(exc)
    def rmdir(self, path):
        rel_path = self._path(path)
        if not rel_path:raise FuseOSError(errno.EBUSY)
        try:
            with self._namespace_lock:
                st = self._stat(rel_path)
                if not st.is_directory:raise FuseOSError(errno.ENOTDIR)
                children = [name for name in self.backing_store.listdir(rel_path) if not is_temporary_file(name)]
                if children:raise FuseOSError(errno.ENOTEMPTY)
                self._run_journaled("delete", backend_path=rel_path, is_directory=True,expected_version=_version_token(st),callback=lambda: self.backing_store.delete(rel_path, True),)
                self.cache_mgr.delete_file_chunks(rel_path, include_descendants=True)
                self.journal.delete_file_hash_state(rel_path, include_descendants=True)
            return 0
        except Exception as exc:_raise_fuse_error(exc)
    def rename(self, old, new, flags=0):
        source = self._path(old)
        destination = self._path(new)
        if not source or not destination:raise FuseOSError(errno.EBUSY)
        if source == destination:return 0
        if flags not in (0, 1):raise FuseOSError(errno.EOPNOTSUPP)
        try:
            with self._namespace_lock:
                self._ensure_parent_directory(destination)
                if flags == 1 and self.backing_store.lexists(destination):raise FuseOSError(errno.EEXIST)
                source_st = self._stat(source)
                destination_exists = self.backing_store.lexists(destination)
                if destination_exists:
                    dest_st = self._stat(destination)
                    if source_st.is_directory and not dest_st.is_directory:raise FuseOSError(errno.ENOTDIR)
                    if not source_st.is_directory and dest_st.is_directory:raise FuseOSError(errno.EISDIR)
                dest_state = self._state_for_path(destination)
                if destination_exists and dest_state is not None and dest_state.refs > 0:self._begin_detach_state(destination, dest_state)
                with self._state_lock:affected = [(key, state) for key, state in self._states.items() if key == source or key.startswith(source + "/")]
                for _, state in affected:self._commit_state(state)
                source_version_before_move = _get_version(self.backing_store, source)
                destination_version_before_move = _get_version(self.backing_store, destination)
                self._run_journaled("move", source_path=source,destination_path=destination, backend_path=source,is_directory=source_st.is_directory,expected_version=source_version_before_move,target_hash=destination_version_before_move,callback=lambda: self.backing_store.move(source, destination),)
                self.cache_mgr.delete_file_chunks(source, include_descendants=True)
                self.cache_mgr.delete_file_chunks(destination, include_descendants=True)
                self.journal.delete_file_hash_state(source, include_descendants=True)
                self.journal.delete_file_hash_state(destination, include_descendants=True)
                for key, state in affected:
                    with state.lock:
                        suffix = key[len(source):]
                        new_key = destination + suffix
                        with self._state_lock:
                            if self._states.get(key) is state:self._states.pop(key, None)
                            state.path = new_key
                            self._states[new_key] = state
                        try:state.version = _get_version(self.backing_store, state.path)
                        except Exception:pass
                        with self._state_lock:
                            for fh, item in self._handles.items():
                                if item is state:self._handle_baselines[fh] = state.version
                        if state.working_path and not state.dirty:
                            try:os.remove(state.working_path)
                            except OSError:pass
                            state.working_path = None
            return 0
        except Exception as exc:_raise_fuse_error(exc)
    def symlink(self, target, source):
        rel_source = self._path(source)
        hook = getattr(self.backing_store, "symlink", None)
        if hook is None:raise FuseOSError(errno.EOPNOTSUPP)
        try:
            hook(target, rel_source)
            return 0
        except Exception as exc:_raise_fuse_error(exc)
    def readlink(self, path):
        rel_path = self._path(path)
        hook = getattr(self.backing_store, "readlink", None)
        if hook is None:raise FuseOSError(errno.EOPNOTSUPP)
        try:return hook(rel_path)
        except Exception as exc:_raise_fuse_error(exc)
    def _set_metadata(self, path, **kwargs):
        rel_path = self._path(path)
        hook = getattr(self.backing_store, "set_metadata", None)
        if hook is None or type(self.backing_store).set_metadata is BackingStore.set_metadata:raise FuseOSError(errno.ENOSYS)
        try:
            state = self._state_for_path(rel_path)
            if state is not None:self._commit_state(state)
            result = hook(rel_path, **kwargs)
            if result is False:raise FuseOSError(errno.ENOSYS)
            return 0
        except Exception as exc:_raise_fuse_error(exc)
    def chmod(self, path, mode, *args, **kwargs):
        rel_path = self._path(path)
        try:
            self._stat(rel_path)
            return 0
        except Exception as exc:_raise_fuse_error(exc)
    def chown(self, path, uid, gid, *args, **kwargs):
        rel_path = self._path(path)
        try:
            self._stat(rel_path)
            return 0
        except Exception as exc:_raise_fuse_error(exc)
    def utimens(self, path, times=None):
        if times is None:
            now = time.time()
            times = (now, now)
        atime, mtime = times
        return self._set_metadata(path, atime=atime, mtime=mtime)
    def opendir(self, path):
        rel_path = self._path(path)
        st = self._stat(rel_path)
        if not st.is_directory:raise FuseOSError(errno.ENOTDIR)
        return 0
    def releasedir(self, path, fh):return 0
    def fsyncdir(self, path, datasync, fh):return 0
    def _collect_backing_files(self, directory=""):
        result = []
        try:names = self.backing_store.listdir(directory)
        except Exception as exc:
            logger.warning("Cannot list backing directory %r: %s", directory, exc)
            return result
        for name in names:
            if is_temporary_file(name):continue
            rel_path = join_backend_path(directory, name)
            try:
                st = self.backing_store.stat(rel_path)
                if st.is_directory:result.extend(self._collect_backing_files(rel_path))
                else:result.append((rel_path, st))
            except Exception as exc:logger.debug("Could not stat backing path %r: %s", rel_path, exc)
        return result
    def refresh_backing_state(self, force=False):
        files = self._collect_backing_files("")
        if not files:existing = set()
        else:existing = {path for path, _ in files}
        for saved_path in self.journal.get_all_file_hashes():
            if saved_path not in existing:
                self.journal.delete_file_hash_state(saved_path)
                self.cache_mgr.delete_file_chunks(saved_path)
        if not files:return
        now = time.time()
        limit = max(1, (len(files) + HASH_BATCH_DIVISOR - 1) // HASH_BATCH_DIVISOR)
        eligible = []
        for path, st in files:
            if self._path_is_dirty(path):continue
            state = self.journal.get_file_hash_state(path)
            due = 0 if state is None else state.get("next_check")
            if due is None:due = 0
            if force or due <= now:eligible.append((due, path, st, state))
        eligible.sort(key=lambda item: (item[0], item[1]))
        for _, path, st, previous in eligible[:limit]:
            check_time = time.time()
            prior_hash = previous.get("hash") if previous else None
            prior_version = previous.get("version") if previous else None
            unchanged = int(previous.get("unchanged_checks") or 0) if previous else 0
            try:
                current_st = self.backing_store.stat(path)
                current_version = _version_token(current_st)
                current_hash = None
                get_hash_overridden = (type(self.backing_store).get_hash is not BackingStore.get_hash)
                if get_hash_overridden:current_hash = self.backing_store.get_hash(path)
                changed = False
                if previous is not None:
                    if prior_version is not None and prior_version != current_version:changed = True
                    if prior_hash is not None and current_hash is not None and prior_hash != current_hash:changed = True
                if changed:
                    self.cache_mgr.delete_file_chunks(path)
                    logger.info("Backing file changed; invalidated cached chunks: %s", path)
                    unchanged = 0
                else:unchanged = min(unchanged + 1, 5)
                interval = min(self.refresh_interval * (unchanged + 1), HASH_MAX_INTERVAL)
                self.journal.set_file_hash_state(path, current_hash, current_version, check_time,check_time + interval, unchanged,)
            except Exception as exc:
                retry_state = previous or {}
                self.journal.set_file_hash_state(path, retry_state.get("hash"), retry_state.get("version"),check_time, check_time + 5,int(retry_state.get("unchanged_checks") or 0),)
                logger.warning("Remote refresh failed for %s; retrying: %s", path, exc)
    def _path_is_dirty(self, rel_path):
        with self._state_lock:state = self._states.get(rel_path)
        if state is None:return False
        with state.lock:return bool(state.dirty)
    def _refresh_worker(self):
        while not self._refresh_stop.wait(self.refresh_interval):
            try:self.refresh_backing_state()
            except Exception:logger.exception("Remote refresh pass failed")
def _backend_matches_local(backend: BackingStore, rel_path: str, local_path: str) -> bool:
    try:
        st = backend.stat(rel_path)
        if st.is_directory or int(st.size) != os.path.getsize(local_path):return False
        local_hash = _blake3_file(local_path)
        with backend.open_read(rel_path) as stream:remote_hash = _blake3_stream(stream)
        return local_hash == remote_hash
    except Exception:return False
def _preserve_recovery_path(cache_dir: str, source_path: str, backend_path: str):
    if not source_path or not os.path.isfile(source_path):return None
    directory = os.path.join(os.path.abspath(cache_dir), "recovery")
    os.makedirs(directory, exist_ok=True)
    base = posixpath.basename(backend_path) or "unknown"
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in base)
    destination = os.path.join(directory, f"{safe}.{int(time.time())}.{uuid.uuid4().hex[:8]}.conflict")
    shutil.move(source_path, destination)
    return destination
def _conditional_write(backend, source_path, rel_path, expected_version):
    hook = getattr(backend, "write_file_from_local_if_unchanged", None)
    overridden = (hook is not None and type(backend).write_file_from_local_if_unchanged is not BackingStore.write_file_from_local_if_unchanged)
    if overridden:
        result = hook(source_path, rel_path, expected_version)
        if result is True:return
        if result is False:raise OSError(errno.EBUSY, "Backing file changed during recovery", rel_path)
    current = _get_version(backend, rel_path)
    if current != expected_version:raise OSError(errno.EBUSY, "Backing file changed during recovery", rel_path)
    backend.write_file_from_local(source_path, rel_path)
def replay_journal(journal: SyncJournal, backing_store: BackingStore,cache_dir=CACHE_DIR):
    for item in journal.pending():
        operation_id = item["id"]
        operation = item["operation"]
        source = item["source_path"]
        backend_path = item["backend_path"]
        try:
            if operation == "write":
                if not source or not os.path.isfile(source):
                    journal.remove(operation_id)
                    continue
                if backing_store.lexists(backend_path) and _backend_matches_local(backing_store, backend_path, source):
                    journal.remove(operation_id)
                    try:os.remove(source)
                    except OSError:pass
                    continue
                expected = item.get("expected_version")
                if expected is None:expected = MISSING_VERSION
                _conditional_write(backing_store, source, backend_path, expected)
                if not backing_store.lexists(backend_path):raise OSError(errno.EIO, "Backing path missing after journal replay", backend_path)
                saved = backing_store.stat(backend_path)
                if saved.is_directory or saved.size != os.path.getsize(source):raise OSError(errno.EIO, "Replay verification failed", backend_path)
                if not _backend_matches_local(backing_store, backend_path, source):raise OSError(errno.EIO, "Replay content verification failed", backend_path)
                journal.remove(operation_id)
                try:os.remove(source)
                except OSError:pass
            elif operation == "mkdir":
                if not backing_store.lexists(backend_path):backing_store.make_directory(backend_path)
                journal.remove(operation_id)
            elif operation == "delete":
                if backing_store.lexists(backend_path):
                    expected = item.get("expected_version")
                    current = _get_version(backing_store, backend_path)
                    if expected is not None and current != expected:
                        logger.warning("Skipping stale journaled delete for %s; backing version changed", backend_path)
                        journal.remove(operation_id)
                        continue
                    backing_store.delete(backend_path, item["is_directory"])
                journal.delete_file_hash_state(backend_path, include_descendants=item["is_directory"])
                journal.remove(operation_id)
            elif operation == "move":
                destination = item["destination_path"]
                if backing_store.lexists(source):
                    expected_source = item.get("expected_version")
                    if expected_source is not None and _get_version(backing_store, source) != expected_source:
                        logger.warning("Skipping stale journaled move for %s; source changed", source)
                        journal.remove(operation_id)
                        continue
                    expected_destination = item.get("target_hash")
                    if expected_destination is not None and _get_version(backing_store, destination) != expected_destination:
                        logger.warning("Skipping journaled move for %s; destination changed", source)
                        journal.remove(operation_id)
                        continue
                    backing_store.move(source, destination)
                elif not backing_store.lexists(destination):raise OSError(errno.ENOENT, "Neither source nor destination exists during move recovery")
                journal.remove(operation_id)
            else:
                logger.warning("Discarding unknown journal operation %r", operation)
                journal.remove(operation_id)
        except Exception as exc:
            if operation == "write" and source and os.path.isfile(source):
                try:
                    recovered = _preserve_recovery_path(cache_dir, source, backend_path or "unknown")
                    logger.error("Could not safely replay write for %s (%s); preserved at %s",backend_path, exc, recovered)
                    journal.remove(operation_id)
                except Exception:logger.exception("Could not preserve failed journal write %s", backend_path)
            else:logger.warning("Journal replay deferred for %s: %s", backend_path, exc)
def main(backing_store: BackingStore, mount_dir: str,*, cache_dir=CACHE_DIR, db_path=DB_PATH, journal_path=JOURNAL_PATH,chunk_size=CHUNK_SIZE, cache_ttl=CACHE_TTL,refresh_interval=REFRESH_INTERVAL):
    if os.name != "posix":raise RuntimeError("This program requires a POSIX operating system.")
    if backing_store is None:raise ValueError("A backing store is required")
    mount_dir = os.path.abspath(mount_dir)
    os.makedirs(mount_dir, exist_ok=True)
    backing_store.initialize()
    cache = CacheManager(db_path, cache_dir, chunk_size=chunk_size, ttl=cache_ttl)
    journal = SyncJournal(journal_path)
    journal.initialize()
    replay_journal(journal, backing_store, cache_dir)
    filesystem = StorageVFS(backing_store, mount_dir, cache_manager=cache,journal=journal, refresh_interval=refresh_interval,)
    filesystem.refresh_backing_state(force=True)
    filesystem.start()
    logger.info("Mount: %s", mount_dir)
    logger.info("Backing store: %s", backing_store.describe())
    logger.info("Chunk cache: %s (%d MiB chunks)", cache.cache_dir,cache.chunk_size // (1024 * 1024))
    logger.info("Clean chunk inactivity timeout: %d seconds", int(cache.ttl))
    logger.info("Journal: %s", journal.path)
    try:FUSE(filesystem,mount_dir,foreground=True,nothreads=False,direct_io=True,default_permissions=True,attr_timeout=1,entry_timeout=1,negative_timeout=0,)
    finally:
        filesystem.stop()
        with filesystem._state_lock:states = list(set(filesystem._states.values()))
        for state in states:
            try:filesystem._commit_state(state)
            except Exception as exc:
                logger.error("Final commit failed for %s: %s", state.path, exc)
                filesystem._preserve_recovery_file(state)
        journal.close()
if __name__ == "__main__":
    class LocalStorageBackend(BackingStore):
        def __init__(self, root_directory):
            self.root_directory = os.path.abspath(root_directory)
            self._mutation_lock = threading.RLock()
        def _full_path(self, relative_path):
            relative_path = clean_backend_path(relative_path or "")
            if not relative_path:return self.root_directory
            components = relative_path.split("/")
            full_path = os.path.abspath(os.path.join(self.root_directory, *components))
            try:common = os.path.commonpath([self.root_directory, full_path])
            except ValueError as exc:raise ValueError(f"Invalid backing path: {relative_path!r}") from exc
            if os.path.normcase(common) != os.path.normcase(self.root_directory):raise PermissionError(errno.EACCES, f"Backing path escapes root: {relative_path!r}")
            current = self.root_directory
            for component in components:
                current = os.path.join(current, component)
                if os.path.islink(current):raise OSError(errno.EOPNOTSUPP, "The demo backend does not expose symlinks", current)
            return full_path
        @staticmethod
        def _reject_symlink(path):
            if os.path.islink(path):raise OSError(errno.EOPNOTSUPP, "The demo backend does not expose symlinks", path)
        def initialize(self):os.makedirs(self.root_directory, exist_ok=True)
        def listdir(self, relative_path):
            full = self._full_path(relative_path)
            self._reject_symlink(full)
            return os.listdir(full)
        def stat(self, relative_path):
            full = self._full_path(relative_path)
            self._reject_symlink(full)
            st = os.stat(full)
            return BackingStat(is_directory=stat.S_ISDIR(st.st_mode),size=st.st_size, creation_time=st.st_ctime,access_time=st.st_atime,modified_time=st.st_mtime,)
        def open_read(self, relative_path):
            full = self._full_path(relative_path)
            self._reject_symlink(full)
            return open(full, "rb")
        def write_file_from_local(self, source_path, relative_path):
            destination = self._full_path(relative_path)
            self._reject_symlink(destination) if os.path.lexists(destination) else None
            parent = os.path.dirname(destination)
            os.makedirs(parent, exist_ok=True)
            temporary = destination + f".vfs-tmp-{os.getpid()}-{threading.get_ident()}-{uuid.uuid4().hex}"
            try:
                with self._mutation_lock:
                    old_stat = os.stat(destination) if os.path.exists(destination) else None
                    shutil.copyfile(source_path, temporary)
                    shutil.copystat(source_path, temporary, follow_symlinks=False)
                    if old_stat is not None:
                        try:os.chown(temporary, old_stat.st_uid, old_stat.st_gid)
                        except (PermissionError, OSError):pass
                        os.chmod(temporary, stat.S_IMODE(old_stat.st_mode))
                    os.replace(temporary, destination)
            finally:
                try:os.remove(temporary)
                except FileNotFoundError:pass
        def write_file_from_local_if_unchanged(self, source_path, relative_path, expected_version):
            with self._mutation_lock:
                current = _get_version(self, relative_path)
                if current != expected_version:return False
                self.write_file_from_local(source_path, relative_path)
                return True
        def make_directory(self, relative_path):
            full = self._full_path(relative_path)
            os.makedirs(full, exist_ok=False)
        def lexists(self, relative_path):return os.path.lexists(self._full_path(relative_path))
        def delete(self, relative_path, is_directory):
            full = self._full_path(relative_path)
            self._reject_symlink(full)
            if not os.path.lexists(full):return
            if is_directory:shutil.rmtree(full)
            else:os.remove(full)
        def move(self, source_relative_path, destination_relative_path):
            source = self._full_path(source_relative_path)
            destination = self._full_path(destination_relative_path)
            self._reject_symlink(source)
            if os.path.lexists(destination):
                self._reject_symlink(destination)
                if os.path.isdir(destination):shutil.rmtree(destination)
                else:os.remove(destination)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            shutil.move(source, destination)
        def get_hash(self, relative_path):
            full = self._full_path(relative_path)
            self._reject_symlink(full)
            if not os.path.isfile(full):return None
            return _blake3_file(full)
        def get_posix_metadata(self, relative_path):
            full = self._full_path(relative_path)
            self._reject_symlink(full)
            st = os.stat(full)
            return {"st_mode": st.st_mode,"st_nlink": st.st_nlink,"st_uid": st.st_uid,"st_gid": st.st_gid,"st_ctime": st.st_ctime,"st_mtime": st.st_mtime,"st_atime": st.st_atime,"st_ino": st.st_ino,"st_dev": st.st_dev,"st_blocks": getattr(st, "st_blocks", (st.st_size + 511) // 512),"st_blksize": getattr(st, "st_blksize", 4096),}
        def set_metadata(self, relative_path, *, mode=None, uid=None, gid=None,atime=None, mtime=None):
            full = self._full_path(relative_path)
            self._reject_symlink(full)
            with self._mutation_lock:
                if mode is not None:os.chmod(full, mode)
                if uid is not None or gid is not None:os.chown(full, -1 if uid is None else uid, -1 if gid is None else gid)
                if atime is not None or mtime is not None:
                    current = os.stat(full)
                    os.utime(full, (current.st_atime if atime is None else atime,current.st_mtime if mtime is None else mtime,))
            return True
        def statfs(self, relative_path=""):
            stv = os.statvfs(self._full_path(relative_path))
            return {key: getattr(stv, key) for key in ("f_bavail", "f_bfree", "f_blocks", "f_bsize", "f_favail","f_ffree", "f_files", "f_flag", "f_frsize", "f_namemax")}
    main(LocalStorageBackend(BACKING_DIR), MOUNT_DIR)