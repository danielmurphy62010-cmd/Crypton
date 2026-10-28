import json, os, shutil, time, network, getpass, sys, traceback, socket, blake3
import errno, stat, tempfile, threading, uuid
SHARED_DIR = os.path.expanduser("~/Shared")
CHUNK_SIZE = 12 * 1024 * 1024
IO_CHUNK_SIZE = 16 * 1024 * 1024
VFS_MISSING_VERSION = "<VFS-MISSING>"
VFS_UPLOAD_IDLE_TIMEOUT = 3600
VFS_MAX_UPLOAD_CHUNK = 32 * 1024 * 1024
if os.name == "nt":import msvcrt
else:import select, termios, tty
def get_optional_input(text, timeout=15):
    if not sys.stdin.isatty() or not sys.stdout.isatty():return ""
    value = []
    cursor = 0
    start = time.monotonic()
    print(text, end="", flush=True)
    def redraw():
        print("\r" + text + "".join(value) + "\x1b[K", end="", flush=True)
        print(f"\r{text}{''.join(value[:cursor])}", end="", flush=True)
    def insert(char):
        nonlocal cursor
        value.insert(cursor, char)
        cursor += 1
        redraw()
    def backspace():
        nonlocal cursor
        if cursor > 0:
            cursor -= 1
            value.pop(cursor)
            redraw()
    def delete():
        if cursor < len(value):
            value.pop(cursor)
            redraw()
    def move_left():
        nonlocal cursor
        if cursor > 0:
            cursor -= 1
            redraw()
    def move_right():
        nonlocal cursor
        if cursor < len(value):
            cursor += 1
            redraw()
    def move_home():
        nonlocal cursor
        cursor = 0
        redraw()
    def move_end():
        nonlocal cursor
        cursor = len(value)
        redraw()
    if os.name == "nt":
        import msvcrt
        while time.monotonic() - start < timeout:
            if not msvcrt.kbhit():
                time.sleep(0.01)
                continue
            char = msvcrt.getwch()
            if char in ("\r", "\n"):
                print()
                return "".join(value) or ""
            if char == "\x03":raise KeyboardInterrupt
            if char in ("\x00", "\xe0"):
                key = msvcrt.getwch()
                if key == "K":move_left()
                elif key == "M":move_right()
                elif key == "G":move_home()
                elif key == "O":move_end()
                elif key == "S":delete()
                continue
            if char == "\b":backspace()
            elif char == "\x1b":continue
            else:insert(char)
        print()
        return ""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while time.monotonic() - start < timeout:
            remaining = timeout - (time.monotonic() - start)
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                print()
                return ""
            char = os.read(fd, 1)
            if char in (b"\r", b"\n"):
                print()
                return "".join(value) or None
            if char == b"\x03":raise KeyboardInterrupt
            if char in (b"\x7f", b"\x08"):
                backspace()
                continue
            if char == b"\x1b":
                ready, _, _ = select.select([fd], [], [], 0.03)
                if not ready:continue
                seq = os.read(fd, 1)
                if seq == b"[":
                    ready, _, _ = select.select([fd], [], [], 0.03)
                    if not ready:continue
                    key = os.read(fd, 1)
                    if key == b"D":move_left()
                    elif key == b"C":move_right()
                    elif key == b"H":move_home()
                    elif key == b"F":move_end()
                    elif key == b"3":
                        ready, _, _ = select.select([fd], [], [], 0.03)
                        if ready and os.read(fd, 1) == b"~":delete()
                continue
            if char[0] < 128:insert(char.decode())
            else:
                expected = (2 if char[0] & 0xE0 == 0xC0 else 3 if char[0] & 0xF0 == 0xE0 else 4 if char[0] & 0xF8 == 0xF0 else 1)
                raw = char
                for _ in range(expected - 1):
                    ready, _, _ = select.select([fd], [], [], 0.05)
                    if not ready:break
                    raw += os.read(fd, 1)
                decoded = raw.decode("utf-8", errors="replace")
                for c in decoded:insert(c)
        print()
        return ""
    finally:termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
def safe_path(base_dir, req_path, allow_root=False):
    base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base, str(req_path).lstrip("/\\")))
    try:
        if os.path.commonpath((base, target)) != base or (base==target and not allow_root):raise PermissionError("Access denied: path outside shared directory")
    except ValueError:raise PermissionError("Access denied: path outside shared directory")
    return target
def make_packet(meta: dict, payload: bytes = b"") -> bytes:
    meta_bytes = json.dumps(meta, separators=(",", ":")).encode("utf-8")
    return len(meta_bytes).to_bytes(4, byteorder="big") + meta_bytes + payload
def vfs_is_temporary_name(name):
    name = os.path.basename(str(name)).lower()
    return any(part in name for part in (".tmp", ".crdownload", ".part", ".download", ".temp", ".bak",".vfs-tmp-", ".vfs-upload-",)) or "~" in name
def vfs_creation_time(st):return float(getattr(st, "st_birthtime", st.st_ctime))
def vfs_version_token(target):
    if not os.path.lexists(target):return VFS_MISSING_VERSION
    st = os.stat(target)
    return json.dumps([bool(stat.S_ISDIR(st.st_mode)), int(st.st_size),round(vfs_creation_time(st), 9), round(float(st.st_mtime), 9)],separators=(",", ":"),)
def vfs_stat_payload(target):
    st = os.stat(target)
    is_directory = stat.S_ISDIR(st.st_mode)
    is_file = stat.S_ISREG(st.st_mode)
    if not (is_directory or is_file):raise OSError(errno.EOPNOTSUPP, "Unsupported file type", target)
    virtual_mode = (stat.S_IFDIR if is_directory else stat.S_IFREG) | 0o777
    return {"is_directory": is_directory,"is_file": is_file,"size": int(st.st_size),"creation_time": vfs_creation_time(st),"access_time": float(st.st_atime),"modified_time": float(st.st_mtime),"version": vfs_version_token(target),"st_mode": int(virtual_mode),"st_nlink": int(getattr(st, "st_nlink", 1)),"st_uid": int(getattr(st, "st_uid", 0)),"st_gid": int(getattr(st, "st_gid", 0)),"st_ctime": float(st.st_ctime),"st_ino": int(getattr(st, "st_ino", 0)),"st_dev": int(getattr(st, "st_dev", 0)),"st_blocks": int(getattr(st, "st_blocks", (st.st_size + 511) // 512)),"st_blksize": int(getattr(st, "st_blksize", 4096)),}
def vfs_hash_hex(path):
    hasher = blake3.blake3()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):hasher.update(block)
    return hasher.digest(64).hex()
def vfs_upload_ranges_complete(ranges, size):
    if size == 0:return True
    cursor = 0
    for start, end in sorted(ranges):
        if start > cursor:return False
        cursor = max(cursor, end)
        if cursor >= size:return True
    return False
class FileServer:
    def __init__(self, host="127.0.0.1", port=9000, password=None, **kwargs):
        if not password:raise ValueError("Server password is required.")
        self.shared_dir = SHARED_DIR
        self._vfs_mutation_lock = threading.RLock()
        self._vfs_upload_lock = threading.RLock()
        self._vfs_uploads = {}
        self.auth_key_dir = kwargs.get("auth_key_dir", "./keys")
        os.makedirs(self.shared_dir, exist_ok=True)
        try:self.server = network.TCPServer(host=host,port=port,password=password,on_exchange=self.handle_exchange,**kwargs)
        except Exception as e:traceback.print_exception(e);raise OSError
        print(f"[*] File Server active on tcp://{host}:{port} | Serving: {self.shared_dir}")
    def _expire_vfs_uploads(self):
        now = time.time()
        expired = []
        with self._vfs_upload_lock:
            for upload_id, item in list(self._vfs_uploads.items()):
                if item["committing"]:continue
                if now - item["last_activity"] > VFS_UPLOAD_IDLE_TIMEOUT:
                    del self._vfs_uploads[upload_id]
                    expired.append(item)
        for item in expired:
            try:os.remove(item["temp_path"])
            except OSError:pass
    def _discard_vfs_upload(self, upload_id, item):
        with self._vfs_upload_lock:
            if self._vfs_uploads.get(upload_id) is item:del self._vfs_uploads[upload_id]
        try:os.remove(item["temp_path"])
        except OSError:pass
    def handle_exchange(self, server_inst, eid, data, cid):
        cmd = None
        try:
            if len(data) < 4:return
            header_len = int.from_bytes(data[:4], "big")
            if header_len < 2 or 4 + header_len > len(data):raise ValueError("Invalid packet header")
            meta = json.loads(data[4:4 + header_len].decode("utf-8"))
            payload = data[4 + header_len:]
            cmd = meta.get("cmd")
            if isinstance(cmd, str) and cmd.startswith("vfs_"):self._expire_vfs_uploads()
            if isinstance(cmd, str) and cmd.startswith("admin_"):
                if cmd == "admin_list_connections":
                    server_inst.list_connections(cid, eid)
                    return
                elif cmd == "admin_list_users":
                    server_inst.list_users(cid, eid)
                    return
                elif cmd == "admin_bootstrap_status":
                    server_inst.bootstrap_status(cid, eid)
                    return
                elif cmd == "admin_enable_bootstrap":
                    server_inst.enable_bootstrap(cid, eid)
                    return
                elif cmd == "admin_disable_bootstrap":
                    server_inst.disable_bootstrap(cid, eid)
                    return
                elif cmd == "admin_setup_bootstrap_totp":
                    server_inst.setup_bootstrap_totp(cid, eid)
                    return
                elif cmd == "admin_verify_bootstrap_totp":
                    server_inst.verify_bootstrap_totp(cid, eid, meta.get("code", ""))
                    return
                elif cmd == "admin_rename_username":
                    server_inst.rename_username(cid, eid,meta.get("target_cid", ""),meta.get("new_username"))
                    return
                elif cmd == "admin_deauth_client":
                    server_inst.deauth_client(cid, eid, meta.get("target_cid", ""))
                    return
                elif cmd == "admin_disconnect_client":
                    server_inst.disconnect_client(cid, eid, meta.get("target_cid", ""))
                    return
                else:
                    result = {"status": "error","message": f"Unknown admin command: {cmd}"}
                    server_inst.send(make_packet(result), eid=eid, client_id=cid)
                    return
            if cmd == "list":
                rel_path = meta.get("path", "")
                target = safe_path(self.shared_dir, rel_path, True)
                if not os.path.exists(target):resp = make_packet({"status": "error","message": "Directory does not exist",})
                elif not os.path.isdir(target):resp = make_packet({"status": "error","message": "Path is not a directory",})
                else:
                    items = []
                    for entry in sorted(os.listdir(target)):
                        full = os.path.join(target, entry)
                        is_dir = os.path.isdir(full)
                        size = 0 if is_dir else os.path.getsize(full)
                        items.append({"name": entry,"is_dir": is_dir,"size": size,})
                    resp = make_packet({"status": "ok","items": items,})
                server_inst.send(resp,eid=eid,client_id=cid,)
            elif cmd == "info":
                rel_path = meta.get("path", "")
                target = safe_path(self.shared_dir, rel_path)
                if not os.path.exists(target):resp = make_packet({"status": "error","message": "Path does not exist",})
                else:
                    is_file = os.path.isfile(target)
                    size = os.path.getsize(target) if is_file else 0
                    total_chunks = ((size + CHUNK_SIZE - 1) // CHUNK_SIZE if is_file else 0)
                    resp = make_packet({"status": "ok","path": rel_path,"is_file": is_file,"is_dir":not is_file,"size": size,"chunk_size": CHUNK_SIZE,"total_chunks": total_chunks,})
                server_inst.send(resp,eid=eid,client_id=cid,)
            elif cmd == "download_chunk":
                rel_path = meta.get("path", "")
                target = safe_path(self.shared_dir, rel_path)
                offset = meta.get("offset",meta.get("chunk_idx", 0) * CHUNK_SIZE,)
                length = meta.get("length", CHUNK_SIZE)
                if length > 1024 * 1024 * 32: resp = make_packet({"status": "error","message": "Download chunk length exceeds maximum"})
                if not os.path.isfile(target):resp = b"\x01File not found"
                else:
                    with open(target, "rb") as f:
                        f.seek(offset)
                        chunk = f.read(length)
                    resp = b"\x00" + chunk
                server_inst.send(resp,eid=eid,client_id=cid,)
            elif cmd == "get_hash":
                rel_path = meta.get("path", "")
                start = meta.get('start',0)
                length = meta.get('len',-1)
                target = safe_path(self.shared_dir, rel_path)
                read_bytes=0
                if not os.path.isfile(target):resp = b"\x01File not found"
                else:
                    with open(target, "rb") as f:
                        f.seek(start)
                        hasher=blake3.blake3()
                        while read_bytes<length or length==-1:
                            to_read=IO_CHUNK_SIZE
                            if IO_CHUNK_SIZE > (length-read_bytes) and length!=-1:to_read=length-read_bytes
                            chunk = f.read(to_read)
                            if not chunk:break
                            read_bytes+=len(chunk)
                            hasher.update(chunk)
                    resp = b"\x00" + hasher.digest(64)
                server_inst.send(resp,eid=eid,client_id=cid)
            elif cmd == "upload_chunk":
                rel_path = meta.get("path", "")
                target = safe_path(self.shared_dir, rel_path)
                offset = meta.get("offset",meta.get("chunk_idx", 0) * CHUNK_SIZE,)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                mode = "r+b" if os.path.exists(target) else "w+b"
                with open(target, mode) as f:
                    f.seek(offset)
                    f.write(payload)
                    f.flush()
                resp = make_packet({"status": "ok",})
                server_inst.send(resp,eid=eid,client_id=cid,)
            elif cmd == "move":
                src_target = safe_path(self.shared_dir,meta.get("src_path", ""),)
                dst_target = safe_path(self.shared_dir,meta.get("dst_path", ""),)
                if not os.path.exists(src_target):resp = make_packet({"status": "error","message": "Source path does not exist",})
                else:
                    os.makedirs(os.path.dirname(dst_target),exist_ok=True,)
                    shutil.move(src_target, dst_target)
                    resp = make_packet({"status": "ok",})
                server_inst.send(resp,eid=eid,client_id=cid,)
            elif cmd == "copy":
                src_target = safe_path(self.shared_dir,meta.get("src_path", ""),)
                dst_target = safe_path(self.shared_dir,meta.get("dst_path", ""),)
                if not os.path.exists(src_target):resp = make_packet({"status": "error","message": "Source path does not exist",})
                else:
                    os.makedirs(os.path.dirname(dst_target),exist_ok=True,)
                    if os.path.isdir(src_target):shutil.copytree(src_target,dst_target,dirs_exist_ok=True,)
                    else:shutil.copy2(src_target,dst_target,)
                    resp = make_packet({"status": "ok",})
                server_inst.send(resp,eid=eid,client_id=cid,)
            elif cmd == "delete":
                target = safe_path(self.shared_dir,meta.get("path"))
                if not os.path.exists(target):resp = make_packet({"status": "error","message": "Path does not exist",})
                else:
                    if os.path.isdir(target):shutil.rmtree(target)
                    else:os.remove(target)
                    resp = make_packet({"status": "ok",})
                server_inst.send(resp,eid=eid,client_id=cid,)
            elif cmd == "truncate":
                rel_path = meta.get("path", "")
                target = safe_path(self.shared_dir, rel_path)
                size = meta.get("size")
                if isinstance(size, bool) or not isinstance(size, int) or size < 0:resp = make_packet({"status": "error", "message": "Invalid truncate size"})
                elif not os.path.isfile(target):resp = make_packet({"status": "error","message": "File does not exist or is not a regular file",})
                else:
                    with open(target, "r+b") as f:
                        f.truncate(size)
                        f.flush()
                    resp = make_packet({"status": "ok","size": size,})
                server_inst.send(resp, eid=eid, client_id=cid,)
            elif cmd == "mkdir":
                target = safe_path(self.shared_dir,meta.get("path", ""),)
                os.makedirs(target, exist_ok=True)
                resp = make_packet({"status": "ok",})
                server_inst.send(resp,eid=eid,client_id=cid,)
            elif cmd == "vfs_list":
                rel_path = meta.get("path", "")
                target = safe_path(self.shared_dir, rel_path)
                if not os.path.isdir(target):resp = make_packet({"status": "error", "code": "not_found", "message": "Directory does not exist"})
                else:
                    items = []
                    for name in sorted(os.listdir(target)):
                        if vfs_is_temporary_name(name):continue
                        full = os.path.join(target, name)
                        if os.path.isdir(full):items.append({"name": name, "is_dir": True, "size": 0})
                        elif os.path.isfile(full):items.append({"name": name, "is_dir": False, "size": os.path.getsize(full)})
                    resp = make_packet({"status": "ok", "items": items})
                server_inst.send(resp, eid=eid, client_id=cid)
            elif cmd == "vfs_stat":
                rel_path = meta.get("path", "")
                target = safe_path(self.shared_dir, rel_path)
                if not os.path.exists(target):resp = make_packet({"status": "error", "code": "not_found", "message": "Path does not exist"})
                else:resp = make_packet({"status": "ok", "path": rel_path, **vfs_stat_payload(target)})
                server_inst.send(resp, eid=eid, client_id=cid)
            elif cmd == "vfs_posix_metadata":
                target = safe_path(self.shared_dir, meta.get("path", ""))
                if not os.path.exists(target):resp = make_packet({"status": "error", "code": "not_found", "message": "Path does not exist"})
                else:
                    fields = vfs_stat_payload(target)
                    resp = make_packet({"status": "ok", **{key: value for key, value in fields.items() if key.startswith("st_")}})
                server_inst.send(resp, eid=eid, client_id=cid)
            elif cmd == "vfs_statfs":
                target = safe_path(self.shared_dir, meta.get("path", ""))
                probe = target if os.path.isdir(target) else os.path.dirname(target)
                if not probe or not os.path.isdir(probe):probe = self.shared_dir
                if hasattr(os, "statvfs"):
                    values = os.statvfs(probe)
                    fields = {name: int(getattr(values, name)) for name in ("f_bavail", "f_bfree", "f_blocks", "f_bsize", "f_favail","f_ffree", "f_files", "f_flag", "f_frsize", "f_namemax",)}
                else:
                    usage = shutil.disk_usage(probe)
                    block_size = 4096
                    fields = {"f_bavail": usage.free // block_size,"f_bfree": usage.free // block_size,"f_blocks": (usage.total + block_size - 1) // block_size,"f_bsize": block_size, "f_favail": 0, "f_ffree": 0,"f_files": 0, "f_flag": 0, "f_frsize": block_size,"f_namemax": 255,}
                resp = make_packet({"status": "ok", **fields})
                server_inst.send(resp, eid=eid, client_id=cid)
            elif cmd == "vfs_mkdir":
                target = safe_path(self.shared_dir, meta.get("path", ""))
                with self._vfs_mutation_lock:
                    if os.path.lexists(target):raise FileExistsError(errno.EEXIST, "Path already exists", target)
                    os.mkdir(target)
                resp = make_packet({"status": "ok"})
                server_inst.send(resp, eid=eid, client_id=cid)
            elif cmd == "vfs_delete":
                target = safe_path(self.shared_dir, meta.get("path", ""))
                requested_directory = meta.get("is_directory")
                with self._vfs_mutation_lock:
                    if not os.path.lexists(target):raise FileNotFoundError(errno.ENOENT, "Path does not exist", target)
                    actual_directory = os.path.isdir(target)
                    if isinstance(requested_directory, bool) and requested_directory != actual_directory:raise OSError(errno.EISDIR if actual_directory else errno.ENOTDIR, "Path type changed before deletion", target)
                    if actual_directory:os.rmdir(target)
                    else:os.remove(target)
                resp = make_packet({"status": "ok"})
                server_inst.send(resp, eid=eid, client_id=cid)
            elif cmd == "vfs_move":
                src_target = safe_path(self.shared_dir, meta.get("src_path", ""))
                dst_target = safe_path(self.shared_dir, meta.get("dst_path", ""))
                with self._vfs_mutation_lock:
                    if not os.path.lexists(src_target):raise FileNotFoundError(errno.ENOENT, "Source path does not exist", src_target)
                    source_is_directory = os.path.isdir(src_target)
                    if os.path.lexists(dst_target):
                        destination_is_directory = os.path.isdir(dst_target)
                        if source_is_directory != destination_is_directory:raise OSError(errno.ENOTDIR if source_is_directory else errno.EISDIR, "Source and destination types differ", dst_target)
                        if destination_is_directory:os.rmdir(dst_target)
                    parent = os.path.dirname(dst_target)
                    if not os.path.isdir(parent):raise FileNotFoundError(errno.ENOENT, "Destination parent does not exist", parent)
                    os.replace(src_target, dst_target)
                resp = make_packet({"status": "ok"})
                server_inst.send(resp, eid=eid, client_id=cid)
            elif cmd == "vfs_begin_upload":
                rel_path = meta.get("path", "")
                target = safe_path(self.shared_dir, rel_path)
                size = meta.get("size")
                if isinstance(size, bool) or not isinstance(size, int) or size < 0:raise ValueError("size must be a non-negative integer")
                expected = meta.get("expected_version")
                if expected is not None and not isinstance(expected, str):raise ValueError("expected_version must be a string")
                target_hash = meta.get("target_hash_hex")
                if target_hash is not None and (not isinstance(target_hash, str) or len(target_hash) != 128 or any(ch not in "0123456789abcdefABCDEF" for ch in target_hash)):raise ValueError("target_hash_hex must be a 128-character hex digest")
                if target_hash is not None:target_hash = target_hash.lower()
                parent = os.path.dirname(target)
                if not os.path.isdir(parent):raise FileNotFoundError(errno.ENOENT, "Destination directory does not exist", parent)
                with self._vfs_mutation_lock:
                    current_version = vfs_version_token(target)
                    if expected is not None and current_version != expected:
                        resp = make_packet({"status": "conflict", "code": "version_mismatch", "message": "Backing file changed before upload began"})
                        server_inst.send(resp, eid=eid, client_id=cid)
                        return
                    if os.path.isdir(target):raise IsADirectoryError(errno.EISDIR, "Destination is a directory", target)
                    baseline = expected if expected is not None else current_version
                    fd, temp_path = tempfile.mkstemp(prefix=".vfs-upload-", suffix=".tmp", dir=parent)
                    try:
                        with os.fdopen(fd, "r+b") as stream:
                            stream.truncate(size)
                            stream.flush()
                            os.fsync(stream.fileno())
                    except Exception:
                        try:os.remove(temp_path)
                        except OSError:pass
                        raise
                    upload_id = uuid.uuid4().hex
                    with self._vfs_upload_lock:self._vfs_uploads[upload_id] = {"client_id": cid, "path": rel_path, "target": target,"temp_path": temp_path, "size": size,"expected_version": baseline, "target_hash": target_hash,"ranges": [], "last_activity": time.time(), "committing": False,}
                resp = make_packet({"status": "ok", "upload_id": upload_id, "size": size})
                server_inst.send(resp, eid=eid, client_id=cid)
            elif cmd == "vfs_upload_chunk":
                upload_id = meta.get("upload_id")
                if not isinstance(upload_id, str):raise ValueError("upload_id is required")
                offset = meta.get("offset", 0)
                if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:raise ValueError("offset must be a non-negative integer")
                if len(payload) > VFS_MAX_UPLOAD_CHUNK:raise ValueError("Upload chunk is too large")
                with self._vfs_upload_lock:
                    upload = self._vfs_uploads.get(upload_id)
                    if upload is None:raise FileNotFoundError(errno.ENOENT, "Upload session does not exist")
                    if upload["client_id"] != cid:raise PermissionError(errno.EACCES, "Upload session belongs to another client")
                    if upload["committing"]:raise OSError(errno.EBUSY, "Upload is being committed")
                    if offset + len(payload) > upload["size"]:raise ValueError("Chunk exceeds declared upload size")
                    with open(upload["temp_path"], "r+b") as stream:
                        stream.seek(offset)
                        stream.write(payload)
                        stream.flush()
                    if payload:upload["ranges"].append((offset, offset + len(payload)))
                    upload["last_activity"] = time.time()
                resp = make_packet({"status": "ok", "bytes_written": len(payload)})
                server_inst.send(resp, eid=eid, client_id=cid)
            elif cmd == "vfs_commit_upload":
                upload_id = meta.get("upload_id")
                if not isinstance(upload_id, str):raise ValueError("upload_id is required")
                with self._vfs_upload_lock:
                    upload = self._vfs_uploads.get(upload_id)
                    if upload is None:raise FileNotFoundError(errno.ENOENT, "Upload session does not exist")
                    if upload["client_id"] != cid:raise PermissionError(errno.EACCES, "Upload session belongs to another client")
                    if upload["committing"]:raise OSError(errno.EBUSY, "Upload is already being committed")
                    upload["committing"] = True
                    upload["last_activity"] = time.time()
                keep_session = True
                try:
                    temp_path = upload["temp_path"]
                    target = upload["target"]
                    size = upload["size"]
                    if not vfs_upload_ranges_complete(upload["ranges"], size):raise OSError(errno.EIO, "Upload is incomplete")
                    if not os.path.isfile(temp_path) or os.path.getsize(temp_path) != size:raise OSError(errno.EIO, "Uploaded file size verification failed")
                    with open(temp_path, "r+b") as stream:
                        stream.flush()
                        os.fsync(stream.fileno())
                    actual_hash = vfs_hash_hex(temp_path)
                    if upload["target_hash"] is not None and actual_hash != upload["target_hash"]:raise OSError(errno.EIO, "Uploaded content hash does not match")
                    conflict = False
                    with self._vfs_mutation_lock:
                        if vfs_version_token(target) != upload["expected_version"]:conflict = True
                        elif os.path.isdir(target):raise IsADirectoryError(errno.EISDIR, "Destination is a directory", target)
                        else:
                            if os.name == "posix" and os.path.isfile(target):
                                try:os.chmod(temp_path, stat.S_IMODE(os.stat(target).st_mode))
                                except OSError:pass
                            os.replace(temp_path, target)
                    if conflict:
                        self._discard_vfs_upload(upload_id, upload)
                        keep_session = False
                        resp = make_packet({"status": "conflict", "code": "version_mismatch", "message": "Backing file changed during upload"})
                        server_inst.send(resp, eid=eid, client_id=cid)
                        return
                    self._discard_vfs_upload(upload_id, upload)
                    keep_session = False
                    resp = make_packet({"status": "ok", "path": upload["path"], "size": size, "hash": actual_hash, "version": vfs_version_token(target)})
                    server_inst.send(resp, eid=eid, client_id=cid)
                finally:
                    if keep_session:
                        with self._vfs_upload_lock:
                            if self._vfs_uploads.get(upload_id) is upload:upload["committing"] = False
            elif cmd == "vfs_abort_upload":
                upload_id = meta.get("upload_id")
                if not isinstance(upload_id, str):raise ValueError("upload_id is required")
                with self._vfs_upload_lock:
                    upload = self._vfs_uploads.get(upload_id)
                    if upload is not None:
                        if upload["client_id"] != cid:raise PermissionError(errno.EACCES, "Upload session belongs to another client")
                        if upload["committing"]:raise OSError(errno.EBUSY, "Cannot abort an upload being committed")
                if upload is not None:self._discard_vfs_upload(upload_id, upload)
                resp = make_packet({"status": "ok"})
                server_inst.send(resp, eid=eid, client_id=cid)
            else:
                resp = make_packet({"status": "error","message": f"Unknown command: {cmd!r}",})
                server_inst.send(resp,eid=eid,client_id=cid,)
        except Exception as e:
            try:
                if isinstance(cmd, str) and cmd.startswith("vfs_"):
                    if isinstance(e, FileNotFoundError) or getattr(e, "errno", None) == errno.ENOENT:code = "not_found"
                    elif isinstance(e, FileExistsError) or getattr(e, "errno", None) == errno.EEXIST:code = "exists"
                    else:code = getattr(e, "errno", None)
                    resp = make_packet({"status": "error", "code": code, "message": str(e)})
                else:resp = make_packet({"status": "error","message": str(e),})
                server_inst.send(resp,eid=eid,client_id=cid,)
            except Exception:pass
if __name__ == "__main__":
    IP="127.0.0.1"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            IP = s.getsockname()[0]
    except:pass
    TPM=False
    try:import TPM_client;TPM=True
    except:pass
    password=None
    if TPM:
        try:
            c=TPM_client.TPMClient()
            password=c.get_bytes('SFTP server password')['value'].decode("ascii")
        except ConnectionError:print('Failed to connect to TPM server. Is TPM.exe running?')
        except:pass
    retry=True
    retrys=10
    while retry and retrys>0:
        retrys-=1
        retry=False
        if password == None:password = getpass.getpass("Server password: ")
        newTOTP = get_optional_input("Setup TOTP? [y/N]: ",5).lower().startswith('y')
        if not isinstance(password,str):raise TypeError('password must be a string')
        try:srv = FileServer(IP,password=password,newTOTP=newTOTP)
        except OSError:
            retry=True
            password=None
    if retrys==0 and retry:raise RuntimeError('Setup Error')
    if TPM:
        try:c.create_bytes('SFTP server password',password.encode('ascii'))
        except:pass
    try:
        while True:time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        srv.server.close()