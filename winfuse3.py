import os, time, ctypes, shutil, stat, uuid, threading, sqlite3, hashlib, queue
from dataclasses import dataclass
from ctypes import wintypes
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
FETCH_CHUNK_SIZE = 12 * 1024 * 1024
MOUNT_DIR = None
RESET_MOUNT = False
JOURNAL_PATH = ".\\sync_journal.db"
REFRESH_INTERVAL = 5
PROVIDER_NAME = "PythonCfApiMirror"
PROVIDER_VERSION = "1.0"
ACTIVE_BACKING_STORE = None
@dataclass(frozen=True)
class BackingStat:
    is_directory:bool
    size:int
    creation_time:float
    access_time:float
    modified_time:float
class BackingStore:
    def initialize(self):pass
    def listdir(self, relative_path):raise NotImplementedError
    def stat(self, relative_path):raise NotImplementedError
    def open_read(self, relative_path):raise NotImplementedError
    def write_file_from_local(self, source_path, relative_path):raise NotImplementedError
    def make_directory(self, relative_path):raise NotImplementedError
    def lexists(self, relative_path):raise NotImplementedError
    def delete(self, relative_path, is_directory):raise NotImplementedError
    def move(self, source_relative_path, destination_relative_path):raise NotImplementedError
    def get_size(self, relative_path):return self.stat(relative_path).size
    def get_hash(self, relative_path):return None
    def describe(self):return type(self).__name__
cldapi=ctypes.WinDLL("cldapi.dll",use_last_error=True)
kernel32=ctypes.WinDLL("kernel32.dll",use_last_error=True)
ntdll=ctypes.WinDLL("ntdll.dll")
ntdll.RtlSetProcessPlaceholderCompatibilityMode.argtypes=[ctypes.c_byte]
ntdll.RtlSetProcessPlaceholderCompatibilityMode.restype=ctypes.c_byte
if ntdll.RtlSetProcessPlaceholderCompatibilityMode(2)<0:raise RuntimeError("Failed to expose Cloud Files placeholders")
MEM_COMMIT=0x1000
MEM_RESERVE=0x2000
PAGE_READWRITE=0x04
MEM_RELEASE=0x8000
PAGE_SIZE=4096
CF_EOF=-1
FILE_ATTRIBUTE_NORMAL=0x80
FILE_ATTRIBUTE_DIRECTORY=0x10
INVALID_FILE_ATTRIBUTES=0xFFFFFFFF
FILE_ATTRIBUTE_REPARSE_POINT=0x400
CF_CALLBACK_TYPE_FETCH_DATA=0
CF_CALLBACK_TYPE_NONE=0xFFFFFFFF
CF_OPERATION_TYPE_TRANSFER_DATA=0
CF_UPDATE_FLAG_NONE=0
CF_UPDATE_FLAG_VERIFY_IN_SYNC=0x01
CF_UPDATE_FLAG_MARK_IN_SYNC=0x02
CF_UPDATE_FLAG_DEHYDRATE=0x04
CF_UPDATE_FLAG_CLEAR_IN_SYNC=0x40
CF_UPDATE_FLAG_PASSTHROUGH_FS_METADATA=0x100
CF_HYDRATION_POLICY_FULL=2
CF_POPULATION_POLICY_ALWAYS_FULL=3
HYDRATION_POLICY=CF_HYDRATION_POLICY_FULL
POPULATION_POLICY=CF_POPULATION_POLICY_ALWAYS_FULL
CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION=1
CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC=2
CF_CREATE_FLAG_NONE=0
CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO=2
CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH=4
CF_OPEN_FILE_FLAG_EXCLUSIVE=1
CF_OPEN_FILE_FLAG_WRITE_ACCESS=2
CF_IN_SYNC_STATE_NOT_IN_SYNC=0
CF_IN_SYNC_STATE_IN_SYNC=1
CF_SET_IN_SYNC_FLAG_NONE=0
STATUS_SUCCESS=0
STATUS_UNSUCCESSFUL=-1073741823
STATUS_CLOUD_FILE_UNSUCCESSFUL=ctypes.c_int32(0xC000CF00).value
FILE_READ_ATTRIBUTES=0x80
CF_PLACEHOLDER_INFO_STANDARD=1
FILE_READ_ATTRIBUTES=0x80
FILE_SHARE_READ=0x01
FILE_SHARE_WRITE=0x02
FILE_SHARE_DELETE=0x04
OPEN_EXISTING=3
INVALID_HANDLE_VALUE=ctypes.c_void_p(-1).value
IGNORE_WRITE=set()
IGNORE_WRITE_LOCK=threading.Lock()
IGNORE_WRITE_WINDOWS={}
IGNORE_WRITE_TTL=600.0
IGNORE_WRITE_EVENT_COALESCE=0.5
class TimestampedEventQueue(queue.Queue):
    def put(self,item,block=True,timeout=None):
        if isinstance(item,tuple) and len(item)==2:
            event=item[0]
            try:setattr(event,"_winfuse_occurred_at",time.monotonic())
            except (AttributeError,TypeError):
                try:object.__setattr__(event,"_winfuse_occurred_at",time.monotonic())
                except (AttributeError,TypeError):pass
        return super().put(item,block,timeout)
def _event_occurred_at(event):
    value=getattr(event,"_winfuse_occurred_at",None)
    return float(value) if value is not None else None
def _ignore_write_key(path):
    normalized=os.path.abspath(os.path.normpath(path))
    if normalized.startswith("\\\\?\\UNC\\"):
        normalized="\\\\"+normalized[8:]
    elif normalized.startswith("\\\\?\\"):
        normalized=normalized[4:]
    return os.path.normcase(normalized)
def _add_ignore_write(path):
    if path is None:return
    key=_ignore_write_key(path)
    now=time.monotonic()
    until=now+IGNORE_WRITE_EVENT_COALESCE
    with IGNORE_WRITE_LOCK:
        windows=IGNORE_WRITE_WINDOWS.get(key,[])
        windows=[(start,end) for start,end in windows if now-end<=IGNORE_WRITE_TTL]
        if windows and now<=windows[-1][1]:
            start,end=windows[-1]
            windows[-1]=(start,max(end,until))
        else:
            windows.append((now,until))
        IGNORE_WRITE_WINDOWS[key]=windows
        IGNORE_WRITE.add(key)
        if len(IGNORE_WRITE_WINDOWS)>4096:
            for stale_key,stale_windows in tuple(IGNORE_WRITE_WINDOWS.items()):
                if stale_windows and now-stale_windows[-1][1]>IGNORE_WRITE_TTL:
                    IGNORE_WRITE_WINDOWS.pop(stale_key,None)
                    IGNORE_WRITE.discard(stale_key)
def _consume_ignore_write(path,occurred_at=None):
    if path is None:return False
    key=_ignore_write_key(path)
    event_time=time.monotonic() if occurred_at is None else float(occurred_at)
    with IGNORE_WRITE_LOCK:
        windows=IGNORE_WRITE_WINDOWS.get(key)
        if not windows:return False
        matched=False
        remaining=[]
        for start,end in windows:
            if event_time<start:
                remaining.append((start,end))
            elif event_time<=end:
                matched=True
                remaining.append((start,end))
        if remaining:
            IGNORE_WRITE_WINDOWS[key]=remaining
        else:
            IGNORE_WRITE_WINDOWS.pop(key,None)
            IGNORE_WRITE.discard(key)
        return matched
def _discard_ignore_write(path):
    if path is None:return
    key=_ignore_write_key(path)
    with IGNORE_WRITE_LOCK:
        IGNORE_WRITE.discard(key)
        IGNORE_WRITE_WINDOWS.pop(key,None)
def hresult_unsigned(hr):return int(hr)&0xFFFFFFFF
def hresult_hex(hr):return f"0x{hresult_unsigned(hr):08X}"
def check_hresult(hr,operation):
    hr=int(hr)
    if hr!=0:raise OSError(f"{operation} failed with HRESULT {hresult_hex(hr)}")
class Node(ctypes.Structure):pass
Node._fields_=[("value",ctypes.c_int),("next",ctypes.POINTER(Node))]
kernel32.VirtualAlloc.argtypes=[ctypes.c_void_p,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]
kernel32.VirtualAlloc.restype=ctypes.c_void_p
kernel32.VirtualFree.argtypes=[ctypes.c_void_p,ctypes.c_size_t,wintypes.DWORD]
kernel32.VirtualFree.restype=wintypes.BOOL
kernel32.GetFileAttributesW.argtypes=[wintypes.LPCWSTR]
kernel32.GetFileAttributesW.restype=wintypes.DWORD
kernel32.DeleteFileW.argtypes=[wintypes.LPCWSTR]
kernel32.DeleteFileW.restype=wintypes.BOOL
kernel32.RemoveDirectoryW.argtypes=[wintypes.LPCWSTR]
kernel32.RemoveDirectoryW.restype=wintypes.BOOL
kernel32.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p]
kernel32.CreateFileW.restype=wintypes.HANDLE
kernel32.CloseHandle.argtypes=[wintypes.HANDLE]
kernel32.CloseHandle.restype=wintypes.BOOL
cldapi.CfOpenFileWithOplock.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.POINTER(ctypes.c_void_p)]
cldapi.CfOpenFileWithOplock.restype=ctypes.HRESULT
cldapi.CfCloseHandle.argtypes=[ctypes.c_void_p]
cldapi.CfCloseHandle.restype=None
cldapi.CfUpdatePlaceholder.argtypes=[wintypes.HANDLE,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(ctypes.c_int64),ctypes.c_void_p]
cldapi.CfUpdatePlaceholder.restype=ctypes.HRESULT
cldapi.CfSetInSyncState.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(ctypes.c_int64)]
cldapi.CfSetInSyncState.restype=ctypes.HRESULT
cldapi.CfRegisterSyncRoot.argtypes=[wintypes.LPCWSTR,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD]
cldapi.CfRegisterSyncRoot.restype=ctypes.HRESULT
cldapi.CfUnregisterSyncRoot.argtypes=[wintypes.LPCWSTR]
cldapi.CfUnregisterSyncRoot.restype=ctypes.HRESULT
cldapi.CfConnectSyncRoot.argtypes=[wintypes.LPCWSTR,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(ctypes.c_int64)]
cldapi.CfConnectSyncRoot.restype=ctypes.HRESULT
cldapi.CfDisconnectSyncRoot.argtypes=[ctypes.c_int64]
cldapi.CfDisconnectSyncRoot.restype=ctypes.HRESULT
cldapi.CfExecute.argtypes=[ctypes.c_void_p,ctypes.c_void_p]
cldapi.CfExecute.restype=ctypes.HRESULT
class GUID(ctypes.Structure):_fields_=[("Data1",wintypes.DWORD),("Data2",wintypes.WORD),("Data3",wintypes.WORD),("Data4",ctypes.c_ubyte*8)]
class LARGE_INTEGER(ctypes.Union):_fields_=[("LowPart",wintypes.DWORD),("HighPart",wintypes.LONG),("QuadPart",ctypes.c_int64)]
class FILE_BASIC_INFO(ctypes.Structure):_fields_=[("CreationTime",LARGE_INTEGER),("LastAccessTime",LARGE_INTEGER),("LastWriteTime",LARGE_INTEGER),("ChangeTime",LARGE_INTEGER),("FileAttributes",wintypes.DWORD),("Reserved",wintypes.DWORD)]
class CF_FS_METADATA(ctypes.Structure):_fields_=[("BasicInfo",FILE_BASIC_INFO),("FileSize",LARGE_INTEGER)]
class CF_PLACEHOLDER_CREATE_INFO(ctypes.Structure):_fields_=[("RelativeFileName",wintypes.LPCWSTR),("FsMetadata",CF_FS_METADATA),("FileIdentity",ctypes.c_void_p),("FileIdentityLength",wintypes.DWORD),("Flags",wintypes.DWORD),("Result",wintypes.LONG),("CreateUsn",ctypes.c_int64)]
class CF_HYDRATION_POLICY(ctypes.Structure):_fields_=[("Primary",wintypes.USHORT),("Modifier",wintypes.USHORT)]
class CF_POPULATION_POLICY(ctypes.Structure):_fields_=[("Primary",wintypes.USHORT),("Modifier",wintypes.USHORT)]
class CF_SYNC_POLICIES(ctypes.Structure):_fields_=[("StructSize",wintypes.ULONG),("Hydration",CF_HYDRATION_POLICY),("Population",CF_POPULATION_POLICY),("InSync",wintypes.ULONG),("HardLink",wintypes.ULONG),("PlaceholderManagement",wintypes.ULONG)]
class CF_SYNC_REGISTRATION(ctypes.Structure):_fields_=[("StructSize",wintypes.ULONG),("ProviderName",wintypes.LPCWSTR),("ProviderVersion",wintypes.LPCWSTR),("SyncRootIdentity",ctypes.c_void_p),("SyncRootIdentityLength",wintypes.DWORD),("FileIdentity",ctypes.c_void_p),("FileIdentityLength",wintypes.DWORD),("ProviderId",GUID)]
class CF_CALLBACK_REGISTRATION(ctypes.Structure):_fields_=[("Type",wintypes.DWORD),("Callback",ctypes.c_void_p)]
class CF_CALLBACK_INFO(ctypes.Structure):_fields_=[("StructSize",wintypes.DWORD),("ConnectionKey",ctypes.c_int64),("CallbackContext",ctypes.c_void_p),("VolumeGuidName",wintypes.LPCWSTR),("VolumeDosName",wintypes.LPCWSTR),("VolumeSerialNumber",wintypes.DWORD),("SyncRootFileId",LARGE_INTEGER),("SyncRootIdentity",ctypes.c_void_p),("SyncRootIdentityLength",wintypes.DWORD),("FileId",LARGE_INTEGER),("FileSize",LARGE_INTEGER),("FileIdentity",ctypes.c_void_p),("FileIdentityLength",wintypes.DWORD),("NormalizedPath",wintypes.LPCWSTR),("TransferKey",ctypes.c_int64),("PriorityHint",ctypes.c_ubyte),("CorrelationVector",ctypes.c_void_p),("ProcessInfo",ctypes.c_void_p),("RequestKey",ctypes.c_int64)]
class _FETCH_DATA_PARAMS(ctypes.Structure):_fields_=[("Flags",wintypes.DWORD),("Padding",wintypes.DWORD),("RequiredFileOffset",LARGE_INTEGER),("RequiredLength",LARGE_INTEGER),("OptionalFileOffset",LARGE_INTEGER),("OptionalLength",LARGE_INTEGER),("LastDehydrationTime",LARGE_INTEGER),("LastDehydrationReason",wintypes.DWORD)]
class _CF_CALLBACK_PARAMETERS_UNION(ctypes.Union):_fields_=[("FetchData",_FETCH_DATA_PARAMS)]
class CF_CALLBACK_PARAMETERS(ctypes.Structure):_fields_=[("ParamSize",wintypes.ULONG),("Union",_CF_CALLBACK_PARAMETERS_UNION)]
class _TRANSFER_DATA(ctypes.Structure):_fields_=[("Flags",wintypes.DWORD),("CompletionStatus",wintypes.LONG),("Buffer",ctypes.c_void_p),("Offset",LARGE_INTEGER),("Length",LARGE_INTEGER)]
class _CF_OPERATION_PARAMETERS_UNION(ctypes.Union):_fields_=[("TransferData",_TRANSFER_DATA)]
class CF_OPERATION_PARAMETERS(ctypes.Structure):_fields_=[("ParamSize",wintypes.ULONG),("Union",_CF_OPERATION_PARAMETERS_UNION)]
class CF_OPERATION_INFO(ctypes.Structure):_fields_=[("StructSize",wintypes.ULONG),("Type",wintypes.ULONG),("ConnectionKey",ctypes.c_int64),("TransferKey",ctypes.c_int64),("CorrelationVector",ctypes.c_void_p),("SyncStatus",ctypes.c_void_p),("RequestKey",ctypes.c_int64)]
class CF_PLACEHOLDER_STANDARD_INFO(ctypes.Structure):_fields_=[("OnDiskDataSize",LARGE_INTEGER),("ValidatedDataSize",LARGE_INTEGER),("ModifiedDataSize",LARGE_INTEGER),("PropertiesSize",LARGE_INTEGER),("PinState",wintypes.DWORD),("InSyncState",wintypes.DWORD),("FileId",LARGE_INTEGER),("SyncRootFileId",LARGE_INTEGER),("FileIdentityLength",wintypes.DWORD),("FileIdentity",ctypes.c_ubyte*1)]
cldapi.CfGetPlaceholderInfo.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
cldapi.CfGetPlaceholderInfo.restype=ctypes.HRESULT
TRANSFER_DATA_PARAM_SIZE=CF_OPERATION_PARAMETERS.Union.offset+ctypes.sizeof(_TRANSFER_DATA)
cldapi.CfCreatePlaceholders.argtypes=[wintypes.LPCWSTR,ctypes.POINTER(CF_PLACEHOLDER_CREATE_INFO),wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
cldapi.CfCreatePlaceholders.restype=ctypes.HRESULT
CF_OPERATION_INFO_PTR=ctypes.POINTER(CF_OPERATION_INFO)
CF_CALLBACK_FUNC=ctypes.WINFUNCTYPE(None,ctypes.c_void_p,ctypes.c_void_p)
refresh_counter=0
def create_guid():
    value = uuid.uuid4()
    guid = GUID()
    ctypes.memmove(ctypes.byref(guid), value.bytes_le, ctypes.sizeof(GUID))
    return guid
def unix_time_to_filetime(value):return int(value * 10_000_000 + 116_444_736_000_000_000)
def make_large_integer(value):
    li = LARGE_INTEGER()
    li.QuadPart = int(value)
    return li
def get_win_attributes(path):
    attrs = kernel32.GetFileAttributesW(path)
    if attrs == INVALID_FILE_ATTRIBUTES:return None
    return attrs
def make_identity(relative_path):
    relative_path = relative_path.replace("/", "\\")
    buffer = ctypes.create_unicode_buffer(relative_path)
    length = ((len(relative_path) + 1) * ctypes.sizeof(ctypes.c_wchar))
    return buffer, length
def join_backend_path(parent, child):return child if not parent else f"{parent}/{child}"
def mount_path_to_backend_path(mount_path):
    mount_path = os.path.abspath(os.path.normpath(mount_path))
    mount_root = os.path.abspath(os.path.normpath(MOUNT_DIR))
    try:relative = os.path.relpath(mount_path, mount_root)
    except ValueError:return None
    if relative == ".":return ""
    if relative == ".." or relative.startswith(".." + os.sep) or os.path.isabs(relative):return None
    return relative.replace(os.sep, "/")
def callback_path_to_mount_path(info):
    volume = info.VolumeDosName
    normalized = info.NormalizedPath
    if not volume or not normalized:return None
    return os.path.abspath(os.path.normpath(volume + normalized))
def callback_path_to_backend_path(info):
    full_mount_path = callback_path_to_mount_path(info)
    if full_mount_path is None:return None
    return mount_path_to_backend_path(full_mount_path)
def build_placeholder_info(backend_directory, entry_name, st):
    is_directory = st.is_directory
    placeholder = CF_PLACEHOLDER_CREATE_INFO()
    name_buffer = ctypes.create_unicode_buffer(entry_name)
    placeholder.RelativeFileName = ctypes.cast(name_buffer, wintypes.LPCWSTR)
    placeholder.FsMetadata.BasicInfo.CreationTime = make_large_integer(unix_time_to_filetime(st.creation_time))
    placeholder.FsMetadata.BasicInfo.LastAccessTime = make_large_integer(unix_time_to_filetime(st.access_time))
    placeholder.FsMetadata.BasicInfo.LastWriteTime = make_large_integer(unix_time_to_filetime(st.modified_time))
    placeholder.FsMetadata.BasicInfo.ChangeTime = make_large_integer(unix_time_to_filetime(st.modified_time))
    placeholder.FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_DIRECTORY if is_directory else FILE_ATTRIBUTE_NORMAL
    placeholder.FsMetadata.BasicInfo.Reserved = 0
    placeholder.FsMetadata.FileSize = make_large_integer(0 if is_directory else st.size)
    relative_identity = join_backend_path(backend_directory, entry_name)
    identity_buffer, identity_length = make_identity(relative_identity)
    placeholder.FileIdentity = ctypes.cast(identity_buffer, ctypes.c_void_p)
    placeholder.FileIdentityLength = identity_length
    placeholder.Flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
    if is_directory:placeholder.Flags |= CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION
    placeholder.Result = 0
    placeholder.CreateUsn = 0
    return placeholder, name_buffer, identity_buffer, relative_identity
def hash_local_file(path):
    h=hashlib.sha512()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024*16),b""):h.update(chunk)
    return h.hexdigest()
def placeholder_data_is_fully_local(info, logical_size):
    logical_size=max(0,int(logical_size))
    if logical_size==0:return True
    on_disk=int(info.OnDiskDataSize.QuadPart)
    validated=int(info.ValidatedDataSize.QuadPart)
    modified=int(info.ModifiedDataSize.QuadPart)
    return on_disk>=logical_size and validated+modified>=logical_size
def get_placeholder_modified_data_size(path):
    attrs=get_win_attributes(path)
    if attrs is None or not attrs&FILE_ATTRIBUTE_REPARSE_POINT:return None
    handle=kernel32.CreateFileW(path,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,None,OPEN_EXISTING,0,None)
    if not handle or handle==INVALID_HANDLE_VALUE:return None
    try:
        buf=ctypes.create_string_buffer(8192)
        returned=wintypes.DWORD()
        hr=cldapi.CfGetPlaceholderInfo(handle,CF_PLACEHOLDER_INFO_STANDARD,buf,len(buf),ctypes.byref(returned))
        if hr!=0:return None
        info=ctypes.cast(buf,ctypes.POINTER(CF_PLACEHOLDER_STANDARD_INFO)).contents
        return max(0,int(info.ModifiedDataSize.QuadPart))
    finally:kernel32.CloseHandle(handle)
def get_local_hash(path):
    attrs=get_win_attributes(path)
    if attrs is None or attrs&FILE_ATTRIBUTE_DIRECTORY:return None
    if attrs&FILE_ATTRIBUTE_REPARSE_POINT:
        handle=kernel32.CreateFileW(path,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,None,OPEN_EXISTING,0,None)
        if not handle or handle==INVALID_HANDLE_VALUE:return None
        try:
            buf=ctypes.create_string_buffer(8192)
            returned=wintypes.DWORD()
            hr=cldapi.CfGetPlaceholderInfo(handle,CF_PLACEHOLDER_INFO_STANDARD,buf,len(buf),ctypes.byref(returned))
            if hr!=0:return None
            info=ctypes.cast(buf,ctypes.POINTER(CF_PLACEHOLDER_STANDARD_INFO)).contents
            logical_size=os.path.getsize(path)
            if not placeholder_data_is_fully_local(info,logical_size):return None
        finally:kernel32.CloseHandle(handle)
    return hash_local_file(path)
def create_single_placeholder(backend,backend_directory,entry_name,mount_directory,mark_internal=None,):
    if is_temporary_file(entry_name):return False
    backend_path = join_backend_path(backend_directory, entry_name)
    st = backend.stat(backend_path)
    placeholder,name_buffer,identity_buffer,relative_identity = build_placeholder_info(backend_directory, entry_name, st)
    placeholder_array = (CF_PLACEHOLDER_CREATE_INFO * 1)(placeholder)
    processed = wintypes.DWORD(0)
    mount_path = os.path.join(mount_directory, entry_name)
    if mark_internal is not None:mark_internal(mount_path, False, True)
    hr = cldapi.CfCreatePlaceholders(ctypes.c_wchar_p(mount_directory),placeholder_array,1,CF_CREATE_FLAG_NONE,ctypes.byref(processed),)
    check_hresult(hr, f"CfCreatePlaceholders({backend_path})")
    if processed.value != 1:raise OSError(f"CfCreatePlaceholders processed {processed.value}/1 entries for {backend_path}")
    result = int(placeholder_array[0].Result)
    if result != 0:raise OSError(f"Placeholder creation failed for {backend_path}: NTSTATUS 0x{result & 0xFFFFFFFF:08X}")
    if mark_internal is not None:mark_internal(mount_path)
    return True
def remove_stale_mount_entry(path, mark_internal=None):
    path = os.path.abspath(path)
    attrs = get_win_attributes(path)
    if attrs is None:return True
    try:
        if attrs & FILE_ATTRIBUTE_DIRECTORY:
            try:children = os.listdir(path)
            except OSError:return False
            for name in children:
                child = os.path.join(path, name)
                if not remove_stale_mount_entry(child, mark_internal):return False
            if mark_internal is not None:mark_internal(path, True)
            ok = kernel32.RemoveDirectoryW(path)
        else:
            if mark_internal is not None:mark_internal(path, True)
            ok = kernel32.DeleteFileW(path)
        if not ok:
            print(f"Failed to remove stale mount entry: {path}; Win32 error={ctypes.get_last_error()}")
            return False
        return True
    except Exception as exc:
        print(f"Error removing stale entry {path}: {exc}")
        return False
def set_mount_file_sync_state(mount_path, in_sync=True):
    attrs = get_win_attributes(mount_path)
    if attrs is None:return False
    if not (attrs & FILE_ATTRIBUTE_REPARSE_POINT):return False
    handle = ctypes.c_void_p()
    hr = cldapi.CfOpenFileWithOplock(ctypes.c_wchar_p(mount_path),CF_OPEN_FILE_FLAG_WRITE_ACCESS,ctypes.byref(handle),)
    if hr != 0 or not handle.value:
        print(f"CfOpenFileWithOplock failed for {mount_path}: {hresult_hex(hr)}")
        return False
    try:
        state = 1 if in_sync else 0
        hr = cldapi.CfSetInSyncState(handle,state,0,None,)
        if hr != 0:
            print(f"CfSetInSyncState failed for {mount_path}: {hresult_hex(hr)}")
            return False
        return True
    finally:cldapi.CfCloseHandle(handle)
def update_mount_file_from_server(backend,backend_path,mount_path,mark_internal,dehydrate=True):
    try:st=backend.stat(backend_path)
    except Exception as e:
        print(f"Cannot stat {backend_path}: {e}")
        return False
    if st.is_directory:return False
    attrs=get_win_attributes(mount_path)
    parent=os.path.dirname(mount_path)
    backend_dir=os.path.dirname(backend_path).replace("\\","/")
    if backend_dir==".":backend_dir=""
    name=os.path.basename(backend_path)
    if attrs is None:
        try:
            os.makedirs(parent,exist_ok=True)
            return create_single_placeholder(backend,backend_dir,name,parent,mark_internal)
        except Exception as e:
            print(f"Cannot create placeholder for {backend_path}: {e}")
            return False
    if not attrs&FILE_ATTRIBUTE_REPARSE_POINT:
        if not remove_stale_mount_entry(mount_path,mark_internal):return False
        try:return create_single_placeholder(backend,backend_dir,name,parent,mark_internal)
        except Exception as e:
            print(f"Cannot replace local file with placeholder {mount_path}: {e}")
            return False
    handle=ctypes.c_void_p()
    hr=cldapi.CfOpenFileWithOplock(mount_path,CF_OPEN_FILE_FLAG_EXCLUSIVE|CF_OPEN_FILE_FLAG_WRITE_ACCESS,ctypes.byref(handle))
    if hr!=0 or not handle.value:
        print(f"Cannot open placeholder {mount_path}: {hresult_hex(hr)}")
        return False
    try:
        hr=cldapi.CfSetInSyncState(handle,CF_IN_SYNC_STATE_IN_SYNC,CF_SET_IN_SYNC_FLAG_NONE,None)
        if hr!=0:
            print(f"CfSetInSyncState failed for {mount_path}: {hresult_hex(hr)}")
            return False
        metadata=CF_FS_METADATA()
        metadata.BasicInfo.CreationTime=make_large_integer(unix_time_to_filetime(st.creation_time))
        metadata.BasicInfo.LastAccessTime=make_large_integer(unix_time_to_filetime(st.access_time))
        metadata.BasicInfo.LastWriteTime=make_large_integer(unix_time_to_filetime(st.modified_time))
        metadata.BasicInfo.ChangeTime=make_large_integer(unix_time_to_filetime(st.modified_time))
        metadata.BasicInfo.FileAttributes=FILE_ATTRIBUTE_NORMAL
        metadata.FileSize=make_large_integer(st.size)
        identity,n=make_identity(join_backend_path(backend_dir,name))
        flags=CF_UPDATE_FLAG_MARK_IN_SYNC|CF_UPDATE_FLAG_PASSTHROUGH_FS_METADATA
        if dehydrate:flags|=CF_UPDATE_FLAG_DEHYDRATE
        if mark_internal:mark_internal(mount_path, True, True)
        hr=cldapi.CfUpdatePlaceholder(handle,ctypes.byref(metadata),ctypes.cast(identity,ctypes.c_void_p),n,None,0,flags,None,None)
        if hr!=0:
            print(f"CfUpdatePlaceholder failed for {mount_path}: {hresult_hex(hr)}")
            return False
        if mark_internal:mark_internal(mount_path)
        return True
    except Exception as e:
        print(f"Refresh failed for {mount_path}: {e}")
        return False
    finally:cldapi.CfCloseHandle(handle)
def collect_backing_files(backend, backend_directory=""):
    files = []
    try:names = backend.listdir(backend_directory)
    except Exception as exc:
        print(f"Cannot list backing directory {backend_directory!r}: {exc}")
        return files
    for entry_name in names:
        if is_temporary_file(entry_name):continue
        backend_path = join_backend_path(backend_directory, entry_name)
        try:
            st = backend.stat(backend_path)
            if st.is_directory:files.extend(collect_backing_files(backend, backend_path))
            else:files.append((backend_path, st))
        except Exception as exc:print(f"Cannot stat {backend_path}: {exc}")
    return files
def check_server_file_updates(backend, mount_directory, journal,is_busy, mark_internal, force=False):
    if type(backend).get_hash is BackingStore.get_hash:return
    files = collect_backing_files(backend, "")
    if not files:return
    existing = {p.replace("\\", "/") for p, _ in files}
    for p in journal.get_all_file_hashes():
        if p not in existing or not backend.lexists(p):journal.delete_file_hash_state(p)
    now = time.time()
    total_files = len(files)
    batch_size = max(1, (total_files + 4) // 5)
    eligible = []
    for backend_path, st in files:
        state = journal.get_file_hash_state(backend_path)
        if force or state is None:
            eligible.append((0.0, backend_path, st, state))
            continue
        due = state.get("next_check")
        if due is None:due = state.get("last_check") or 0.0
        if due <= now:eligible.append((due, backend_path, st, state))
    eligible.sort(key=lambda item: (item[0], item[1]))
    selected = []
    for item in eligible:
        if not force and is_busy(item[1]):continue
        selected.append(item)
        if len(selected) >= batch_size:break
    for _, backend_path, st, state in selected:
        now = time.time()
        old_hash = state["hash"] if state else None
        old_local = state.get("local_hash") if state else None
        old_mtime = state.get("backing_mtime") if state else None
        unchanged = int(state.get("unchanged_checks") or 0) if state else 0
        try:
            if not backend.lexists(backend_path):
                journal.delete_file_hash_state(backend_path)
                continue
            new_size = int(backend.get_size(backend_path))
            new_hash = backend.get_hash(backend_path)
            if new_hash is None:
                journal.set_file_hash_state(backend_path, old_hash, now, 5, old_local)
                journal.schedule_file_check(backend_path, now + 5, st.modified_time, unchanged)
                continue
            mount_path = os.path.join(mount_directory, backend_path.replace("/", os.sep))
            attrs = get_win_attributes(mount_path)
            backing_changed = (state is None or old_hash is None or new_hash != old_hash)
            mtime_changed = (old_mtime is not None and st.modified_time != old_mtime)
            mount_missing = attrs is None
            mount_size = None
            if not mount_missing:
                try:mount_size = os.stat(mount_path).st_size
                except OSError:mount_missing = True
            size_changed = (not mount_missing and mount_size != new_size)
            modified_data_size = get_placeholder_modified_data_size(mount_path) if attrs is not None else None
            if modified_data_size is None and attrs is not None and attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                journal.set_file_hash_state(backend_path, old_hash, now, 5, old_local)
                journal.schedule_file_check(backend_path, now + 5, st.modified_time, unchanged)
                continue
            if modified_data_size:
                journal.set_file_hash_state(backend_path, old_hash, now, 5, old_local)
                journal.schedule_file_check(backend_path, now + 5, st.modified_time, unchanged)
                continue
            if mount_missing or backing_changed or size_changed:
                if not update_mount_file_from_server(backend, backend_path, mount_path, mark_internal, dehydrate=True):
                    journal.set_file_hash_state(backend_path, old_hash, now, 5, old_local)
                    journal.schedule_file_check(backend_path, now + 5, st.modified_time, unchanged)
                    print(f"[refresh] failed: {backend_path}; retrying")
                    continue
            elif mtime_changed:
                if not update_mount_file_from_server(backend, backend_path, mount_path, mark_internal, dehydrate=False):
                    journal.set_file_hash_state(backend_path, old_hash, now, 5, old_local)
                    journal.schedule_file_check(backend_path, now + 5, st.modified_time, unchanged)
                    continue
            journal.set_file_hash_state(backend_path, new_hash, now, 5, new_hash)
            if backing_changed or mtime_changed or size_changed:unchanged = 0
            else:unchanged = min(unchanged + 1, 5)
            interval = min(5 * (unchanged + 1), 30)
            journal.schedule_file_check(backend_path, time.time() + interval, st.modified_time, unchanged)
        except Exception as e:
            retry_time = time.time() + 5
            journal.set_file_hash_state(backend_path, old_hash, time.time(), 5, old_local)
            journal.schedule_file_check(backend_path, retry_time, st.modified_time, unchanged)
            print(f"[refresh] error for {backend_path}: {e}; retrying in 5 seconds")
def refresh_directory(backend,backend_directory,mount_directory,is_busy,mark_internal=None,journal=None):
    if is_busy(backend_directory):return
    os.makedirs(mount_directory,exist_ok=True)
    try:backend_names = {name for name in backend.listdir(backend_directory) if not is_temporary_file(name)}
    except OSError:return
    try:mount_names = {name for name in os.listdir(mount_directory) if not is_temporary_file(name)}
    except OSError:return
    for name in sorted(backend_names-mount_names):
        bp=join_backend_path(backend_directory,name)
        if is_busy(bp):continue
        try:
            created=create_single_placeholder(backend,backend_directory,name,mount_directory,mark_internal)
            if created and journal and type(backend).get_hash is not BackingStore.get_hash:
                remote_hash=backend.get_hash(bp)
                if remote_hash is not None:
                    now=time.time()
                    st=backend.stat(bp)
                    journal.set_file_hash_state(bp,remote_hash,now,5,remote_hash)
                    journal.schedule_file_check(bp,now+5,st.modified_time,0)
        except Exception as e:print(f"Cannot create {bp}: {e}")
    for name in sorted(mount_names-backend_names):
        bp=join_backend_path(backend_directory,name)
        if is_busy(bp):continue
        path=os.path.join(mount_directory,name)
        attrs=get_win_attributes(path)
        if attrs is None:continue
        state=journal.get_file_hash_state(bp) if journal else None
        if attrs&FILE_ATTRIBUTE_REPARSE_POINT or state is not None:
            remove_stale_mount_entry(path,mark_internal)
            if journal:journal.delete_file_hash_state(bp)
        elif attrs&FILE_ATTRIBUTE_DIRECTORY:
            try:
                backend.make_directory(bp)
                refresh_directory(backend,bp,path,is_busy,mark_internal,journal)
            except Exception as e:print(f"Cannot upload directory {bp}: {e}")
        else:
            try:
                backend.write_file_from_local(path,bp)
                local_hash=hash_local_file(path)
                remote=backend.get_hash(bp) if type(backend).get_hash is not BackingStore.get_hash else local_hash
                if remote is not None and journal:journal.set_file_hash_state(bp,remote,time.time(),5,local_hash)
            except Exception as e:print(f"Cannot upload local-only file {bp}: {e}")
    for name in sorted(backend_names&mount_names):
        bp=join_backend_path(backend_directory,name)
        try:st=backend.stat(bp)
        except OSError:continue
        child=os.path.join(mount_directory,name)
        if st.is_directory and not is_busy(bp):refresh_directory(backend,bp,child,is_busy,mark_internal,journal)
def refresh_mount(backend,mount_directory,is_busy,journal,mark_internal=None,force_hash_check=False):
    refresh_directory(backend,"",mount_directory,is_busy,mark_internal,journal)
    check_server_file_updates(backend,mount_directory,journal,is_busy,mark_internal,force_hash_check)
def _cf_execute_transfer_data(connection_key,transfer_key,request_key,offset,data=None,failure_length=0,completion_status=STATUS_SUCCESS,):
    transfer_length = (len(data) if data is not None else int(failure_length))
    if transfer_length < 0:raise ValueError("Negative transfer length")
    buffer_ptr = None
    try:
        if data is not None and completion_status == STATUS_SUCCESS:
            if not data:raise ValueError("Cannot transfer empty data")
            alloc_size = (len(data) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
            buffer_ptr = kernel32.VirtualAlloc(None,alloc_size,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE)
            if not buffer_ptr:raise MemoryError("VirtualAlloc failed")
            ctypes.memmove(buffer_ptr, data, len(data))
        op_info = CF_OPERATION_INFO()
        op_info.StructSize = ctypes.sizeof(CF_OPERATION_INFO)
        op_info.Type = CF_OPERATION_TYPE_TRANSFER_DATA
        op_info.ConnectionKey = connection_key
        op_info.TransferKey = transfer_key
        op_info.RequestKey = request_key
        op_params = CF_OPERATION_PARAMETERS()
        op_params.ParamSize = TRANSFER_DATA_PARAM_SIZE
        transfer = op_params.Union.TransferData
        transfer.Flags = 0
        transfer.CompletionStatus = completion_status
        transfer.Buffer = buffer_ptr
        transfer.Offset = make_large_integer(offset)
        transfer.Length = make_large_integer(transfer_length)
        hr = cldapi.CfExecute(ctypes.byref(op_info),ctypes.byref(op_params),)
        check_hresult(hr, "CfExecute(TRANSFER_DATA)")
    finally:
        if buffer_ptr:kernel32.VirtualFree(buffer_ptr, 0, MEM_RELEASE)
def _cf_fail_fetch(connection_key,transfer_key,request_key,offset,length,logical_size,):
    offset = max(0, int(offset))
    start = offset & ~(PAGE_SIZE - 1)
    if length == CF_EOF:requested_end = max(start, int(logical_size))
    elif length >= 0:requested_end = max(start + PAGE_SIZE,offset + int(length),)
    else:requested_end = start + PAGE_SIZE
    end = max(start + PAGE_SIZE, requested_end)
    failure_length = (end - start + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    _cf_execute_transfer_data(connection_key,transfer_key,request_key,start,data=None,failure_length=failure_length,completion_status=STATUS_CLOUD_FILE_UNSUCCESSFUL,)
def on_fetch_data(callback_info_ptr, callback_parameters_ptr):
    try:
        info = ctypes.cast(callback_info_ptr,ctypes.POINTER(CF_CALLBACK_INFO),).contents
        params = ctypes.cast(callback_parameters_ptr,ctypes.POINTER(CF_CALLBACK_PARAMETERS),).contents
        offset = int(params.Union.FetchData.RequiredFileOffset.QuadPart)
        length = int(params.Union.FetchData.RequiredLength.QuadPart)
        connection_key = int(info.ConnectionKey)
        transfer_key = int(info.TransferKey)
        request_key = int(info.RequestKey)
        logical_size = max(0, int(info.FileSize.QuadPart))
        backend = ACTIVE_BACKING_STORE
        backend_path = callback_path_to_backend_path(info)
        mount_path = (os.path.abspath(os.path.join(MOUNT_DIR, backend_path.replace("/", os.sep))) if backend_path is not None else None)
    except Exception as exc:
        print(f"Invalid FETCH_DATA callback: {exc}")
        return
    def worker():
        try:
            if backend is None:raise RuntimeError("Backing store is unavailable")
            if backend_path is None:raise ValueError("Could not resolve callback path to backing path")
            if offset < 0 or offset > logical_size:raise ValueError(f"Invalid fetch offset {offset}; logical size is {logical_size}")
            if length < 0 and length != CF_EOF:raise ValueError(f"Invalid fetch length {length}")
            if length == CF_EOF:required_end = logical_size
            else:required_end = min(logical_size,offset + length,)
            if required_end <= offset:raise ValueError(f"Empty or stale fetch range: offset={offset}, length={length}, logical_size={logical_size}")
            start = offset & ~(PAGE_SIZE - 1)
            if required_end >= logical_size:end = logical_size
            else:end = min(logical_size,(required_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1),)
            if end <= start:raise ValueError(f"Invalid aligned range [{start}, {end})")
            st = backend.stat(backend_path)
            if st.is_directory:raise IsADirectoryError(backend_path)
            if st.size < end:raise IOError(f"Backing file is too short for fetch: {backend_path}; backing_size={st.size}, required_end={end}. The placeholder may need a metadata refresh.")
            with backend.open_read(backend_path) as f:
                current_offset = start
                while current_offset < end:
                    remaining = end - current_offset
                    chunk_size = min(FETCH_CHUNK_SIZE,remaining,)
                    if current_offset + chunk_size < end:chunk_size &= ~(PAGE_SIZE - 1)
                    if chunk_size <= 0:raise ValueError("Invalid transfer chunk size")
                    f.seek(current_offset)
                    data = f.read(chunk_size)
                    if len(data) != chunk_size:raise IOError(f"Short read from {backend_path}: wanted {chunk_size}, got {len(data)}")
                    _add_ignore_write(mount_path)
                    _cf_execute_transfer_data(connection_key,transfer_key,request_key,current_offset,data=data,completion_status=STATUS_SUCCESS,)
                    current_offset += len(data)
        except Exception as exc:
            _discard_ignore_write(mount_path)
            print(f"FETCH_DATA failed for {backend_path!r}: {exc}")
            try:_cf_fail_fetch(connection_key,transfer_key,request_key,offset,length,logical_size,)
            except Exception as completion_exc:print(f"Could not complete failed FETCH_DATA for {backend_path!r}: {completion_exc}")
    threading.Thread(target=worker,name="CfFetchData",daemon=True,).start()
cb_fetch_data = CF_CALLBACK_FUNC(on_fetch_data)
CALLBACK_REGISTRATIONS=(CF_CALLBACK_REGISTRATION*2)()
CALLBACK_REGISTRATIONS[0].Callback=ctypes.cast(cb_fetch_data,ctypes.c_void_p)
CALLBACK_REGISTRATIONS[0].Type=CF_CALLBACK_TYPE_FETCH_DATA
CALLBACK_REGISTRATIONS[1].Type=CF_CALLBACK_TYPE_NONE
CALLBACK_REGISTRATIONS[1].Callback=None
def mount_path_signature(path):
    attrs = get_win_attributes(path)
    if attrs is None:return None
    try:
        st = os.stat(path)
        return (attrs,st.st_size,st.st_mtime_ns,st.st_ctime_ns,)
    except OSError:return ("stat-error", attrs)
def is_temporary_file(path):
    name = os.path.basename(path).lower()
    out=any([x in name for x in (".tmp", ".crdownload", ".part", ".download", ".temp", '.bak')]) or "~" in name
    return out
class SyncJournal:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        self._lock = threading.RLock()
        self._db = None
    def initialize(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS file_hashes (backend_path TEXT PRIMARY KEY, hash TEXT, local_hash TEXT, last_check REAL, cooldown REAL, next_check REAL, backing_mtime REAL, unchanged_checks INTEGER NOT NULL DEFAULT 0)")
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(file_hashes)")}
        migrations = {"local_hash": "TEXT","next_check": "REAL","backing_mtime": "REAL","unchanged_checks": "INTEGER NOT NULL DEFAULT 0",}
        for name, definition in migrations.items():
            if name not in cols:self._db.execute(f"ALTER TABLE file_hashes ADD COLUMN {name} {definition}")
        self._db.execute("UPDATE file_hashes SET next_check = COALESCE(next_check, last_check, 0)")
        self._db.execute("CREATE TABLE IF NOT EXISTS operations (id INTEGER PRIMARY KEY AUTOINCREMENT, operation TEXT NOT NULL, source_path TEXT, destination_path TEXT, backend_path TEXT, is_directory INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL)")
        self._db.commit()
    def get_file_hash_state(self, backend_path):
        with self._lock:row = self._db.execute("SELECT hash, local_hash, last_check, cooldown, next_check, backing_mtime, unchanged_checks FROM file_hashes WHERE backend_path = ?", (backend_path.replace("\\", "/"),)).fetchone()
        if row is None:return None
        return {"hash": row[0],"local_hash": row[1],"last_check": row[2],"cooldown": row[3],"next_check": row[4],"backing_mtime": row[5],"unchanged_checks": row[6],}
    def set_file_hash_state(self, backend_path, file_hash, last_check, cooldown, local_hash=None):
        with self._lock:
            self._db.execute("INSERT INTO file_hashes (backend_path, hash, local_hash, last_check, cooldown, next_check) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(backend_path) DO UPDATE SET hash = excluded.hash, local_hash = COALESCE(excluded.local_hash, file_hashes.local_hash), last_check = excluded.last_check, cooldown = excluded.cooldown, next_check = excluded.next_check", (backend_path.replace("\\", "/"),file_hash,local_hash,last_check,cooldown,last_check + cooldown,))
            self._db.commit()
    def schedule_file_check(self, backend_path, next_check,backing_mtime, unchanged_checks):
        with self._lock:
            self._db.execute("UPDATE file_hashes SET next_check = ?, backing_mtime = ?, unchanged_checks = ? WHERE backend_path = ?", (next_check,backing_mtime,unchanged_checks,backend_path.replace("\\", "/"),))
            self._db.commit()
    def delete_file_hash_state(self, backend_path):
        with self._lock:
            self._db.execute("DELETE FROM file_hashes WHERE backend_path=?", (backend_path.replace("\\", "/"),))
            self._db.commit()
    def get_all_file_hashes(self):
        with self._lock:
            rows = self._db.execute("SELECT backend_path FROM file_hashes").fetchall()
            return [row[0] for row in rows]
    def cancel_writes_for(self, source_path=None, backend_path=None):
        with self._lock:
            conditions, values = [], []
            if source_path is not None:
                conditions.append("source_path=?")
                values.append(os.path.abspath(source_path))
            if backend_path is not None:
                conditions.append("backend_path=?")
                values.append(backend_path.replace("\\", "/"))
            if not conditions:return
            self._db.execute(f"DELETE FROM operations WHERE operation='write' AND ({' OR '.join(conditions)})", values)
            self._db.commit()
    def add(self, operation, source_path=None, destination_path=None, backend_path=None, is_directory=False):
        with self._lock:
            cursor = self._db.execute("INSERT INTO operations (operation, source_path, destination_path, backend_path, is_directory, created_at) VALUES (?, ?, ?, ?, ?, ?)", (operation, source_path, destination_path, backend_path, int(is_directory), time.time()))
            self._db.commit()
            return cursor.lastrowid
    def remove(self, operation_id):
        with self._lock:
            self._db.execute("DELETE FROM operations WHERE id=?", (operation_id,))
            self._db.commit()
    def pending(self):
        try:
            with self._lock:rows = self._db.execute("SELECT id, operation, source_path, destination_path, backend_path, is_directory FROM operations ORDER BY id").fetchall()
            return [{"id":r[0], "operation":r[1], "source_path":r[2], "destination_path":r[3], "backend_path":r[4], "is_directory":bool(r[5])} for r in rows]
        except sqlite3.OperationalError:return []
    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
class MountSyncHandler(FileSystemEventHandler):
    def __init__(self, mount_dir, backing_store, journal):
        super().__init__()
        self.mount_dir = os.path.abspath(mount_dir)
        self.backing_store = backing_store
        self.journal = journal
        self._lock = threading.RLock()
        self._active_folders = set()
        self._internal_paths = {}
    def _get_backend_path(self, mount_path):return mount_path_to_backend_path(mount_path)
    def _folder_for(self, backend_path):return os.path.dirname(backend_path).replace("\\", "/")
    def _mark_internal(self, path, allow_delete=False, allow_change=False):
        path = os.path.abspath(path)
        signature = mount_path_signature(path)
        now = time.monotonic()
        with self._lock:
            previous = self._internal_paths.get(path)
            preserve_delete = bool(allow_delete or (previous is not None and previous[0] > now and len(previous) > 2 and previous[2]))
            preserve_change = bool(allow_change or (previous is not None and previous[0] > now and len(previous) > 3 and previous[3]))
            self._internal_paths[path] = (now + 2.0, signature, preserve_delete, preserve_change)
    def _is_internal(self, path, for_delete=False):
        path = os.path.abspath(path)
        now = time.monotonic()
        with self._lock:
            entry = self._internal_paths.get(path)
            if entry is None:return False
            expiry, expected_signature = entry[0], entry[1]
            allow_delete = bool(entry[2]) if len(entry) > 2 else False
            allow_change = bool(entry[3]) if len(entry) > 3 else False
            if expiry <= now:
                del self._internal_paths[path]
                return False
            if for_delete and allow_delete:return True
            current_signature = mount_path_signature(path)
            if current_signature == expected_signature:return True
            if allow_change:
                self._internal_paths[path] = (expiry, current_signature, allow_delete, False)
                return True
            del self._internal_paths[path]
            return False
    def _begin_operation(self, folders):
        folders = {f.replace("\\", "/").rstrip("/") for f in folders if f is not None}
        with self._lock:self._active_folders.update(folders)
        return folders
    def _end_operation(self, folders):
        with self._lock:
            for f in folders:self._active_folders.discard(f)
    def is_folder_busy(self, backend_path):
        backend_path = backend_path.replace("\\", "/").rstrip("/")
        with self._lock:
            for folder in self._active_folders:
                if not folder or backend_path == folder or backend_path.startswith(folder + "/") or folder.startswith(backend_path + "/"):return True
        return False
    def _run_journaled(self, operation, folders, **kwargs):
        journal_id = self.journal.add(operation, **kwargs)
        active = self._begin_operation(folders)
        try:
            if operation == "write":self._copy_file_now(kwargs["source_path"], kwargs["backend_path"])
            elif operation == "mkdir":self.backing_store.make_directory(kwargs["backend_path"])
            elif operation == "delete":
                self.backing_store.delete(kwargs["backend_path"], kwargs["is_directory"])
                self.journal.delete_file_hash_state(kwargs["backend_path"])
            elif operation == "move":self.backing_store.move(kwargs["source_path"], kwargs["destination_path"])
            self.journal.remove(journal_id)
        finally:self._end_operation(active)
    @staticmethod
    def _source_signature(path):
        st = os.stat(path)
        return (st.st_size,st.st_mtime_ns,st.st_ctime_ns,)
    def _copy_file_now(self,source_path,backend_path):
        hashing=type(self.backing_store).get_hash is not BackingStore.get_hash
        for attempt in range(10):
            try:
                if not os.path.isfile(source_path):raise FileNotFoundError(source_path)
                before=self._source_signature(source_path)
                time.sleep(0.15)
                stable=self._source_signature(source_path)
                if before!=stable:
                    time.sleep(0.1*(attempt+1))
                    continue
                state = self.journal.get_file_hash_state(backend_path)
                local_hash_before = hash_local_file(source_path) if hashing else None
                known_local_hash = state.get("local_hash") if state else None
                if hashing and self.backing_store.lexists(backend_path):
                    remote = self.backing_store.get_hash(backend_path)
                    backing_changed = (remote is not None and state is not None and state.get("hash") is not None and remote != state["hash"])
                    local_unchanged = (known_local_hash is not None and local_hash_before == known_local_hash)
                    if backing_changed and local_unchanged:
                        if not update_mount_file_from_server(self.backing_store,backend_path,source_path,self._mark_internal,):raise OSError(f"Backing changed; could not refresh {source_path}")
                        self.journal.set_file_hash_state(backend_path, remote, time.time(), 5, remote)
                        return
                self.backing_store.write_file_from_local(source_path,backend_path)
                if self._source_signature(source_path)!=stable:
                    time.sleep(0.1*(attempt+1))
                    continue
                local_hash=hash_local_file(source_path)
                attrs=get_win_attributes(source_path)
                if attrs is not None and attrs&FILE_ATTRIBUTE_REPARSE_POINT:
                    if not set_mount_file_sync_state(source_path,True):print(f"Warning: upload succeeded but in-sync marking failed: {source_path}")
                remote=self.backing_store.get_hash(backend_path) if hashing else local_hash
                if remote is None:raise OSError(f"Could not verify backing write: {backend_path}")
                self.journal.set_file_hash_state(backend_path,remote,time.time(),5,local_hash)
                self._mark_internal(source_path)
                return
            except Exception as e:
                if attempt==9:raise
                time.sleep(0.1*(attempt+1))
    def _copy_file(self, source_path, backend_path, event_time=None):
        if _consume_ignore_write(source_path,event_time):return
        folder = self._folder_for(backend_path)
        try:self._run_journaled("write",{folder},source_path=os.path.abspath(source_path),backend_path=backend_path,)
        except Exception as exc:print(f"Upload failed: {source_path} -> {backend_path}: {exc}")
    def on_created(self, event):
        event_time=_event_occurred_at(event)
        if _consume_ignore_write(event.src_path,event_time):return
        if self._is_internal(event.src_path):return
        if not event.is_directory and is_temporary_file(event.src_path):return
        backend_path = self._get_backend_path(event.src_path)
        if backend_path is None:return
        if event.is_directory:
            try:self._run_journaled("mkdir", {backend_path}, backend_path=backend_path, is_directory=True)
            except Exception:pass
            return
        self._copy_file(event.src_path, backend_path, event_time)
    def on_modified(self, event):
        event_time=_event_occurred_at(event)
        if _consume_ignore_write(event.src_path,event_time):return
        if (event.is_directory or is_temporary_file(event.src_path) or self._is_internal(event.src_path)):return
        backend_path = self._get_backend_path(event.src_path)
        if backend_path is None:return
        self._copy_file(event.src_path, backend_path, event_time)
    def on_deleted(self, event):
        if not event.is_directory and is_temporary_file(event.src_path):return
        if self._is_internal(event.src_path, for_delete=True):return
        backend_path = self._get_backend_path(event.src_path)
        if backend_path is None:return
        self.journal.cancel_writes_for(source_path=event.src_path, backend_path=backend_path)
        self.journal.delete_file_hash_state(backend_path)
        if not self.backing_store.lexists(backend_path):return
        try:
            folder = self._folder_for(backend_path)
            self._run_journaled("delete", {folder}, backend_path=backend_path, is_directory=event.is_directory)
        except Exception:pass
    def on_moved(self, event):
        event_time=_event_occurred_at(event)
        if self._is_internal(event.src_path) or self._is_internal(event.dest_path):return
        source_backend = self._get_backend_path(event.src_path)
        destination_backend = self._get_backend_path(event.dest_path)
        if source_backend is None or destination_backend is None:return
        source_temp = not event.is_directory and is_temporary_file(event.src_path)
        destination_temp = not event.is_directory and is_temporary_file(event.dest_path)
        if destination_temp:return
        if source_temp and not destination_temp:
            if os.path.isfile(event.dest_path):self._copy_file(event.dest_path, destination_backend, event_time)
            return
        self.journal.delete_file_hash_state(source_backend)
        source_folder = self._folder_for(source_backend)
        destination_folder = self._folder_for(destination_backend)
        if not self.backing_store.lexists(source_backend):
            if not event.is_directory and os.path.isfile(event.dest_path):self._copy_file(event.dest_path, destination_backend, event_time)
            return
        try:self._run_journaled("move",{source_folder, destination_folder},source_path=source_backend,destination_path=destination_backend,is_directory=event.is_directory,)
        except Exception as exc:print(f"Move failed: {source_backend} -> {destination_backend}: {exc}")
def register_sync_root():
    registration = CF_SYNC_REGISTRATION()
    registration.StructSize = ctypes.sizeof(CF_SYNC_REGISTRATION)
    registration.ProviderName = ctypes.c_wchar_p(PROVIDER_NAME)
    registration.ProviderVersion = ctypes.c_wchar_p(PROVIDER_VERSION)
    registration.SyncRootIdentity = None
    registration.SyncRootIdentityLength = 0
    registration.FileIdentity = None
    registration.FileIdentityLength = 0
    registration.ProviderId = create_guid()
    policies = CF_SYNC_POLICIES()
    policies.StructSize = ctypes.sizeof(CF_SYNC_POLICIES)
    policies.Hydration.Primary = HYDRATION_POLICY
    policies.Population.Primary = POPULATION_POLICY
    hr = cldapi.CfRegisterSyncRoot(ctypes.c_wchar_p(MOUNT_DIR), ctypes.byref(registration), ctypes.byref(policies), 0)
    check_hresult(hr, "CfRegisterSyncRoot")
def unregister_sync_root():
    try:cldapi.CfUnregisterSyncRoot(ctypes.c_wchar_p(MOUNT_DIR))
    except Exception:pass
def connect_sync_root():
    connection_key = ctypes.c_int64(0)
    connect_flags = (CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH)
    hr = cldapi.CfConnectSyncRoot(ctypes.c_wchar_p(MOUNT_DIR), ctypes.byref(CALLBACK_REGISTRATIONS), None, connect_flags, ctypes.byref(connection_key))
    check_hresult(hr, "CfConnectSyncRoot")
    return connection_key.value
def replay_journal(journal, backing_store):
    pending = journal.pending()
    if not pending:return
    for item in pending:
        operation_id = item["id"]
        operation = item["operation"]
        try:
            if operation == "write":
                source_path = item["source_path"]
                if not os.path.isfile(source_path):
                    journal.remove(operation_id)
                    continue
                backing_store.write_file_from_local(source_path, item["backend_path"])
            elif operation == "mkdir":backing_store.make_directory(item["backend_path"])
            elif operation == "delete":
                if backing_store.lexists(item["backend_path"]):backing_store.delete(item["backend_path"], item["is_directory"])
                journal.delete_file_hash_state(item["backend_path"])
            elif operation == "move":
                if backing_store.lexists(item["source_path"]):backing_store.move(item["source_path"], item["destination_path"])
            journal.remove(operation_id)
        except Exception:pass
def main(backing_store, mount_dir):
    global ACTIVE_BACKING_STORE, MOUNT_DIR
    MOUNT_DIR = os.path.abspath(mount_dir)
    if os.name != "nt":raise RuntimeError("This program requires Windows.")
    if backing_store is None:raise ValueError("A backing store is required.")
    if ACTIVE_BACKING_STORE is not None:raise RuntimeError("A Cloud Files mirror is already running.")
    ACTIVE_BACKING_STORE = backing_store
    backing_store.initialize()
    os.makedirs(MOUNT_DIR, exist_ok=True)
    journal = SyncJournal(JOURNAL_PATH)
    journal.initialize()
    connection_key, observer, refresh_thread = None, None, None
    stop_event = threading.Event()
    try:
        unregister_sync_root()
        os.makedirs(MOUNT_DIR, exist_ok=True)
        replay_journal(journal, backing_store)
        register_sync_root()
        refresh_mount(backing_store,MOUNT_DIR,lambda path:False,journal,force_hash_check=True)
        connection_key = connect_sync_root()
        event_handler = MountSyncHandler(MOUNT_DIR, backing_store, journal)
        refresh_mount(backing_store, MOUNT_DIR, event_handler.is_folder_busy, journal, event_handler._mark_internal)
        observer = Observer()
        observer._event_queue = TimestampedEventQueue()
        observer.schedule(event_handler, MOUNT_DIR, recursive=True)
        observer.start()
        def refresh_worker():
            last_refresh = time.time() - REFRESH_INTERVAL
            while not stop_event.wait(max(REFRESH_INTERVAL - (time.time() - last_refresh), 0.5)):
                try:refresh_mount(backing_store, MOUNT_DIR, event_handler.is_folder_busy, journal, event_handler._mark_internal)
                except Exception:pass
                last_refresh = time.time()
        refresh_thread = threading.Thread(target=refresh_worker, name="MountRefresh", daemon=True)
        refresh_thread.start()
        print(f"[*] Mount:{MOUNT_DIR}")
        print(f"[*] Journal:{os.path.abspath(JOURNAL_PATH)}")
        print(f"[*] Namespace refresh:every {REFRESH_INTERVAL}s")
        while True:time.sleep(10)
    except KeyboardInterrupt:pass
    finally:
        stop_event.set()
        if refresh_thread is not None:refresh_thread.join(timeout=2)
        if observer is not None:
            try:
                observer.stop()
                observer.join()
            except Exception:pass
        if connection_key is not None:
            try:cldapi.CfDisconnectSyncRoot(connection_key)
            except Exception:pass
        unregister_sync_root()
        journal.close()
        ACTIVE_BACKING_STORE = None
if __name__ == "__main__":
    class LocalStorageBackend(BackingStore):
        def __init__(self, root_directory):self.root_directory = os.path.abspath(root_directory)
        def _full_path(self, relative_path):
            if not relative_path:return self.root_directory
            relative_path = relative_path.replace("/", os.sep)
            full_path = os.path.abspath(os.path.join(self.root_directory, relative_path))
            try:common = os.path.commonpath([self.root_directory, full_path])
            except ValueError:raise ValueError(f"Invalid backing path:{relative_path!r}")
            if os.path.normcase(common) != os.path.normcase(self.root_directory):raise ValueError(f"Backing path escapes root:{relative_path!r}")
            return full_path
        def initialize(self):os.makedirs(self.root_directory, exist_ok=True)
        def listdir(self, relative_path):return os.listdir(self._full_path(relative_path))
        def stat(self, relative_path):
            st = os.stat(self._full_path(relative_path))
            return BackingStat(is_directory=stat.S_ISDIR(st.st_mode), size=st.st_size, creation_time=st.st_ctime, access_time=st.st_atime, modified_time=st.st_mtime)
        def open_read(self, relative_path):return open(self._full_path(relative_path), "rb")
        def write_file_from_local(self, source_path, relative_path):
            destination_path = self._full_path(relative_path)
            os.makedirs(os.path.dirname(destination_path), exist_ok=True)
            temporary_path = destination_path + f".tmp.{os.getpid()}.{threading.get_ident()}"
            try:
                for attempt in range(10):
                    try:
                        if not os.path.isfile(source_path):return
                        time.sleep(0.05)
                        shutil.copy2(source_path, temporary_path)
                        os.replace(temporary_path, destination_path)
                        return
                    except Exception as e:
                        if attempt == 9:raise e
                        time.sleep(0.10 * (attempt + 1))
            finally:
                if os.path.exists(temporary_path):
                    try:os.remove(temporary_path)
                    except OSError:pass
        def make_directory(self, relative_path):os.makedirs(self._full_path(relative_path), exist_ok=True)
        def lexists(self, relative_path):return os.path.lexists(self._full_path(relative_path))
        def delete(self, relative_path, is_directory):
            path = self._full_path(relative_path)
            if not os.path.lexists(path):return
            if is_directory:shutil.rmtree(path, ignore_errors=True)
            else:
                try:os.remove(path)
                except FileNotFoundError:pass
        def move(self, source_relative_path, destination_relative_path):
            source_path = self._full_path(source_relative_path)
            destination_path = self._full_path(destination_relative_path)
            os.makedirs(os.path.dirname(destination_path), exist_ok=True)
            if os.path.lexists(destination_path):
                if os.path.isdir(destination_path):shutil.rmtree(destination_path, ignore_errors=True)
                else:os.remove(destination_path)
            shutil.move(source_path, destination_path)
        def get_hash(self, relative_path):
            full_path = self._full_path(relative_path)
            try:st = os.stat(full_path)
            except FileNotFoundError:return None
            token = f"{st.st_dev}:{st.st_ino}:{st.st_size}:{st.st_mtime_ns}:{st.st_ctime_ns}"
            return hashlib.sha512(token.encode("ascii")).hexdigest()
    main(LocalStorageBackend(".\\storage"), '.\\mount')