#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <cfapi.h>
#include <bcrypt.h>
#include <pybind11/pybind11.h>
#include <pybind11/eval.h>
#include <pybind11/stl.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cwctype>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <exception>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#pragma comment(lib, "cldapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
namespace py = pybind11;
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
struct WinFuseTransferDataParameters {
    CF_OPERATION_TRANSFER_DATA_FLAGS Flags;
    NTSTATUS CompletionStatus;
    LPCVOID Buffer;
    LARGE_INTEGER Offset;
    LARGE_INTEGER Length;
};
namespace {
constexpr std::size_t FETCH_CHUNK_SIZE = 16u * 1024u * 1024u;
constexpr DWORD PAGE_SIZE = 4096;
constexpr std::int64_t CF_EOF_VALUE = -1;
constexpr DWORD CF_UPDATE_FLAG_MARK_IN_SYNC_VALUE = 0x02;
constexpr DWORD CF_UPDATE_FLAG_DEHYDRATE_VALUE = 0x04;
constexpr DWORD CF_UPDATE_FLAG_PASSTHROUGH_FS_METADATA_VALUE = 0x100;
constexpr DWORD CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION_VALUE = 0x01;
constexpr DWORD CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC_VALUE = 0x02;
constexpr DWORD CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO_VALUE = 0x02;
constexpr DWORD CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH_VALUE = 0x04;
constexpr DWORD CF_OPEN_FILE_FLAG_EXCLUSIVE_VALUE = 0x01;
constexpr DWORD CF_OPEN_FILE_FLAG_WRITE_ACCESS_VALUE = 0x02;
constexpr DWORD CF_PLACEHOLDER_INFO_STANDARD_VALUE = 1;
constexpr LONG STATUS_SUCCESS_VALUE = 0;
constexpr LONG STATUS_CLOUD_FILE_UNSUCCESSFUL_VALUE = static_cast<LONG>(0xC000CF00u);
constexpr DWORD REFRESH_INTERVAL_SECONDS = 5;
constexpr double IGNORE_WRITE_TTL_SECONDS = 600.0;
constexpr double IGNORE_WRITE_COALESCE_SECONDS = 0.5;
constexpr wchar_t PROVIDER_NAME[] = L"PythonCfApiMirror";
constexpr wchar_t PROVIDER_VERSION[] = L"1.0";
using FileTimeTicks = std::int64_t;
static std::atomic<class Engine*> g_active_engine{nullptr};
static std::mutex g_active_mutex;
py::object python_unicode(const std::wstring& value) {
    PyObject* raw = PyUnicode_FromWideChar(value.data(), static_cast<Py_ssize_t>(value.size()));
    if (!raw) throw py::error_already_set();
    return py::reinterpret_steal<py::object>(raw);
}
std::wstring utf8_to_wide(const std::string& value) {
    if (value.empty()) return {};
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                   static_cast<int>(value.size()), nullptr, 0);
    if (count <= 0) throw std::runtime_error("Invalid UTF-8 path/string");
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), result.data(), count);
    return result;
}
std::string wide_to_utf8(const std::wstring& value) {
    if (value.empty()) return {};
    int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                    static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (count <= 0) throw std::runtime_error("Could not encode Windows path as UTF-8");
    std::string result(static_cast<std::size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), result.data(), count, nullptr, nullptr);
    return result;
}
std::wstring normalize_windows_path(const std::wstring& input) {
    std::wstring value = fs::absolute(fs::path(input)).lexically_normal().wstring();
    if (value.rfind(L"\\\\?\\UNC\\", 0) == 0) value = L"\\\\" + value.substr(8);
    else if (value.rfind(L"\\\\?\\", 0) == 0) value = value.substr(4);
    while (value.size() > 3 && (value.back() == L'\\' || value.back() == L'/')) value.pop_back();
    return value;
}
std::wstring lower_windows(std::wstring value) {
    for (auto& ch : value) ch = static_cast<wchar_t>(std::towlower(ch));
    return value;
}
std::string normalize_backend_path(std::string value) {
    std::replace(value.begin(), value.end(), '\\', '/');
    while (!value.empty() && value.front() == '/') value.erase(value.begin());
    while (!value.empty() && value.back() == '/') value.pop_back();
    return value;
}
std::string join_backend_path(const std::string& parent, const std::string& child) {
    if (parent.empty()) return normalize_backend_path(child);
    if (child.empty()) return normalize_backend_path(parent);
    return normalize_backend_path(parent) + "/" + normalize_backend_path(child);
}
std::string parent_backend_path(const std::string& path) {
    const auto p = path.find_last_of('/');
    return p == std::string::npos ? std::string{} : path.substr(0, p);
}
std::string base_backend_path(const std::string& path) {
    const auto p = path.find_last_of('/');
    return p == std::string::npos ? path : path.substr(p + 1);
}
std::wstring replace_slashes(std::wstring value) {
    std::replace(value.begin(), value.end(), L'/', L'\\');
    return value;
}
std::wstring backend_path_to_wide(const std::string& path) {
    return replace_slashes(utf8_to_wide(path));
}
std::uint64_t unix_time_to_filetime(double value) {
    constexpr long double EPOCH_DELTA = 116444736000000000.0L;
    long double ticks = static_cast<long double>(value) * 10000000.0L + EPOCH_DELTA;
    if (ticks < 0) ticks = 0;
    if (ticks > static_cast<long double>(std::numeric_limits<std::uint64_t>::max()))
        ticks = static_cast<long double>(std::numeric_limits<std::uint64_t>::max());
    return static_cast<std::uint64_t>(ticks);
}
LARGE_INTEGER make_large_integer(double value) {
    LARGE_INTEGER result{};
    result.QuadPart = static_cast<LONGLONG>(unix_time_to_filetime(value));
    return result;
}
FILETIME make_filetime(double value) {
    ULARGE_INTEGER ticks{};
    ticks.QuadPart = unix_time_to_filetime(value);
    FILETIME ft{};
    ft.dwLowDateTime = ticks.LowPart;
    ft.dwHighDateTime = ticks.HighPart;
    return ft;
}
std::string hresult_hex(HRESULT hr) {
    std::ostringstream out;
    out << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0')
        << static_cast<std::uint32_t>(hr);
    return out.str();
}
void check_hresult(HRESULT hr, const char* operation) {
    if (hr != S_OK) throw std::runtime_error(std::string(operation) + " failed with HRESULT " + hresult_hex(hr));
}
void log_error(const std::string& message) {
    std::cerr << message << std::endl;
}
bool is_temporary_file(const std::wstring& path) {
    std::wstring name = fs::path(path).filename().wstring();
    std::transform(name.begin(), name.end(), name.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    static const std::array<std::wstring, 6> markers = {L".tmp", L".crdownload", L".part", L".download", L".temp", L".bak"};
    for (const auto& marker : markers) if (name.find(marker) != std::wstring::npos) return true;
    return name.find(L'~') != std::wstring::npos;
}
DWORD get_win_attributes(const std::wstring& path) {
    DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes == INVALID_FILE_ATTRIBUTES ? INVALID_FILE_ATTRIBUTES : attributes;
}
bool exists_win(const std::wstring& path) {
    return get_win_attributes(path) != INVALID_FILE_ATTRIBUTES;
}
std::wstring absolute_path(const std::wstring& path) {
    return normalize_windows_path(path);
}
struct FileSignature {
    bool valid = false;
    DWORD attributes = 0;
    std::uint64_t size = 0;
    FILETIME creation{};
    FILETIME modified{};
    bool operator==(const FileSignature& other) const {
        return valid == other.valid && (!valid || (
            attributes == other.attributes && size == other.size &&
            CompareFileTime(&creation, &other.creation) == 0 &&
            CompareFileTime(&modified, &other.modified) == 0));
    }
};
FileSignature mount_path_signature(const std::wstring& path) {
    FileSignature signature;
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return signature;
    signature.valid = true;
    signature.attributes = data.dwFileAttributes;
    signature.size = (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
    signature.creation = data.ftCreationTime;
    signature.modified = data.ftLastWriteTime;
    return signature;
}
struct BackingStat {
    bool is_directory = false;
    std::uint64_t size = 0;
    double creation_time = 0;
    double access_time = 0;
    double modified_time = 0;
};
class BackendAdapter {
public:
    explicit BackendAdapter(py::object backend) : backend_(std::move(backend)) {}
    void initialize() const {
        py::gil_scoped_acquire gil;
        backend_.attr("initialize")();
    }
    std::vector<std::string> listdir(const std::string& relative_path) const {
        py::gil_scoped_acquire gil;
        py::object result = backend_.attr("listdir")(py::str(relative_path));
        std::vector<std::string> names;
        for (py::handle item : result) {
            std::wstring wide = py::cast<std::wstring>(item);
            names.push_back(wide_to_utf8(wide));
        }
        return names;
    }
    BackingStat stat(const std::string& relative_path) const {
        py::gil_scoped_acquire gil;
        try {
            py::object value = backend_.attr("stat")(py::str(relative_path));
            BackingStat result;
            result.is_directory = py::cast<bool>(value.attr("is_directory"));
            result.size = py::cast<std::uint64_t>(value.attr("size"));
            result.creation_time = py::cast<double>(value.attr("creation_time"));
            result.access_time = py::cast<double>(value.attr("access_time"));
            result.modified_time = py::cast<double>(value.attr("modified_time"));
            return result;
        } catch (py::error_already_set& error) {
            const std::string message = error.what();
            throw std::runtime_error("Python backing-store stat() failed: " + message);
        }
    }
    void write_file_from_local(const std::wstring& source_path, const std::string& relative_path) const {
        py::gil_scoped_acquire gil;
        backend_.attr("write_file_from_local")(python_unicode(source_path), py::str(relative_path));
    }
    void make_directory(const std::string& relative_path) const {
        py::gil_scoped_acquire gil;
        backend_.attr("make_directory")(py::str(relative_path));
    }
    bool lexists(const std::string& relative_path) const {
        py::gil_scoped_acquire gil;
        return py::cast<bool>(backend_.attr("lexists")(py::str(relative_path)));
    }
    void delete_path(const std::string& relative_path, bool is_directory) const {
        py::gil_scoped_acquire gil;
        backend_.attr("delete")(py::str(relative_path), py::bool_(is_directory));
    }
    void move_path(const std::string& source, const std::string& destination) const {
        py::gil_scoped_acquire gil;
        backend_.attr("move")(py::str(source), py::str(destination));
    }
    std::uint64_t get_size(const std::string& relative_path) const {
        py::gil_scoped_acquire gil;
        return py::cast<std::uint64_t>(backend_.attr("get_size")(py::str(relative_path)));
    }
    std::optional<std::string> get_hash(const std::string& relative_path) const {
        py::gil_scoped_acquire gil;
        py::object value = backend_.attr("get_hash")(py::str(relative_path));
        if (value.is_none()) return std::nullopt;
        return py::cast<std::string>(value);
    }
    std::string read_range(const std::string& relative_path, std::uint64_t offset, std::size_t length) const {
        py::gil_scoped_acquire gil;
        py::object stream = py::none();
        try {
            stream = backend_.attr("open_read")(py::str(relative_path));
            stream.attr("seek")(offset);
            py::object value = stream.attr("read")(length);
            std::string bytes = py::cast<std::string>(value);
            if (py::hasattr(stream, "close")) stream.attr("close")();
            return bytes;
        } catch (py::error_already_set& error) {
            const std::string message = error.what();
            try { if (!stream.is_none() && py::hasattr(stream, "close")) stream.attr("close")(); } catch (...) {}
            throw std::runtime_error("Python backing-store read failed: " + message);
        } catch (...) {
            try { if (!stream.is_none() && py::hasattr(stream, "close")) stream.attr("close")(); } catch (...) {}
            throw;
        }
    }
private:
    py::object backend_;
};
struct FileHashState {
    std::optional<std::string> hash;
    std::optional<std::string> local_hash;
    std::optional<double> last_check;
    std::optional<double> cooldown;
    std::optional<double> next_check;
    std::optional<double> backing_mtime;
    int unchanged_checks = 0;
};
struct PendingOperation {
    std::int64_t id = 0;
    std::string operation;
    std::wstring source_path;
    std::wstring destination_path;
    std::string backend_path;
    bool is_directory = false;
};
class SyncJournal {
public:
    explicit SyncJournal(std::wstring path) : path_(std::move(path)) {}
    void initialize() {
        py::gil_scoped_acquire gil;
        fs::path parent = fs::path(path_).parent_path();
        if (!parent.empty()) fs::create_directories(parent);
        py::object sqlite3 = py::module_::import("sqlite3");
        db_ = sqlite3.attr("connect")(python_unicode(path_), py::arg("check_same_thread") = false);
        db_.attr("execute")(
            "CREATE TABLE IF NOT EXISTS file_hashes (backend_path TEXT PRIMARY KEY, hash TEXT, local_hash TEXT, last_check REAL, cooldown REAL, next_check REAL, backing_mtime REAL, unchanged_checks INTEGER NOT NULL DEFAULT 0)");
        py::object cols = db_.attr("execute")("PRAGMA table_info(file_hashes)");
        std::set<std::string> existing;
        for (py::handle row_handle : cols) {
            auto row = py::reinterpret_borrow<py::sequence>(row_handle);
            existing.insert(py::cast<std::string>(row[1]));
        }
        const std::array<std::pair<const char*, const char*>, 4> migrations = {{
            {"local_hash", "TEXT"}, {"next_check", "REAL"},
            {"backing_mtime", "REAL"}, {"unchanged_checks", "INTEGER NOT NULL DEFAULT 0"}
        }};
        for (const auto& migration : migrations) {
            if (!existing.count(migration.first)) {
                std::string sql = "ALTER TABLE file_hashes ADD COLUMN ";
                sql += migration.first; sql += " "; sql += migration.second;
                db_.attr("execute")(sql);
            }
        }
        db_.attr("execute")("UPDATE file_hashes SET next_check = COALESCE(next_check, last_check, 0)");
        db_.attr("execute")(
            "CREATE TABLE IF NOT EXISTS operations (id INTEGER PRIMARY KEY AUTOINCREMENT, operation TEXT NOT NULL, source_path TEXT, destination_path TEXT, backend_path TEXT, is_directory INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL)");
        db_.attr("commit")();
    }
    std::optional<FileHashState> get_file_hash_state(const std::string& backend_path) {
        py::gil_scoped_acquire gil;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        py::object row = db_.attr("execute")(
            "SELECT hash, local_hash, last_check, cooldown, next_check, backing_mtime, unchanged_checks FROM file_hashes WHERE backend_path = ?",
            py::make_tuple(normalize_backend_path(backend_path))).attr("fetchone")();
        if (row.is_none()) return std::nullopt;
        FileHashState state;
        state.hash = optional_string(row[0]);
        state.local_hash = optional_string(row[1]);
        state.last_check = optional_double(row[2]);
        state.cooldown = optional_double(row[3]);
        state.next_check = optional_double(row[4]);
        state.backing_mtime = optional_double(row[5]);
        state.unchanged_checks = row[6].is_none() ? 0 : py::cast<int>(row[6]);
        return state;
    }
    void set_file_hash_state(const std::string& backend_path,
                             const std::optional<std::string>& file_hash,
                             double last_check, double cooldown,
                             const std::optional<std::string>& local_hash = std::nullopt) {
        py::gil_scoped_acquire gil;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        db_.attr("execute")(
            "INSERT INTO file_hashes (backend_path, hash, local_hash, last_check, cooldown, next_check) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(backend_path) DO UPDATE SET hash = excluded.hash, local_hash = COALESCE(excluded.local_hash, file_hashes.local_hash), last_check = excluded.last_check, cooldown = excluded.cooldown, next_check = excluded.next_check",
            py::make_tuple(normalize_backend_path(backend_path), optional_py(file_hash), optional_py(local_hash),
                           last_check, cooldown, last_check + cooldown));
        db_.attr("commit")();
    }
    void schedule_file_check(const std::string& backend_path, double next_check,
                             double backing_mtime, int unchanged_checks) {
        py::gil_scoped_acquire gil;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        db_.attr("execute")(
            "UPDATE file_hashes SET next_check = ?, backing_mtime = ?, unchanged_checks = ? WHERE backend_path = ?",
            py::make_tuple(next_check, backing_mtime, unchanged_checks, normalize_backend_path(backend_path)));
        db_.attr("commit")();
    }
    void delete_file_hash_state(const std::string& backend_path) {
        py::gil_scoped_acquire gil;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        db_.attr("execute")("DELETE FROM file_hashes WHERE backend_path = ?",
                            py::make_tuple(normalize_backend_path(backend_path)));
        db_.attr("commit")();
    }
    std::vector<std::string> get_all_file_hashes() {
        py::gil_scoped_acquire gil;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        py::object rows = db_.attr("execute")("SELECT backend_path FROM file_hashes").attr("fetchall")();
        std::vector<std::string> values;
        for (py::handle row_handle : rows) {
            auto row = py::reinterpret_borrow<py::sequence>(row_handle);
            values.push_back(py::cast<std::string>(row[0]));
        }
        return values;
    }
    void cancel_writes_for(const std::optional<std::wstring>& source_path,
                           const std::optional<std::string>& backend_path) {
        py::gil_scoped_acquire gil;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        std::string sql = "DELETE FROM operations WHERE operation='write' AND (";
        std::vector<py::object> values;
        bool need_or = false;
        if (source_path) {
            sql += "source_path=?";
            values.push_back(python_unicode(absolute_path(*source_path)));
            need_or = true;
        }
        if (backend_path) {
            if (need_or) sql += " OR ";
            sql += "backend_path=?";
            values.push_back(py::str(normalize_backend_path(*backend_path)));
            need_or = true;
        }
        if (!need_or) return;
        sql += ")";
        PyObject* raw_tuple = PyTuple_New(static_cast<Py_ssize_t>(values.size()));
        if (!raw_tuple) throw py::error_already_set();
        py::tuple params = py::reinterpret_steal<py::tuple>(raw_tuple);
        for (std::size_t i = 0; i < values.size(); ++i) {
            PyObject* item = values[i].ptr();
            Py_INCREF(item);
            PyTuple_SET_ITEM(params.ptr(), static_cast<Py_ssize_t>(i), item);
        }
        db_.attr("execute")(sql, params);
        db_.attr("commit")();
    }
    std::int64_t add(const std::string& operation,
                     const std::optional<std::wstring>& source_path,
                     const std::optional<std::wstring>& destination_path,
                     const std::optional<std::string>& backend_path,
                     bool is_directory) {
        py::gil_scoped_acquire gil;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        py::object cursor = db_.attr("execute")(
            "INSERT INTO operations (operation, source_path, destination_path, backend_path, is_directory, created_at) VALUES (?, ?, ?, ?, ?, ?) ",
            py::make_tuple(operation, source_path ? python_unicode(operation == "move" ? *source_path : absolute_path(*source_path)) : py::none(),
                           destination_path ? python_unicode(operation == "move" ? *destination_path : absolute_path(*destination_path)) : py::none(),
                           backend_path ? py::cast(normalize_backend_path(*backend_path)) : py::none(),
                           is_directory ? 1 : 0, unix_now()));
        db_.attr("commit")();
        return py::cast<std::int64_t>(cursor.attr("lastrowid"));
    }
    void remove(std::int64_t operation_id) {
        py::gil_scoped_acquire gil;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        db_.attr("execute")("DELETE FROM operations WHERE id = ?", py::make_tuple(operation_id));
        db_.attr("commit")();
    }
    std::vector<PendingOperation> pending() {
        py::gil_scoped_acquire gil;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        py::object rows = db_.attr("execute")(
            "SELECT id, operation, source_path, destination_path, backend_path, is_directory FROM operations ORDER BY id").attr("fetchall")();
        std::vector<PendingOperation> result;
        for (py::handle row_handle : rows) {
            auto row = py::reinterpret_borrow<py::sequence>(row_handle);
            PendingOperation item;
            item.id = py::cast<std::int64_t>(row[0]);
            item.operation = py::cast<std::string>(row[1]);
            if (!row[2].is_none()) item.source_path = py::cast<std::wstring>(row[2]);
            if (!row[3].is_none()) item.destination_path = py::cast<std::wstring>(row[3]);
            if (!row[4].is_none()) item.backend_path = py::cast<std::string>(row[4]);
            item.is_directory = py::cast<int>(row[5]) != 0;
            result.push_back(std::move(item));
        }
        return result;
    }
    void close() {
        py::gil_scoped_acquire gil;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (!db_.is_none()) {
            db_.attr("close")();
            db_ = py::none();
        }
    }
private:
    static double unix_now() {
        return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
    }
    static py::object optional_py(const std::optional<std::string>& value) {
        return value ? py::cast(*value) : py::none();
    }
    static std::optional<std::string> optional_string(py::handle value) {
        if (value.is_none()) return std::nullopt;
        return py::cast<std::string>(value);
    }
    static std::optional<double> optional_double(py::handle value) {
        if (value.is_none()) return std::nullopt;
        return py::cast<double>(value);
    }
    std::wstring path_;
    py::object db_ = py::none();
    std::recursive_mutex mutex_;
};
struct InternalEntry {
    Clock::time_point expires;
    FileSignature signature;
    bool allow_delete = false;
    bool allow_change = false;
};
struct IgnoreWindow {
    Clock::time_point start;
    Clock::time_point end;
};
struct FetchRequest {
    CF_CONNECTION_KEY connection_key{};
    CF_TRANSFER_KEY transfer_key{};
    CF_REQUEST_KEY request_key{};
    std::int64_t offset = 0;
    std::int64_t length = 0;
    std::int64_t logical_size = 0;
    std::string backend_path;
    std::wstring mount_path;
};
class Engine {
public:
    Engine(py::object backend, const std::wstring& mount_dir,
           bool supports_hash, const std::wstring& journal_path)
        : backend_(std::move(backend)),
          mount_dir_(absolute_path(mount_dir)),
          journal_(journal_path),
          supports_hash_(supports_hash) {}
    ~Engine() {
        try { stop(); } catch (...) {}
    }
    void start() {
        if (started_) throw std::runtime_error("This Cloud Files mirror is already running.");
        {
            std::lock_guard<std::mutex> lock(g_active_mutex);
            if (g_active_engine.load() != nullptr)
                throw std::runtime_error("A Cloud Files mirror is already running.");
            g_active_engine.store(this);
        }
        try {
            using RtlSetModeFn = LONG(NTAPI*)(UCHAR);
            auto ntdll = GetModuleHandleW(L"ntdll.dll");
            auto set_mode = reinterpret_cast<RtlSetModeFn>(GetProcAddress(ntdll, "RtlSetProcessPlaceholderCompatibilityMode"));
            if (!set_mode || set_mode(2) < 0)
                throw std::runtime_error("Failed to expose Cloud Files placeholders");
            backend_.initialize();
            fs::create_directories(fs::path(mount_dir_));
            journal_.initialize();
            journal_open_ = true;
            unregister_sync_root();
            fs::create_directories(fs::path(mount_dir_));
            replay_journal();
            register_sync_root();
            refresh_mount(false, true);
            connect_sync_root();
            refresh_mount(false, false);
            started_ = true;
            stopping_ = false;
        } catch (...) {
            if (connection_connected_) { CfDisconnectSyncRoot(connection_key_); connection_connected_ = false; }
            try { unregister_sync_root(); } catch (...) {}
            try { journal_.close(); } catch (...) {}
            journal_open_ = false;
            g_active_engine.store(nullptr);
            throw;
        }
    }
    void stop() {
        if (!started_ && !journal_open_) {
            Engine* expected = this;
            g_active_engine.compare_exchange_strong(expected, nullptr);
            return;
        }
        {
            std::lock_guard<std::mutex> lock(fetch_mutex_);
            stopping_ = true;
        }
        if (connection_connected_) {
            CfDisconnectSyncRoot(connection_key_);
            connection_connected_ = false;
        }
        Engine* expected = this;
        g_active_engine.compare_exchange_strong(expected, nullptr);
        std::vector<FetchWorker> workers;
        {
            std::lock_guard<std::mutex> lock(fetch_mutex_);
            workers.swap(fetch_threads_);
        }
        for (auto& worker : workers) if (worker.thread.joinable()) worker.thread.join();
        unregister_sync_root();
        try { journal_.close(); } catch (...) {}
        started_ = false;
        journal_open_ = false;
    }
    void refresh() {
        ensure_started();
        refresh_mount(false, false);
    }
    bool is_folder_busy(const std::wstring& path) const {
        const auto backend_path = mount_path_to_backend_path(path);
        if (!backend_path) return false;
        const std::string normalized = normalize_backend_path(*backend_path);
        std::lock_guard<std::mutex> lock(operation_mutex_);
        for (const auto& folder : active_folders_) {
            if (folder.empty() || normalized == folder ||
                (normalized.size() > folder.size() && normalized.compare(0, folder.size(), folder) == 0 && normalized[folder.size()] == '/') ||
                (folder.size() > normalized.size() && folder.compare(0, normalized.size(), normalized) == 0 && folder[normalized.size()] == '/'))
                return true;
        }
        return false;
    }
    void on_created(const std::wstring& path, bool is_directory, double event_time) {
        if (consume_ignore_write(path, event_time)) return;
        if (is_internal(path, false)) return;
        if (!is_directory && is_temporary_file(path)) return;
        auto backend_path = mount_path_to_backend_path(path);
        if (!backend_path) return;
        if (is_directory) {
            try { run_journaled("mkdir", {*backend_path}, std::nullopt, std::nullopt, *backend_path, true); }
            catch (const std::exception& e) { log_error(std::string("Directory creation sync failed: ") + e.what()); }
            return;
        }
        copy_file(path, *backend_path, event_time);
    }
    void on_modified(const std::wstring& path, bool is_directory, double event_time) {
        if (consume_ignore_write(path, event_time)) return;
        if (is_directory || is_temporary_file(path) || is_internal(path, false)) return;
        auto backend_path = mount_path_to_backend_path(path);
        if (!backend_path) return;
        copy_file(path, *backend_path, event_time);
    }
    void on_deleted(const std::wstring& path, bool is_directory) {
        if (!is_directory && is_temporary_file(path)) return;
        if (is_internal(path, true)) return;
        auto backend_path = mount_path_to_backend_path(path);
        if (!backend_path) return;
        journal_.cancel_writes_for(path, *backend_path);
        journal_.delete_file_hash_state(*backend_path);
        if (!backend_.lexists(*backend_path)) return;
        try {
            const std::string folder = parent_backend_path(*backend_path);
            run_journaled("delete", {folder}, std::nullopt, std::nullopt, *backend_path, is_directory);
        } catch (const std::exception& e) {
            log_error(std::string("Delete sync failed: ") + e.what());
        }
    }
    void on_moved(const std::wstring& source_path, const std::wstring& destination_path,
                  bool is_directory, double event_time) {
        if (is_internal(source_path, false) || is_internal(destination_path, false)) return;
        auto source_backend = mount_path_to_backend_path(source_path);
        auto destination_backend = mount_path_to_backend_path(destination_path);
        if (!source_backend || !destination_backend) return;
        const bool source_temp = !is_directory && is_temporary_file(source_path);
        const bool destination_temp = !is_directory && is_temporary_file(destination_path);
        if (destination_temp) return;
        if (source_temp && !destination_temp) {
            if (GetFileAttributesW(destination_path.c_str()) != INVALID_FILE_ATTRIBUTES)
                copy_file(destination_path, *destination_backend, event_time);
            return;
        }
        journal_.delete_file_hash_state(*source_backend);
        const std::string source_folder = parent_backend_path(*source_backend);
        const std::string destination_folder = parent_backend_path(*destination_backend);
        if (!backend_.lexists(*source_backend)) {
            if (!is_directory && GetFileAttributesW(destination_path.c_str()) != INVALID_FILE_ATTRIBUTES)
                copy_file(destination_path, *destination_backend, event_time);
            return;
        }
        try {
            run_journaled("move", {source_folder, destination_folder},
                          utf8_to_wide(*source_backend), utf8_to_wide(*destination_backend),
                          std::nullopt, is_directory);
        } catch (const std::exception& e) {
            log_error("Move failed: " + *source_backend + " -> " + *destination_backend + ": " + e.what());
        }
    }
private:
    void ensure_started() const {
        if (!started_) throw std::runtime_error("The Cloud Files mirror has not been started.");
    }
    static double monotonic_seconds() {
        return std::chrono::duration<double>(Clock::now().time_since_epoch()).count();
    }
    std::optional<std::string> mount_path_to_backend_path(const std::wstring& path) const {
        std::wstring full;
        try { full = absolute_path(path); } catch (...) { return std::nullopt; }
        const std::wstring root = mount_dir_;
        const std::wstring full_lower = lower_windows(full);
        const std::wstring root_lower = lower_windows(root);
        if (full_lower.size() < root_lower.size() || full_lower.compare(0, root_lower.size(), root_lower) != 0)
            return std::nullopt;
        const bool root_has_separator = !root_lower.empty() && (root_lower.back() == L'\\' || root_lower.back() == L'/');
        if (!root_has_separator && full_lower.size() > root_lower.size() &&
            full_lower[root_lower.size()] != L'\\' && full_lower[root_lower.size()] != L'/')
            return std::nullopt;
        std::wstring relative = full.substr(root.size());
        while (!relative.empty() && (relative.front() == L'\\' || relative.front() == L'/')) relative.erase(relative.begin());
        if (relative == L"." || relative.empty()) return std::string{};
        fs::path rel(relative);
        for (const auto& part : rel) if (part == L"..") return std::nullopt;
        return normalize_backend_path(wide_to_utf8(relative));
    }
    std::wstring mount_path_for_backend(const std::string& backend_path) const {
        return (fs::path(mount_dir_) / fs::path(backend_path_to_wide(backend_path))).lexically_normal().wstring();
    }
    void mark_internal(const std::wstring& path, bool allow_delete = false, bool allow_change = false) {
        const std::wstring key = lower_windows(absolute_path(path));
        const auto now = Clock::now();
        const auto signature = mount_path_signature(path);
        std::lock_guard<std::mutex> lock(internal_mutex_);
        auto it = internal_paths_.find(key);
        bool preserve_delete = allow_delete;
        bool preserve_change = allow_change;
        if (it != internal_paths_.end() && it->second.expires > now) {
            preserve_delete = preserve_delete || it->second.allow_delete;
            preserve_change = preserve_change || it->second.allow_change;
        }
        internal_paths_[key] = InternalEntry{now + std::chrono::seconds(2), signature, preserve_delete, preserve_change};
    }
    bool is_internal(const std::wstring& path, bool for_delete) {
        const std::wstring key = lower_windows(absolute_path(path));
        const auto now = Clock::now();
        std::lock_guard<std::mutex> lock(internal_mutex_);
        auto it = internal_paths_.find(key);
        if (it == internal_paths_.end()) return false;
        auto& entry = it->second;
        if (entry.expires <= now) { internal_paths_.erase(it); return false; }
        if (for_delete && entry.allow_delete) return true;
        const FileSignature current = mount_path_signature(path);
        if (current == entry.signature) return true;
        if (entry.allow_change) {
            entry.signature = current;
            entry.allow_change = false;
            return true;
        }
        internal_paths_.erase(it);
        return false;
    }
    void add_ignore_write(const std::wstring& path) {
        if (path.empty()) return;
        const auto key = lower_windows(absolute_path(path));
        const auto now = Clock::now();
        const auto until = now + std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(IGNORE_WRITE_COALESCE_SECONDS));
        std::lock_guard<std::mutex> lock(ignore_mutex_);
        auto& windows = ignore_windows_[key];
        windows.erase(std::remove_if(windows.begin(), windows.end(), [now](const IgnoreWindow& w) {
            return std::chrono::duration<double>(now - w.end).count() > IGNORE_WRITE_TTL_SECONDS;
        }), windows.end());
        if (!windows.empty() && now <= windows.back().end) windows.back().end = std::max(windows.back().end, until);
        else windows.push_back(IgnoreWindow{now, until});
        if (ignore_windows_.size() > 4096) {
            for (auto it = ignore_windows_.begin(); it != ignore_windows_.end();) {
                if (!it->second.empty() && std::chrono::duration<double>(now - it->second.back().end).count() > IGNORE_WRITE_TTL_SECONDS)
                    it = ignore_windows_.erase(it);
                else ++it;
            }
        }
    }
    bool consume_ignore_write(const std::wstring& path, double occurred_at) {
        if (path.empty()) return false;
        const auto key = lower_windows(absolute_path(path));
        const auto event_time = Clock::time_point(Clock::duration(static_cast<Clock::duration::rep>(occurred_at * Clock::period::den / Clock::period::num)));
        std::lock_guard<std::mutex> lock(ignore_mutex_);
        auto it = ignore_windows_.find(key);
        if (it == ignore_windows_.end()) return false;
        bool matched = false;
        std::vector<IgnoreWindow> remaining;
        for (const auto& window : it->second) {
            if (event_time < window.start) remaining.push_back(window);
            else if (event_time <= window.end) { matched = true; remaining.push_back(window); }
        }
        if (remaining.empty()) ignore_windows_.erase(it);
        else it->second = std::move(remaining);
        return matched;
    }
    void begin_operation(const std::set<std::string>& folders) {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        for (const auto& folder : folders) active_folders_.insert(normalize_backend_path(folder));
    }
    void end_operation(const std::set<std::string>& folders) {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        for (const auto& folder : folders) active_folders_.erase(normalize_backend_path(folder));
    }
    void run_journaled(const std::string& operation, const std::set<std::string>& folders,
                       const std::optional<std::wstring>& source_path,
                       const std::optional<std::wstring>& destination_path,
                       const std::optional<std::string>& backend_path,
                       bool is_directory) {
        const auto id = journal_.add(operation, source_path, destination_path, backend_path, is_directory);
        begin_operation(folders);
        try {
            if (operation == "write") {
                if (!source_path || !backend_path) throw std::runtime_error("Write operation is missing a source/backend path");
                copy_file_now(*source_path, *backend_path);
            } else if (operation == "mkdir") {
                if (!backend_path) throw std::runtime_error("Mkdir operation is missing a backend path");
                backend_.make_directory(*backend_path);
            } else if (operation == "delete") {
                if (!backend_path) throw std::runtime_error("Delete operation is missing a backend path");
                backend_.delete_path(*backend_path, is_directory);
                journal_.delete_file_hash_state(*backend_path);
            } else if (operation == "move") {
                if (!source_path || !destination_path) throw std::runtime_error("Move operation is missing a path");
                backend_.move_path(wide_to_utf8(*source_path), wide_to_utf8(*destination_path));
            }
            journal_.remove(id);
        } catch (...) {
            end_operation(folders);
            throw;
        }
        end_operation(folders);
    }
    struct SourceSignature {
        std::uint64_t size = 0;
        FILETIME modified{};
        FILETIME creation{};
        bool valid = false;
        bool operator==(const SourceSignature& other) const {
            return valid == other.valid && (!valid || (size == other.size &&
                CompareFileTime(&modified, &other.modified) == 0 && CompareFileTime(&creation, &other.creation) == 0));
        }
    };
    SourceSignature source_signature(const std::wstring& path) const {
        WIN32_FILE_ATTRIBUTE_DATA data{};
        if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return {};
        SourceSignature result;
        result.valid = true;
        result.size = (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
        result.modified = data.ftLastWriteTime;
        result.creation = data.ftCreationTime;
        return result;
    }
    void copy_file(const std::wstring& source_path, const std::string& backend_path, double event_time) {
        if (consume_ignore_write(source_path, event_time)) return;
        const std::string folder = parent_backend_path(backend_path);
        try {
            run_journaled("write", {folder}, source_path, std::nullopt, backend_path, false);
        } catch (const std::exception& e) {
            log_error("Upload failed: " + wide_to_utf8(source_path) + " -> " + backend_path + ": " + e.what());
        }
    }
    void copy_file_now(const std::wstring& source_path, const std::string& backend_path) {
        for (int attempt = 0; attempt < 10; ++attempt) {
            try {
                DWORD attrs = get_win_attributes(source_path);
                if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY))
                    throw std::runtime_error("Source file does not exist or is not a file: " + wide_to_utf8(source_path));
                const SourceSignature before = source_signature(source_path);
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
                const SourceSignature stable = source_signature(source_path);
                if (!before.valid || !(before == stable)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100 * (attempt + 1)));
                    continue;
                }
                auto state = journal_.get_file_hash_state(backend_path);
                std::optional<std::string> local_hash_before;
                std::optional<std::string> known_local_hash;
                if (supports_hash_) local_hash_before = get_local_hash(source_path);
                if (state) known_local_hash = state->local_hash;
                if (supports_hash_ && backend_.lexists(backend_path)) {
                    auto remote = backend_.get_hash(backend_path);
                    const bool backing_changed = remote && state && state->hash && *remote != *state->hash;
                    const bool local_unchanged = known_local_hash && local_hash_before && *known_local_hash == *local_hash_before;
                    if (backing_changed && local_unchanged) {
                        if (!update_mount_file_from_server(backend_path, source_path, true))
                            throw std::runtime_error("Backing changed; could not refresh " + wide_to_utf8(source_path));
                        journal_.set_file_hash_state(backend_path, remote, unix_now(), 5, remote);
                        return;
                    }
                }
                backend_.write_file_from_local(source_path, backend_path);
                if (!(source_signature(source_path) == stable)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100 * (attempt + 1)));
                    continue;
                }
                const auto local_hash = get_local_hash(source_path);
                attrs = get_win_attributes(source_path);
                if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
                    if (!set_mount_file_sync_state(source_path, true))
                        log_error("Warning: upload succeeded but in-sync marking failed: " + wide_to_utf8(source_path));
                }
                auto remote = supports_hash_ ? backend_.get_hash(backend_path) : local_hash;
                if (!remote) throw std::runtime_error("Could not verify backing write: " + backend_path);
                journal_.set_file_hash_state(backend_path, remote, unix_now(), 5, local_hash);
                mark_internal(source_path);
                return;
            } catch (const std::exception& e) {
                if (attempt == 9) throw;
                std::this_thread::sleep_for(std::chrono::milliseconds(100 * (attempt + 1)));
            }
        }
    }
    static double unix_now() {
        return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
    }
    std::optional<std::string> hash_local_file(const std::wstring& path) const {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (file == INVALID_HANDLE_VALUE) return std::nullopt;
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        std::vector<UCHAR> hash_object;
        std::array<UCHAR, 64> digest{};
        DWORD object_length = 0, result_length = 0, hash_length = 0;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA512_ALGORITHM, nullptr, 0);
        if (status >= 0) status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length), &result_length, 0);
        if (status >= 0) status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_length), sizeof(hash_length), &result_length, 0);
        if (status >= 0) {
            hash_object.resize(object_length);
            status = BCryptCreateHash(algorithm, &hash, hash_object.data(), object_length, nullptr, 0, 0);
        }
        std::array<UCHAR, 1024 * 1024> buffer{};
        while (status >= 0) {
            DWORD read = 0;
            if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
                status = static_cast<NTSTATUS>(GetLastError());
                break;
            }
            if (read == 0) break;
            status = BCryptHashData(hash, buffer.data(), read, 0);
        }
        if (status >= 0) status = BCryptFinishHash(hash, digest.data(), hash_length, 0);
        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        CloseHandle(file);
        if (status < 0) return std::nullopt;
        std::ostringstream out;
        out << std::hex << std::setfill('0');
        for (DWORD i = 0; i < hash_length; ++i) out << std::setw(2) << static_cast<unsigned>(digest[i]);
        return out.str();
    }
    bool placeholder_data_is_fully_local(const CF_PLACEHOLDER_STANDARD_INFO* info, std::uint64_t logical_size) const {
        logical_size = std::max<std::uint64_t>(0, logical_size);
        if (logical_size == 0) return true;
        const auto on_disk = static_cast<std::uint64_t>(std::max<LONGLONG>(0, info->OnDiskDataSize.QuadPart));
        const auto validated = static_cast<std::uint64_t>(std::max<LONGLONG>(0, info->ValidatedDataSize.QuadPart));
        const auto modified = static_cast<std::uint64_t>(std::max<LONGLONG>(0, info->ModifiedDataSize.QuadPart));
        return on_disk >= logical_size && validated + modified >= logical_size;
    }
    std::optional<std::uint64_t> get_placeholder_modified_data_size(const std::wstring& path) const {
        DWORD attrs = get_win_attributes(path);
        if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_REPARSE_POINT)) return std::nullopt;
        HANDLE file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (file == INVALID_HANDLE_VALUE) return std::nullopt;
        alignas(CF_PLACEHOLDER_STANDARD_INFO) std::array<std::uint8_t, 8192> buffer{};
        DWORD returned = 0;
        HRESULT hr = CfGetPlaceholderInfo(file, CF_PLACEHOLDER_INFO_STANDARD,
                                         buffer.data(), static_cast<DWORD>(buffer.size()), &returned);
        CloseHandle(file);
        if (FAILED(hr)) return std::nullopt;
        auto* info = reinterpret_cast<const CF_PLACEHOLDER_STANDARD_INFO*>(buffer.data());
        return static_cast<std::uint64_t>(std::max<LONGLONG>(0, info->ModifiedDataSize.QuadPart));
    }
    std::optional<std::string> get_local_hash(const std::wstring& path) const {
        DWORD attrs = get_win_attributes(path);
        if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) return std::nullopt;
        if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
            HANDLE file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
            if (file == INVALID_HANDLE_VALUE) return std::nullopt;
            alignas(CF_PLACEHOLDER_STANDARD_INFO) std::array<std::uint8_t, 8192> buffer{};
            DWORD returned = 0;
            HRESULT hr = CfGetPlaceholderInfo(file, CF_PLACEHOLDER_INFO_STANDARD,
                                             buffer.data(), static_cast<DWORD>(buffer.size()), &returned);
            if (FAILED(hr)) { CloseHandle(file); return std::nullopt; }
            auto* info = reinterpret_cast<const CF_PLACEHOLDER_STANDARD_INFO*>(buffer.data());
            LARGE_INTEGER file_size{};
            if (!GetFileSizeEx(file, &file_size)) { CloseHandle(file); return std::nullopt; }
            const bool complete = placeholder_data_is_fully_local(info, static_cast<std::uint64_t>(std::max<LONGLONG>(0, file_size.QuadPart)));
            CloseHandle(file);
            if (!complete) return std::nullopt;
        }
        return hash_local_file(path);
    }
    void make_placeholder_metadata(CF_FS_METADATA& metadata, const BackingStat& st) const {
        ZeroMemory(&metadata, sizeof(metadata));
        metadata.BasicInfo.CreationTime = make_large_integer(st.creation_time);
        metadata.BasicInfo.LastAccessTime = make_large_integer(st.access_time);
        metadata.BasicInfo.LastWriteTime = make_large_integer(st.modified_time);
        metadata.BasicInfo.ChangeTime = make_large_integer(st.modified_time);
        metadata.BasicInfo.FileAttributes = st.is_directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
        metadata.FileSize.QuadPart = st.is_directory ? 0 : static_cast<LONGLONG>(st.size);
    }
    bool create_single_placeholder(const std::string& backend_directory,
                                   const std::string& entry_name,
                                   const std::wstring& mount_directory) {
        if (is_temporary_file(utf8_to_wide(entry_name))) return false;
        const std::string backend_path = join_backend_path(backend_directory, entry_name);
        const BackingStat st = backend_.stat(backend_path);
        CF_PLACEHOLDER_CREATE_INFO placeholder{};
        const std::wstring name = utf8_to_wide(entry_name);
        const std::string identity_utf8 = join_backend_path(backend_directory, entry_name);
        const std::wstring identity = backend_path_to_wide(identity_utf8);
        placeholder.RelativeFileName = name.c_str();
        make_placeholder_metadata(placeholder.FsMetadata, st);
        placeholder.FileIdentity = const_cast<wchar_t*>(identity.c_str());
        placeholder.FileIdentityLength = static_cast<DWORD>((identity.size() + 1) * sizeof(wchar_t));
        if (placeholder.FileIdentityLength > 4096)
            throw std::runtime_error("CFAPI file identity exceeds the 4 KB limit: " + backend_path);
        DWORD placeholder_flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC_VALUE;
        if (st.is_directory) placeholder_flags |= CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION_VALUE;
        placeholder.Flags = static_cast<CF_PLACEHOLDER_CREATE_FLAGS>(placeholder_flags);
        placeholder.Result = 0;
        placeholder.CreateUsn = 0;
        const std::wstring full_mount_path = (fs::path(mount_directory) / name).wstring();
        mark_internal(full_mount_path, false, true);
        DWORD processed = 0;
        HRESULT hr = CfCreatePlaceholders(mount_directory.c_str(), &placeholder, 1,
                                          CF_CREATE_FLAG_NONE, &processed);
        check_hresult(hr, "CfCreatePlaceholders");
        if (processed != 1) {
            std::ostringstream message;
            message << "CfCreatePlaceholders processed " << processed << "/1 entries for " << backend_path;
            throw std::runtime_error(message.str());
        }
        if (placeholder.Result != 0) {
            std::ostringstream message;
            message << "Placeholder creation failed for " << backend_path << ": HRESULT "
                    << hresult_hex(placeholder.Result);
            throw std::runtime_error(message.str());
        }
        mark_internal(full_mount_path);
        return true;
    }
    bool remove_stale_mount_entry(const std::wstring& path) {
        const DWORD attrs = get_win_attributes(path);
        if (attrs == INVALID_FILE_ATTRIBUTES) return true;
        try {
            if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
                std::error_code ec;
                for (const auto& entry : fs::directory_iterator(fs::path(path), ec)) {
                    if (ec) return false;
                    if (!remove_stale_mount_entry(entry.path().wstring())) return false;
                }
                mark_internal(path, true);
                if (!RemoveDirectoryW(path.c_str())) {
                    log_error("Failed to remove stale mount entry: " + wide_to_utf8(path) + "; Win32 error=" + std::to_string(GetLastError()));
                    return false;
                }
            } else {
                mark_internal(path, true);
                if (!DeleteFileW(path.c_str())) {
                    log_error("Failed to remove stale mount entry: " + wide_to_utf8(path) + "; Win32 error=" + std::to_string(GetLastError()));
                    return false;
                }
            }
            return true;
        } catch (const std::exception& e) {
            log_error("Error removing stale entry " + wide_to_utf8(path) + ": " + e.what());
            return false;
        }
    }
    bool set_mount_file_sync_state(const std::wstring& path, bool in_sync) {
        DWORD attrs = get_win_attributes(path);
        if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
        HANDLE handle = INVALID_HANDLE_VALUE;
        HRESULT hr = CfOpenFileWithOplock(path.c_str(), static_cast<CF_OPEN_FILE_FLAGS>(CF_OPEN_FILE_FLAG_WRITE_ACCESS_VALUE), &handle);
        if (FAILED(hr) || handle == INVALID_HANDLE_VALUE) {
            log_error("CfOpenFileWithOplock failed for " + wide_to_utf8(path) + ": " + hresult_hex(hr));
            return false;
        }
        const auto state = in_sync ? CF_IN_SYNC_STATE_IN_SYNC : CF_IN_SYNC_STATE_NOT_IN_SYNC;
        hr = CfSetInSyncState(handle, state, CF_SET_IN_SYNC_FLAG_NONE, nullptr);
        if (FAILED(hr)) log_error("CfSetInSyncState failed for " + wide_to_utf8(path) + ": " + hresult_hex(hr));
        CfCloseHandle(handle);
        return SUCCEEDED(hr);
    }
    bool update_mount_file_from_server(const std::string& backend_path,
                                       const std::wstring& mount_path,
                                       bool dehydrate) {
        BackingStat st;
        try { st = backend_.stat(backend_path); }
        catch (const std::exception& e) { log_error("Cannot stat " + backend_path + ": " + e.what()); return false; }
        if (st.is_directory) return false;
        const DWORD attrs = get_win_attributes(mount_path);
        const std::wstring parent = fs::path(mount_path).parent_path().wstring();
        const std::string backend_dir = parent_backend_path(backend_path);
        const std::string name = base_backend_path(backend_path);
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            try {
                fs::create_directories(fs::path(parent));
                return create_single_placeholder(backend_dir, name, parent);
            } catch (const std::exception& e) {
                log_error("Cannot create placeholder for " + backend_path + ": " + e.what());
                return false;
            }
        }
        if (!(attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
            if (!remove_stale_mount_entry(mount_path)) return false;
            try { return create_single_placeholder(backend_dir, name, parent); }
            catch (const std::exception& e) {
                log_error("Cannot replace local file with placeholder " + wide_to_utf8(mount_path) + ": " + e.what());
                return false;
            }
        }
        HANDLE handle = INVALID_HANDLE_VALUE;
        HRESULT hr = CfOpenFileWithOplock(mount_path.c_str(),
            static_cast<CF_OPEN_FILE_FLAGS>(CF_OPEN_FILE_FLAG_EXCLUSIVE_VALUE | CF_OPEN_FILE_FLAG_WRITE_ACCESS_VALUE), &handle);
        if (FAILED(hr) || handle == INVALID_HANDLE_VALUE) {
            log_error("Cannot open placeholder " + wide_to_utf8(mount_path) + ": " + hresult_hex(hr));
            return false;
        }
        bool success = false;
        do {
            hr = CfSetInSyncState(handle, CF_IN_SYNC_STATE_IN_SYNC, CF_SET_IN_SYNC_FLAG_NONE, nullptr);
            if (FAILED(hr)) {
                log_error("CfSetInSyncState failed for " + wide_to_utf8(mount_path) + ": " + hresult_hex(hr));
                break;
            }
            CF_FS_METADATA metadata{};
            make_placeholder_metadata(metadata, st);
            metadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
            const std::wstring identity = backend_path_to_wide(backend_path);
            DWORD flags = CF_UPDATE_FLAG_MARK_IN_SYNC_VALUE | CF_UPDATE_FLAG_PASSTHROUGH_FS_METADATA_VALUE;
            if (dehydrate) flags |= CF_UPDATE_FLAG_DEHYDRATE_VALUE;
            mark_internal(mount_path, true, true);
            hr = CfUpdatePlaceholder(handle, &metadata, identity.c_str(),
                static_cast<DWORD>((identity.size() + 1) * sizeof(wchar_t)), nullptr, 0,
                static_cast<CF_UPDATE_FLAGS>(flags), nullptr, nullptr);
            if (FAILED(hr)) {
                log_error("CfUpdatePlaceholder failed for " + wide_to_utf8(mount_path) + ": " + hresult_hex(hr));
                break;
            }
            mark_internal(mount_path);
            success = true;
        } while (false);
        CfCloseHandle(handle);
        return success;
    }
    struct BackingFile {
        std::string path;
        BackingStat stat;
    };
    std::vector<BackingFile> collect_backing_files(const std::string& directory) {
        std::vector<BackingFile> files;
        std::vector<std::string> names;
        try { names = backend_.listdir(directory); }
        catch (const std::exception& e) {
            log_error("Cannot list backing directory " + directory + ": " + e.what());
            return files;
        }
        for (const auto& name : names) {
            if (is_temporary_file(utf8_to_wide(name))) continue;
            const std::string path = join_backend_path(directory, name);
            try {
                BackingStat st = backend_.stat(path);
                if (st.is_directory) {
                    auto nested = collect_backing_files(path);
                    files.insert(files.end(), std::make_move_iterator(nested.begin()), std::make_move_iterator(nested.end()));
                } else {
                    files.push_back(BackingFile{path, st});
                }
            } catch (const std::exception& e) {
                log_error("Cannot stat " + path + ": " + e.what());
            }
        }
        return files;
    }
    bool is_backend_path_busy(const std::string& backend_path) const {
        const std::string normalized = normalize_backend_path(backend_path);
        std::lock_guard<std::mutex> lock(operation_mutex_);
        for (const auto& folder : active_folders_) {
            if (folder.empty() || normalized == folder ||
                (normalized.size() > folder.size() && normalized.compare(0, folder.size(), folder) == 0 && normalized[folder.size()] == '/') ||
                (folder.size() > normalized.size() && folder.compare(0, normalized.size(), normalized) == 0 && folder[normalized.size()] == '/'))
                return true;
        }
        return false;
    }
    void check_server_file_updates(bool force) {
        if (!supports_hash_) return;
        const auto files = collect_backing_files("");
        if (files.empty()) return;
        std::set<std::string> existing;
        for (const auto& file : files) existing.insert(normalize_backend_path(file.path));
        for (const auto& path : journal_.get_all_file_hashes()) {
            if (!existing.count(path) || !backend_.lexists(path)) journal_.delete_file_hash_state(path);
        }
        const double now = unix_now();
        const std::size_t batch_size = std::max<std::size_t>(1, (files.size() + 4) / 5);
        struct Eligible {
            double due = 0;
            const BackingFile* file = nullptr;
            std::optional<FileHashState> state;
        };
        std::vector<Eligible> eligible;
        for (const auto& file : files) {
            auto state = journal_.get_file_hash_state(file.path);
            if (force || !state) {
                eligible.push_back(Eligible{0.0, &file, state});
                continue;
            }
            double due = state->next_check.value_or(state->last_check.value_or(0.0));
            if (due <= now) eligible.push_back(Eligible{due, &file, state});
        }
        std::sort(eligible.begin(), eligible.end(), [](const Eligible& a, const Eligible& b) {
            if (a.due != b.due) return a.due < b.due;
            return a.file->path < b.file->path;
        });
        std::vector<Eligible> selected;
        for (const auto& item : eligible) {
            if (!force && is_backend_path_busy(item.file->path)) continue;
            selected.push_back(item);
            if (selected.size() >= batch_size) break;
        }
        for (const auto& item : selected) {
            const BackingFile& file = *item.file;
            const auto& state = item.state;
            const double check_time = unix_now();
            const auto old_hash = state ? state->hash : std::nullopt;
            const auto old_local = state ? state->local_hash : std::nullopt;
            const auto old_mtime = state ? state->backing_mtime : std::nullopt;
            int unchanged = state ? state->unchanged_checks : 0;
            try {
                if (!backend_.lexists(file.path)) {
                    journal_.delete_file_hash_state(file.path);
                    continue;
                }
                const std::uint64_t new_size = backend_.get_size(file.path);
                const auto new_hash = backend_.get_hash(file.path);
                if (!new_hash) {
                    journal_.set_file_hash_state(file.path, old_hash, check_time, 5, old_local);
                    journal_.schedule_file_check(file.path, check_time + 5, file.stat.modified_time, unchanged);
                    continue;
                }
                const std::wstring mount_path = mount_path_for_backend(file.path);
                const DWORD attrs = get_win_attributes(mount_path);
                const bool backing_changed = (!state || !old_hash || *new_hash != *old_hash);
                const bool mtime_changed = old_mtime && file.stat.modified_time != *old_mtime;
                bool mount_missing = attrs == INVALID_FILE_ATTRIBUTES;
                std::optional<std::uint64_t> mount_size;
                if (!mount_missing) {
                    WIN32_FILE_ATTRIBUTE_DATA data{};
                    if (GetFileAttributesExW(mount_path.c_str(), GetFileExInfoStandard, &data))
                        mount_size = (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
                    else mount_missing = true;
                }
                const bool size_changed = !mount_missing && mount_size && *mount_size != new_size;
                const auto modified_size = attrs == INVALID_FILE_ATTRIBUTES
                    ? std::optional<std::uint64_t>{} : get_placeholder_modified_data_size(mount_path);
                if (!modified_size && attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
                    journal_.set_file_hash_state(file.path, old_hash, check_time, 5, old_local);
                    journal_.schedule_file_check(file.path, check_time + 5, file.stat.modified_time, unchanged);
                    continue;
                }
                if (modified_size && *modified_size > 0) {
                    journal_.set_file_hash_state(file.path, old_hash, check_time, 5, old_local);
                    journal_.schedule_file_check(file.path, check_time + 5, file.stat.modified_time, unchanged);
                    continue;
                }
                if (mount_missing || backing_changed || size_changed) {
                    if (!update_mount_file_from_server(file.path, mount_path, true)) {
                        journal_.set_file_hash_state(file.path, old_hash, check_time, 5, old_local);
                        journal_.schedule_file_check(file.path, check_time + 5, file.stat.modified_time, unchanged);
                        log_error("[refresh] failed: " + file.path + "; retrying");
                        continue;
                    }
                } else if (mtime_changed) {
                    if (!update_mount_file_from_server(file.path, mount_path, false)) {
                        journal_.set_file_hash_state(file.path, old_hash, check_time, 5, old_local);
                        journal_.schedule_file_check(file.path, check_time + 5, file.stat.modified_time, unchanged);
                        continue;
                    }
                }
                journal_.set_file_hash_state(file.path, new_hash, check_time, 5, new_hash);
                if (backing_changed || mtime_changed || size_changed) unchanged = 0;
                else unchanged = std::min(unchanged + 1, 5);
                const int interval = std::min(5 * (unchanged + 1), 30);
                journal_.schedule_file_check(file.path, unix_now() + interval, file.stat.modified_time, unchanged);
            } catch (const std::exception& e) {
                const double retry_time = unix_now() + 5;
                journal_.set_file_hash_state(file.path, old_hash, unix_now(), 5, old_local);
                journal_.schedule_file_check(file.path, retry_time, file.stat.modified_time, unchanged);
                log_error("[refresh] error for " + file.path + ": " + e.what() + "; retrying in 5 seconds");
            }
        }
    }
    void refresh_directory(const std::string& backend_directory,
                           const std::wstring& mount_directory) {
        if (is_backend_path_busy(backend_directory)) return;
        fs::create_directories(fs::path(mount_directory));
        std::set<std::string> backend_names;
        try {
            for (const auto& name : backend_.listdir(backend_directory))
                if (!is_temporary_file(utf8_to_wide(name))) backend_names.insert(name);
        } catch (const std::exception&) { return; }
        std::set<std::string> mount_names;
        std::error_code ec;
        for (const auto& entry : fs::directory_iterator(fs::path(mount_directory), ec)) {
            if (ec) return;
            const std::string name = wide_to_utf8(entry.path().filename().wstring());
            if (!is_temporary_file(entry.path().filename().wstring())) mount_names.insert(name);
        }
        for (const auto& name : backend_names) {
            if (mount_names.count(name)) continue;
            const std::string backend_path = join_backend_path(backend_directory, name);
            if (is_backend_path_busy(backend_path)) continue;
            try {
                const bool created = create_single_placeholder(backend_directory, name, mount_directory);
                if (created && supports_hash_) {
                    auto remote_hash = backend_.get_hash(backend_path);
                    if (remote_hash) {
                        const double now = unix_now();
                        const BackingStat st = backend_.stat(backend_path);
                        journal_.set_file_hash_state(backend_path, remote_hash, now, 5, remote_hash);
                        journal_.schedule_file_check(backend_path, now + 5, st.modified_time, 0);
                    }
                }
            } catch (const std::exception& e) {
                log_error("Cannot create " + backend_path + ": " + e.what());
            }
        }
        for (const auto& name : mount_names) {
            if (backend_names.count(name)) continue;
            const std::string backend_path = join_backend_path(backend_directory, name);
            if (is_backend_path_busy(backend_path)) continue;
            const std::wstring path = (fs::path(mount_directory) / utf8_to_wide(name)).wstring();
            const DWORD attrs = get_win_attributes(path);
            if (attrs == INVALID_FILE_ATTRIBUTES) continue;
            auto state = journal_.get_file_hash_state(backend_path);
            if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) || state) {
                remove_stale_mount_entry(path);
                journal_.delete_file_hash_state(backend_path);
            } else if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
                try {
                    backend_.make_directory(backend_path);
                    refresh_directory(backend_path, path);
                } catch (const std::exception& e) {
                    log_error("Cannot upload directory " + backend_path + ": " + e.what());
                }
            } else {
                try {
                    backend_.write_file_from_local(path, backend_path);
                    auto local_hash = get_local_hash(path);
                    auto remote_hash = supports_hash_ ? backend_.get_hash(backend_path) : local_hash;
                    if (remote_hash) journal_.set_file_hash_state(backend_path, remote_hash, unix_now(), 5, local_hash);
                } catch (const std::exception& e) {
                    log_error("Cannot upload local-only file " + backend_path + ": " + e.what());
                }
            }
        }
        for (const auto& name : backend_names) {
            if (!mount_names.count(name)) continue;
            const std::string backend_path = join_backend_path(backend_directory, name);
            try {
                const BackingStat st = backend_.stat(backend_path);
                if (st.is_directory && !is_backend_path_busy(backend_path)) {
                    const std::wstring child = (fs::path(mount_directory) / utf8_to_wide(name)).wstring();
                    refresh_directory(backend_path, child);
                }
            } catch (const std::exception&) {}
        }
    }
    void refresh_mount(bool ignored_busy, bool force_hash_check) {
        (void)ignored_busy;
        refresh_directory("", mount_dir_);
        check_server_file_updates(force_hash_check);
    }
    void replay_journal() {
        const auto pending = journal_.pending();
        for (const auto& item : pending) {
            try {
                if (item.operation == "write") {
                    const DWORD source_attributes = item.source_path.empty() ? INVALID_FILE_ATTRIBUTES : get_win_attributes(item.source_path);
                    if (source_attributes == INVALID_FILE_ATTRIBUTES || (source_attributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        journal_.remove(item.id);
                        continue;
                    }
                    backend_.write_file_from_local(item.source_path, item.backend_path);
                } else if (item.operation == "mkdir") {
                    backend_.make_directory(item.backend_path);
                } else if (item.operation == "delete") {
                    if (backend_.lexists(item.backend_path)) backend_.delete_path(item.backend_path, item.is_directory);
                    journal_.delete_file_hash_state(item.backend_path);
                } else if (item.operation == "move") {
                    const std::string src = wide_to_utf8(item.source_path);
                    const std::string dst = wide_to_utf8(item.destination_path);
                    if (backend_.lexists(src)) backend_.move_path(src, dst);
                }
                journal_.remove(item.id);
            } catch (const std::exception& e) {
                log_error("Journal replay failed for operation " + std::to_string(item.id) + ": " + e.what());
            }
        }
    }
    void register_sync_root() {
        CF_SYNC_REGISTRATION registration{};
        registration.StructSize = sizeof(CF_SYNC_REGISTRATION);
        registration.ProviderName = PROVIDER_NAME;
        registration.ProviderVersion = PROVIDER_VERSION;
        registration.SyncRootIdentity = nullptr;
        registration.SyncRootIdentityLength = 0;
        registration.FileIdentity = nullptr;
        registration.FileIdentityLength = 0;
        HRESULT guid_hr = CoCreateGuid(&registration.ProviderId);
        check_hresult(guid_hr, "CoCreateGuid");
        CF_SYNC_POLICIES policies{};
        policies.StructSize = sizeof(CF_SYNC_POLICIES);
        policies.Hydration.Primary = CF_HYDRATION_POLICY_FULL;
        policies.Population.Primary = CF_POPULATION_POLICY_ALWAYS_FULL;
        HRESULT hr = CfRegisterSyncRoot(mount_dir_.c_str(), &registration, &policies, CF_REGISTER_FLAG_NONE);
        check_hresult(hr, "CfRegisterSyncRoot");
        root_registered_ = true;
    }
    void unregister_sync_root() noexcept {
        HRESULT hr = CfUnregisterSyncRoot(mount_dir_.c_str());
        (void)hr;
        root_registered_ = false;
    }
    void connect_sync_root() {
        static const CF_CALLBACK_REGISTRATION callbacks[] = {
            {CF_CALLBACK_TYPE_FETCH_DATA, &Engine::fetch_data_callback},
            {CF_CALLBACK_TYPE_NONE, nullptr}
        };
        const DWORD flags = CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO_VALUE | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH_VALUE;
        HRESULT hr = CfConnectSyncRoot(mount_dir_.c_str(), callbacks, nullptr,
                                       static_cast<CF_CONNECT_FLAGS>(flags), &connection_key_);
        check_hresult(hr, "CfConnectSyncRoot");
        connection_connected_ = true;
    }
    static void CALLBACK fetch_data_callback(const CF_CALLBACK_INFO* info,
                                             const CF_CALLBACK_PARAMETERS* parameters) {
        Engine* engine = g_active_engine.load();
        if (!engine || !info || !parameters) return;
        engine->handle_fetch_data(info, parameters);
    }
    void handle_fetch_data(const CF_CALLBACK_INFO* info,
                           const CF_CALLBACK_PARAMETERS* parameters) {
        FetchRequest request;
        try {
            request.offset = parameters->FetchData.RequiredFileOffset.QuadPart;
            request.length = parameters->FetchData.RequiredLength.QuadPart;
            request.connection_key = info->ConnectionKey;
            request.transfer_key = info->TransferKey;
            request.request_key = info->RequestKey;
            request.logical_size = std::max<LONGLONG>(0, info->FileSize.QuadPart);
            if (!info->VolumeDosName || !info->NormalizedPath)
                throw std::runtime_error("Callback did not include VolumeDosName/NormalizedPath");
            request.mount_path = absolute_path(std::wstring(info->VolumeDosName) + info->NormalizedPath);
            auto backend_path = mount_path_to_backend_path(request.mount_path);
            if (!backend_path) throw std::runtime_error("Could not resolve callback path to backing path");
            request.backend_path = *backend_path;
        } catch (const std::exception& e) {
            log_error(std::string("Invalid FETCH_DATA callback: ") + e.what());
            return;
        }
        std::lock_guard<std::mutex> lock(fetch_mutex_);
        if (stopping_) return;
        for (auto it = fetch_threads_.begin(); it != fetch_threads_.end();) {
            if (it->finished->load()) {
                if (it->thread.joinable()) it->thread.join();
                it = fetch_threads_.erase(it);
            } else {
                ++it;
            }
        }
        auto finished = std::make_shared<std::atomic<bool>>(false);
        FetchWorker worker;
        worker.finished = finished;
        worker.thread = std::thread([this, request, finished]() {
            try { fetch_worker(request); }
            catch (const std::exception& e) { log_error(std::string("Unhandled fetch worker error: ") + e.what()); }
            catch (...) { log_error("Unhandled non-standard fetch worker error"); }
            finished->store(true);
        });
        fetch_threads_.push_back(std::move(worker));
    }
    void execute_transfer_data(const FetchRequest& request, std::uint64_t offset,
                               const std::string* data, std::uint64_t failure_length,
                               LONG completion_status) {
        const std::size_t transfer_length = data ? data->size() : static_cast<std::size_t>(failure_length);
        void* buffer = nullptr;
        if (data && completion_status == STATUS_SUCCESS_VALUE) {
            if (data->empty()) throw std::runtime_error("Cannot transfer empty data");
            const std::size_t alloc_size = (data->size() + PAGE_SIZE - 1) & ~(static_cast<std::size_t>(PAGE_SIZE) - 1);
            buffer = VirtualAlloc(nullptr, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buffer) throw std::runtime_error("VirtualAlloc failed for hydration buffer");
            std::memcpy(buffer, data->data(), data->size());
        }
        CF_OPERATION_INFO op_info{};
        op_info.StructSize = sizeof(CF_OPERATION_INFO);
        op_info.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
        op_info.ConnectionKey = request.connection_key;
        op_info.TransferKey = request.transfer_key;
        op_info.RequestKey = request.request_key;
        CF_OPERATION_PARAMETERS op_params{};
        const std::size_t transfer_data_offset = offsetof(CF_OPERATION_PARAMETERS, TransferData);
        auto* transfer_data = reinterpret_cast<WinFuseTransferDataParameters*>(
            reinterpret_cast<unsigned char*>(&op_params) + transfer_data_offset);
        transfer_data->Flags = CF_OPERATION_TRANSFER_DATA_FLAG_NONE;
        transfer_data->CompletionStatus = static_cast<NTSTATUS>(completion_status);
        transfer_data->Buffer = buffer;
        transfer_data->Offset.QuadPart = static_cast<LONGLONG>(offset);
        transfer_data->Length.QuadPart = static_cast<LONGLONG>(transfer_length);
        op_params.ParamSize = static_cast<ULONG>(transfer_data_offset + sizeof(*transfer_data));
        HRESULT hr = CfExecute(&op_info, &op_params);
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
        check_hresult(hr, "CfExecute(TRANSFER_DATA)");
    }
    void fail_fetch(const FetchRequest& request) {
        const std::uint64_t offset = static_cast<std::uint64_t>(std::max<std::int64_t>(0, request.offset));
        const std::uint64_t start = offset & ~(static_cast<std::uint64_t>(PAGE_SIZE) - 1);
        std::uint64_t requested_end = start + PAGE_SIZE;
        if (request.length == CF_EOF_VALUE) requested_end = std::max<std::uint64_t>(start, static_cast<std::uint64_t>(request.logical_size));
        else if (request.length >= 0)
            requested_end = std::max<std::uint64_t>(start + PAGE_SIZE, offset + static_cast<std::uint64_t>(request.length));
        const std::uint64_t end = std::max<std::uint64_t>(start + PAGE_SIZE, requested_end);
        const std::uint64_t failure_length = (end - start + PAGE_SIZE - 1) & ~(static_cast<std::uint64_t>(PAGE_SIZE) - 1);
        execute_transfer_data(request, start, nullptr, failure_length, STATUS_CLOUD_FILE_UNSUCCESSFUL_VALUE);
    }
    void fetch_worker(const FetchRequest& request) {
        try {
            if (request.offset < 0 || request.offset > request.logical_size)
                throw std::runtime_error("Invalid fetch offset " + std::to_string(request.offset) +
                                         "; logical size is " + std::to_string(request.logical_size));
            if (request.length < 0 && request.length != CF_EOF_VALUE)
                throw std::runtime_error("Invalid fetch length " + std::to_string(request.length));
            const std::uint64_t offset = static_cast<std::uint64_t>(request.offset);
            const std::uint64_t logical_size = static_cast<std::uint64_t>(request.logical_size);
            const std::uint64_t required_end = request.length == CF_EOF_VALUE
                ? logical_size : std::min<std::uint64_t>(logical_size, offset + static_cast<std::uint64_t>(request.length));
            if (required_end <= offset)
                throw std::runtime_error("Empty or stale fetch range: offset=" + std::to_string(request.offset) +
                    ", length=" + std::to_string(request.length) + ", logical_size=" + std::to_string(request.logical_size));
            const std::uint64_t start = offset & ~(static_cast<std::uint64_t>(PAGE_SIZE) - 1);
            const std::uint64_t end = required_end >= logical_size
                ? logical_size : std::min<std::uint64_t>(logical_size,
                    (required_end + PAGE_SIZE - 1) & ~(static_cast<std::uint64_t>(PAGE_SIZE) - 1));
            if (end <= start) throw std::runtime_error("Invalid aligned fetch range");
            const BackingStat st = backend_.stat(request.backend_path);
            if (st.is_directory) throw std::runtime_error("Cannot hydrate a directory");
            if (st.size < end)
                throw std::runtime_error("Backing file is too short for fetch: " + request.backend_path +
                    "; backing_size=" + std::to_string(st.size) + ", required_end=" + std::to_string(end) +
                    ". The placeholder may need a metadata refresh.");
            std::uint64_t current_offset = start;
            while (current_offset < end) {
                const std::uint64_t remaining = end - current_offset;
                std::size_t chunk_size = static_cast<std::size_t>(std::min<std::uint64_t>(FETCH_CHUNK_SIZE, remaining));
                if (current_offset + chunk_size < end) chunk_size &= ~(static_cast<std::size_t>(PAGE_SIZE) - 1);
                if (chunk_size == 0) throw std::runtime_error("Invalid transfer chunk size");
                std::string data = backend_.read_range(request.backend_path, current_offset, chunk_size);
                if (data.size() != chunk_size)
                    throw std::runtime_error("Short read from " + request.backend_path + ": wanted " +
                        std::to_string(chunk_size) + ", got " + std::to_string(data.size()));
                add_ignore_write(request.mount_path);
                execute_transfer_data(request, current_offset, &data, 0, STATUS_SUCCESS_VALUE);
                current_offset += data.size();
            }
        } catch (const std::exception& e) {
            discard_ignore_write(request.mount_path);
            log_error("FETCH_DATA failed for '" + request.backend_path + "': " + e.what());
            try { fail_fetch(request); }
            catch (const std::exception& completion_error) {
                log_error("Could not complete failed FETCH_DATA for '" + request.backend_path + "': " + completion_error.what());
            }
        }
    }
    void discard_ignore_write(const std::wstring& path) {
        if (path.empty()) return;
        std::lock_guard<std::mutex> lock(ignore_mutex_);
        ignore_windows_.erase(lower_windows(absolute_path(path)));
    }
    struct FetchWorker {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> finished;
    };
    BackendAdapter backend_;
    std::wstring mount_dir_;
    SyncJournal journal_;
    bool supports_hash_ = false;
    bool started_ = false;
    bool journal_open_ = false;
    bool root_registered_ = false;
    CF_CONNECTION_KEY connection_key_{};
    bool connection_connected_ = false;
    mutable std::mutex operation_mutex_;
    std::set<std::string> active_folders_;
    std::mutex internal_mutex_;
    std::map<std::wstring, InternalEntry> internal_paths_;
    std::mutex ignore_mutex_;
    std::map<std::wstring, std::vector<IgnoreWindow>> ignore_windows_;
    std::mutex fetch_mutex_;
    std::vector<FetchWorker> fetch_threads_;
    std::atomic<bool> stopping_{false};
};
}
struct BackingStoreBase {};
[[noreturn]] void raise_not_implemented(const char* method) {
    PyErr_Format(PyExc_NotImplementedError, "BackingStore.%s() must be implemented", method);
    throw py::error_already_set();
}
py::object make_watchdog_handler(Engine& engine, py::object& timestamped_queue_type) {
    py::dict scope;
    scope["FileSystemEventHandler"] =
        py::module_::import("watchdog.events").attr("FileSystemEventHandler");
    scope["queue"] = py::module_::import("queue");
    scope["time"] = py::module_::import("time");
    py::exec(R"PY(
class _WinFuseTimestampedEventQueue(queue.Queue):
    def put(self, item, block=True, timeout=None):
        if isinstance(item, tuple) and len(item) == 2:
            event = item[0]
            try:
                setattr(event, "_winfuse_occurred_at", time.monotonic())
            except (AttributeError, TypeError):
                try:
                    object.__setattr__(event, "_winfuse_occurred_at", time.monotonic())
                except (AttributeError, TypeError):
                    pass
        return super().put(item, block, timeout)
def _winfuse_event_time(event):
    value = getattr(event, "_winfuse_occurred_at", None)
    return float(value) if value is not None else time.monotonic()
class _WinFuseEventHandler(FileSystemEventHandler):
    def __init__(self, engine):
        super().__init__()
        self._engine = engine
    def on_created(self, event):
        self._engine.on_created(event.src_path, bool(event.is_directory), _winfuse_event_time(event))
    def on_modified(self, event):
        self._engine.on_modified(event.src_path, bool(event.is_directory), _winfuse_event_time(event))
    def on_deleted(self, event):
        self._engine.on_deleted(event.src_path, bool(event.is_directory))
    def on_moved(self, event):
        self._engine.on_moved(event.src_path, event.dest_path,
                              bool(event.is_directory), _winfuse_event_time(event))
)PY", scope, scope);
    timestamped_queue_type = py::reinterpret_borrow<py::object>(scope["_WinFuseTimestampedEventQueue"]);
    py::object handler_type = py::reinterpret_borrow<py::object>(scope["_WinFuseEventHandler"]);
    py::object engine_object = py::cast(&engine, py::return_value_policy::reference);
    return handler_type(engine_object);
}
void run_main(py::object backing_store, py::object mount_dir_argument) {
    py::module_ module = py::module_::import("winfuse4");
    py::module_ os = py::module_::import("os");
    if (py::cast<std::string>(os.attr("name")) != "nt")
        throw std::runtime_error("This program requires Windows.");
    if (backing_store.is_none())
        throw py::value_error("A backing store is required.");
    if (!module.attr("ACTIVE_BACKING_STORE").is_none())
        throw std::runtime_error("A Cloud Files mirror is already running.");
    py::object mount_dir_python = os.attr("path").attr("abspath")(
        os.attr("fspath")(mount_dir_argument));
    const std::wstring mount_dir = py::cast<std::wstring>(mount_dir_python);
    py::object journal_path_python = os.attr("fspath")(module.attr("JOURNAL_PATH"));
    const std::wstring journal_path = py::cast<std::wstring>(journal_path_python);
    py::object backing_type = py::type::of(backing_store);
    py::object backend_hash_method = py::getattr(backing_type, "get_hash", py::none());
    py::object base_hash_method = module.attr("BackingStore").attr("get_hash");
    const bool supports_hash = !backend_hash_method.is_none() && !backend_hash_method.is(base_hash_method);
    py::object observer_class;
    try {
        observer_class = py::module_::import("watchdog.observers").attr("Observer");
    } catch (py::error_already_set& error) {
        error.restore();
        PyErr_Clear();
        throw std::runtime_error("The 'watchdog' package is required. Install it with 'pip install watchdog'.");
    }
    double refresh_interval = py::cast<double>(module.attr("REFRESH_INTERVAL"));
    if (refresh_interval < 0.5) refresh_interval = 0.5;
    Engine engine(backing_store, mount_dir, supports_hash, journal_path);
    module.attr("ACTIVE_BACKING_STORE") = backing_store;
    module.attr("MOUNT_DIR") = mount_dir_python;
    py::object observer = py::none();
    bool engine_started = false;
    bool observer_started = false;
    std::exception_ptr failure;
    try {
        py::object time_module = py::module_::import("time");
        py::object queue_type;
        py::object handler = make_watchdog_handler(engine, queue_type);
        observer = observer_class();
        observer.attr("_event_queue") = queue_type();
        observer.attr("schedule")(handler, mount_dir_python, true);
        {
            py::gil_scoped_release release;
            engine.start();
        }
        engine_started = true;
        observer.attr("start")();
        observer_started = true;
        py::print("[*] Mount:", mount_dir_python);
        py::object absolute_journal = os.attr("path").attr("abspath")(journal_path_python);
        py::print("[*] Journal:", absolute_journal);
        py::print("[*] Namespace refresh: every", refresh_interval, "s");
        double next_refresh = py::cast<double>(time_module.attr("monotonic")()) + refresh_interval;
        for (;;) {
            const double now = py::cast<double>(time_module.attr("monotonic")());
            const double delay = std::max(0.1, next_refresh - now);
            time_module.attr("sleep")(delay);
            try {
                py::gil_scoped_release release;
                engine.refresh();
            } catch (const py::error_already_set& error) {
                log_error(std::string("[refresh] error: ") + error.what());
            } catch (const std::exception& error) {
                log_error(std::string("[refresh] error: ") + error.what());
            }
            next_refresh = py::cast<double>(time_module.attr("monotonic")()) + refresh_interval;
        }
    } catch (py::error_already_set& error) {
        if (error.matches(PyExc_KeyboardInterrupt)) {
            PyErr_Clear();
        } else {
            failure = std::current_exception();
        }
    } catch (...) {
        failure = std::current_exception();
    }
    if (observer_started && !observer.is_none()) {
        try { observer.attr("stop")(); } catch (...) { PyErr_Clear(); }
        try { observer.attr("join")(); } catch (...) { PyErr_Clear(); }
    }
    if (engine_started) {
        try {
            py::gil_scoped_release release;
            engine.stop();
        } catch (...) {
            if (!failure) failure = std::current_exception();
        }
    }
    module.attr("ACTIVE_BACKING_STORE") = py::none();
    module.attr("MOUNT_DIR") = py::none();
    if (failure) std::rethrow_exception(failure);
}
PYBIND11_MODULE(winfuse4, module) {
    module.doc() = "Native C++ implementation of the winfuse4 Windows Cloud Files mirror";
    py::class_<BackingStat>(module, "BackingStat")
        .def(py::init<bool, std::uint64_t, double, double, double>(),
             py::arg("is_directory"), py::arg("size"), py::arg("creation_time"),
             py::arg("access_time"), py::arg("modified_time"))
        .def_readonly("is_directory", &BackingStat::is_directory)
        .def_readonly("size", &BackingStat::size)
        .def_readonly("creation_time", &BackingStat::creation_time)
        .def_readonly("access_time", &BackingStat::access_time)
        .def_readonly("modified_time", &BackingStat::modified_time)
        .def("__repr__", [](const BackingStat& value) {
            std::ostringstream out;
            out << "BackingStat(is_directory=" << (value.is_directory ? "True" : "False")
                << ", size=" << value.size << ", creation_time=" << value.creation_time
                << ", access_time=" << value.access_time
                << ", modified_time=" << value.modified_time << ")";
            return out.str();
        });
    py::class_<BackingStoreBase>(module, "BackingStore")
        .def(py::init<>())
        .def("initialize", [](BackingStoreBase&) {})
        .def("listdir", [](BackingStoreBase&, py::object) -> py::object {
            raise_not_implemented("listdir");
        }, py::arg("relative_path"))
        .def("stat", [](BackingStoreBase&, py::object) -> py::object {
            raise_not_implemented("stat");
        }, py::arg("relative_path"))
        .def("open_read", [](BackingStoreBase&, py::object) -> py::object {
            raise_not_implemented("open_read");
        }, py::arg("relative_path"))
        .def("write_file_from_local", [](BackingStoreBase&, py::object, py::object) {
            raise_not_implemented("write_file_from_local");
        }, py::arg("source_path"), py::arg("relative_path"))
        .def("make_directory", [](BackingStoreBase&, py::object) {
            raise_not_implemented("make_directory");
        }, py::arg("relative_path"))
        .def("lexists", [](BackingStoreBase&, py::object) -> bool {
            raise_not_implemented("lexists");
        }, py::arg("relative_path"))
        .def("delete", [](BackingStoreBase&, py::object, bool) {
            raise_not_implemented("delete");
        }, py::arg("relative_path"), py::arg("is_directory"))
        .def("move", [](BackingStoreBase&, py::object, py::object) {
            raise_not_implemented("move");
        }, py::arg("source_relative_path"), py::arg("destination_relative_path"))
        .def("get_size", [](BackingStoreBase& self, py::object relative_path) -> py::object {
            py::object self_object = py::cast(&self, py::return_value_policy::reference);
            py::object stat_value = self_object.attr("stat")(relative_path);
            py::object size_value = stat_value.attr("size");
            return size_value;
        }, py::arg("relative_path"))
        .def("get_hash", [](BackingStoreBase&, py::object) -> py::object {
            return py::none();
        }, py::arg("relative_path"))
        .def("describe", [](BackingStoreBase& self) {
            py::object self_object = py::cast(&self, py::return_value_policy::reference);
            return py::str(py::type::of(self_object).attr("__name__"));
        });
    py::class_<Engine>(module, "_Engine")
        .def(py::init<py::object, const std::wstring&, bool, const std::wstring&>(),
             py::arg("backing_store"), py::arg("mount_dir"), py::arg("supports_hash"),
             py::arg("journal_path") = L".\\sync_journal.db")
        .def("start", &Engine::start, py::call_guard<py::gil_scoped_release>())
        .def("refresh", &Engine::refresh, py::call_guard<py::gil_scoped_release>())
        .def("stop", &Engine::stop, py::call_guard<py::gil_scoped_release>())
        .def("is_folder_busy", &Engine::is_folder_busy, py::arg("path"),
             py::call_guard<py::gil_scoped_release>())
        .def("on_created", &Engine::on_created, py::arg("path"), py::arg("is_directory"), py::arg("event_time"),
             py::call_guard<py::gil_scoped_release>())
        .def("on_modified", &Engine::on_modified, py::arg("path"), py::arg("is_directory"), py::arg("event_time"),
             py::call_guard<py::gil_scoped_release>())
        .def("on_deleted", &Engine::on_deleted, py::arg("path"), py::arg("is_directory"),
             py::call_guard<py::gil_scoped_release>())
        .def("on_moved", &Engine::on_moved, py::arg("source_path"), py::arg("destination_path"),
             py::arg("is_directory"), py::arg("event_time"), py::call_guard<py::gil_scoped_release>());
    module.def("main", &run_main, py::arg("backing_store"), py::arg("mount_dir"),
               "Run the Cloud Files mirror until interrupted (Ctrl+C). ");
    module.attr("FETCH_CHUNK_SIZE") = py::int_(FETCH_CHUNK_SIZE);
    module.attr("MOUNT_DIR") = py::none();
    module.attr("RESET_MOUNT") = py::bool_(false);
    module.attr("JOURNAL_PATH") = py::str(".\\sync_journal.db");
    module.attr("REFRESH_INTERVAL") = py::int_(REFRESH_INTERVAL_SECONDS);
    module.attr("PROVIDER_NAME") = py::str("PythonCfApiMirror");
    module.attr("PROVIDER_VERSION") = py::str("1.0");
    module.attr("ACTIVE_BACKING_STORE") = py::none();
    module.attr("__version__") = py::str("4.0.0");
}